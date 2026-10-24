#!/usr/bin/env python3
"""Differentially validate the generated Go oracle against Unicorn."""

from __future__ import annotations

import argparse
from dataclasses import replace
import gzip
import hashlib
import os
from pathlib import Path
import pickle
import struct
import subprocess

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from generate_macos_fairplay_go_oracle import (
    BLOCK,
    FAULT_SITES,
    START,
    STOP,
    reg_index,
)
from probe_macos_fairplay_whitebox_checkpoint import (
    CheckpointBlockOracle,
    FaultSite,
)
from raw_macho_db import RawMachODatabase, dyld_info_fixups


def checkpoint_bytes(checkpoint: dict[str, object], address: int, size: int) -> bytes:
    pages = checkpoint["memory_pages"]
    return bytes(
        pages[(address + offset) & ~0xFFF][(address + offset) & 0xFFF]
        for offset in range(size)
    )


def exact_sites(database: RawMachODatabase) -> list[tuple[int, int, FaultSite]]:
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    result = []
    for round_index in (6, 7, 8):
        for byte_index, (pc, register, kind) in enumerate(FAULT_SITES[round_index]):
            if kind == "index-after":
                site = FaultSite(
                    round_index,
                    byte_index,
                    pc,
                    None,
                    after_pc=pc,
                    after_register=register,
                    after_shift=0,
                    restore_register=False,
                )
            else:
                raw = database.bytes.get_dword_at(
                    pc, allow_uninitialized=True
                ).to_bytes(4, "little")
                instruction = next(disassembler.disasm(raw, pc, count=1))
                destination = disassembler.reg_name(
                    instruction.operands[0].reg
                ).lower()
                restore = reg_index(destination) != reg_index(register)
                site = FaultSite(
                    round_index,
                    byte_index,
                    pc,
                    register if kind == "index" else None,
                    pointer_register=register if kind == "pointer" else None,
                    restore_register=restore,
                )
            result.append((round_index, byte_index, site))
    return result


def read_exact(stream, size: int) -> bytes:
    result = bytearray()
    while len(result) != size:
        value = stream.read(size - len(result))
        if not value:
            raise EOFError("Go oracle closed its output")
        result.extend(value)
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--go-oracle", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args()

    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    block = checkpoint_bytes(checkpoint, BLOCK, 16)
    binary = Path(checkpoint["binary"])
    fixups, _names = dyld_info_fixups(binary)
    database = RawMachODatabase(binary, fixups=fixups)
    sites = exact_sites(database)

    oracle = CheckpointBlockOracle(
        args.checkpoint,
        entry=START,
        block=BLOCK,
        result_block=BLOCK,
        stop_address=STOP,
        stop_hit=1,
        instruction_limit=200_000,
    )
    index_sites = [
        site for _round, _byte, site in sites if site.index_register is not None
    ]
    domains = oracle.learn_index_domains(index_sites)

    cases: list[tuple[int, int, int, bytes]] = []
    protocol_round = {6: 6, 7: 8, 8: 9}
    for round_index, byte_index, site in sites:
        if site.index_register is not None:
            site = replace(
                site,
                index_domain=domains[(site.pc, str(site.index_register))],
            )
        for xor_value in (1, 7, 255):
            expected, _events = oracle.run(
                block,
                fault_site=site,
                fault_value=xor_value,
            )
            cases.append(
                (protocol_round[round_index], byte_index, xor_value, expected)
            )

    process = subprocess.Popen(
        [
            str(args.go_oracle),
            "--model",
            str(args.model),
            "--workers",
            str(args.workers),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(b"\x01")
    process.stdin.flush()
    if read_exact(process.stdout, 8) != bytes.fromhex("000a000000000001"):
        raise ValueError("Go oracle hello mismatch")
    request = bytearray(b"\x03" + struct.pack("<I", len(cases)))
    for round_index, byte_index, xor_value, _expected in cases:
        request.extend(block)
        request.extend(
            struct.pack(
                "<I",
                round_index | byte_index << 16 | xor_value << 24,
            )
        )
    process.stdin.write(request)
    process.stdin.flush()
    if read_exact(process.stdout, 1) != b"\x00":
        raise ValueError("Go oracle returned an error")
    raw = read_exact(process.stdout, 16 * len(cases))
    observed = [raw[offset : offset + 16] for offset in range(0, len(raw), 16)]
    mismatches = sum(
        expected != observed[index]
        for index, (*_metadata, expected) in enumerate(cases)
    )
    process.stdin.write(b"\x02")
    process.stdin.flush()
    if process.wait() != 0:
        raise ValueError("Go oracle exited unsuccessfully")
    if mismatches:
        raise ValueError(f"Go oracle differs in {mismatches}/{len(cases)} cases")
    output_hash = hashlib.sha256(raw).hexdigest()
    print(
        "fairplay_go_oracle_differential=1 "
        f"cases={len(cases)} matches={len(cases)} mismatches=0 "
        f"domains={len(domains)} output_sha256={output_hash}"
    )


if __name__ == "__main__":
    main()
