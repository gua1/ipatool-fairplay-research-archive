#!/usr/bin/env python3
"""Validate the checked 26A428 Go oracle against Unicorn."""

from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path
import pickle
import struct
import subprocess
import sys

from probe_macos_fairplay_whitebox_checkpoint import CheckpointBlockOracle, FaultSite


ENTRY = 0x100234CDC
BLOCK = 0x710000014EE8
ROUND_PC = {8: 0x1002361BC, 7: 0x100235FA8, 6: 0x100235DD0}
FAULT_LANES = {
    8: ((8,8),(9,8),(10,16),(11,0),(8,0),(9,0),(10,8),(11,24),(8,24),(9,24),(10,0),(11,16),(8,16),(9,16),(10,24),(11,8)),
    7: ((8,8),(9,24),(11,8),(12,24),(8,0),(9,16),(11,0),(12,16),(8,24),(9,8),(11,24),(11,16),(8,16),(9,0),(10,8),(12,0)),
    6: ((10,16),(12,8),(14,16),(15,0),(10,8),(12,0),(14,8),(14,0),(10,0),(12,24),(12,16),(15,16),(10,24),(11,8),(14,24),(15,8)),
}


def checkpoint_block(checkpoint: dict[str, object]) -> bytes:
    if checkpoint["schema"] == 1:
        return bytes(checkpoint["memory"][BLOCK + offset] for offset in range(16))
    pages = checkpoint["memory_pages"]
    return bytes(pages[(BLOCK + offset) & ~0xFFF][(BLOCK + offset) & 0xFFF] for offset in range(16))


def read_exact(stream, size: int) -> bytes:
    result = bytearray()
    while len(result) != size:
        value = stream.read(size - len(result))
        if not value:
            raise EOFError("Go oracle closed its output")
        result.extend(value)
    return bytes(result)


def evaluate_go(binary: Path, model: Path, workers: int, jobs: list[tuple[bytes, int]]) -> list[bytes]:
    process = subprocess.Popen(
        [str(binary), "--model", str(model), "--workers", str(workers)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(b"\x01")
    process.stdin.flush()
    if read_exact(process.stdout, 8) != bytes.fromhex("000a000000000001"):
        raise ValueError("Go oracle hello mismatch")
    request = bytearray(b"\x03" + struct.pack("<I", len(jobs)))
    for block, meta in jobs:
        request.extend(block)
        request.extend(struct.pack("<I", meta))
    process.stdin.write(request)
    process.stdin.flush()
    if read_exact(process.stdout, 1) != b"\x00":
        raise ValueError("Go oracle returned an error")
    raw = read_exact(process.stdout, 16 * len(jobs))
    process.stdin.write(b"\x02")
    process.stdin.flush()
    if process.wait() != 0:
        raise ValueError("Go oracle exited unsuccessfully")
    return [raw[offset : offset + 16] for offset in range(0, len(raw), 16)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--go-oracle", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--normal-cases", type=int, default=256)
    args = parser.parse_args()
    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    baseline = checkpoint_block(checkpoint)
    oracle = CheckpointBlockOracle(
        args.checkpoint,
        entry=ENTRY,
        block=BLOCK,
        result_block=BLOCK,
        stop_address=ENTRY,
        stop_hit=2,
        instruction_limit=200_000,
    )
    normal = [
        hashlib.sha256(b"macOS 26A428 Go differential" + index.to_bytes(8, "big")).digest()[:16]
        for index in range(args.normal_cases)
    ]
    expected = [oracle.run(block)[0] for block in normal]
    jobs = [(block, 0xFFFF) for block in normal]
    protocol_round = {6: 6, 7: 8, 8: 9}
    for round_index in (6, 7, 8):
        for byte_index, (register, shift) in enumerate(FAULT_LANES[round_index]):
            site = FaultSite(
                round_index,
                byte_index,
                ROUND_PC[round_index],
                None,
                after_pc=ROUND_PC[round_index],
                after_register=f"w{register}",
                after_shift=shift,
                restore_register=False,
            )
            for xor_value in (1, 7, 255):
                expected.append(
                    oracle.run(baseline, fault_site=site, fault_value=xor_value)[0]
                )
                jobs.append(
                    (
                        baseline,
                        protocol_round[round_index]
                        | byte_index << 16
                        | xor_value << 24,
                    )
                )
    observed = evaluate_go(args.go_oracle, args.model, args.workers, jobs)
    mismatches = sum(left != right for left, right in zip(expected, observed))
    if mismatches:
        raise ValueError(f"Go oracle differs in {mismatches}/{len(jobs)} cases")
    combined = hashlib.sha256(b"".join(observed)).hexdigest()
    print(
        "macos26a428_go_oracle_differential=1 "
        f"normal={len(normal)} faults=144 matches={len(jobs)} mismatches=0 "
        f"output_sha256={combined}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
