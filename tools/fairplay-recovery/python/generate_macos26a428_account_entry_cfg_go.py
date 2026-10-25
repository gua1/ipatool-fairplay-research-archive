#!/usr/bin/env python3
"""Generate the pure-Go 26A428 license parser up to account entry."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pickle
from pathlib import Path

import generate_macos26a428_bootstrap_cfg_go as cfg
import generate_macos_fairplay_go_oracle as generator
from continue_fairplay_checkpoint_unicorn import checkpoint_memory_pages
from raw_macho_db import RawMachODatabase, dyld_info_fixups


START = 0x100CD1C18
STOP = 0x10057AE74
EXECUTABLE_PATH_PAGE = 0x700000200000


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--block-profile", type=Path, action="append", required=True)
    parser.add_argument("--block-trace", type=Path, action="append", required=True)
    parser.add_argument("--access-report", type=Path, action="append", default=[])
    parser.add_argument("--go-output", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.block_profile) != len(args.block_trace):
        parser.error("each block profile requires one matching block trace")

    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    if int(checkpoint["pc"], 16) != START:
        raise ValueError("checkpoint is not at the account-entry parser start")
    binary = Path(checkpoint["binary"])
    binary_hash = hashlib.sha256(binary.read_bytes()).digest()
    if binary_hash.hex() != checkpoint["binary_sha256"]:
        raise ValueError("checkpoint binary hash mismatch")
    fixups, _names = dyld_info_fixups(binary)
    database = RawMachODatabase(binary, fixups=fixups)

    sizes: dict[int, int] = {}
    blocks: list[int] = []
    seen: set[int] = set()
    event_count = 0
    for profile_path, trace_path in zip(args.block_profile, args.block_trace):
        profile = json.loads(profile_path.read_text())
        trace = json.loads(trace_path.read_text())
        for document in (profile, trace):
            if document["binary_sha256"] != checkpoint["binary_sha256"]:
                raise ValueError("account-entry trace build mismatch")
        for row in profile["block_counts"]:
            address, size = int(row["pc"], 16), int(row["size"])
            if address in sizes and sizes[address] != size:
                raise ValueError(f"conflicting block size at {address:#x}")
            sizes[address] = size
        raw_blocks = [int(value, 16) for value in trace["recent_pcs"]]
        if int(trace["start_pc"], 16) != START or int(trace["stop"]["pc"], 16) != STOP:
            raise ValueError("account-entry trace has the wrong boundary")
        stop_index = raw_blocks.index(STOP)
        event_count += stop_index
        for address in raw_blocks[:stop_index]:
            if address >= cfg.EXTERNAL_BASE or address == cfg.NOOP_CALLBACK or address in seen:
                continue
            seen.add(address)
            blocks.append(address)
    missing = [address for address in blocks if address not in sizes]
    if missing:
        raise ValueError(f"profiles lack {len(missing)} reached block sizes")

    original_start = cfg.START
    cfg.START = START
    try:
        source = cfg.generate_source(database, blocks, sizes, STOP)
    finally:
        cfg.START = original_start
    source = source.replace(
        "runRawSourceBootstrapCFG", "runRawSourceAccountEntryCFG"
    ).replace("rawSourceBootstrapBlock", "rawSourceAccountEntryBlock")
    args.go_output.parent.mkdir(parents=True, exist_ok=True)
    args.go_output.write_text(source)

    checkpoint_pages = set(checkpoint_memory_pages(checkpoint))
    stack_pages = set(range(0x7000000E0000, 0x700000110000, 0x1000))
    all_image_pages = {
        address
        for segment in database.segments
        if segment.name != "__PAGEZERO"
        for address in range(
            segment.vmaddr & ~0xFFF,
            (segment.end_ea + 0xFFF) & ~0xFFF,
            0x1000,
        )
    }
    if args.access_report:
        accessed_pages = {
            int(address, 16)
            for report_path in args.access_report
            for address in json.loads(report_path.read_text())["accessed_pages"]
        }
        image_pages = all_image_pages & accessed_pages
    else:
        image_pages = all_image_pages
    instruction_patches_by_page: dict[int, list[tuple[int, bytes]]] = {}
    for patch_address, patch in cfg.patched_instruction_bytes(database).items():
        instruction_patches_by_page.setdefault(patch_address & ~0xFFF, []).append(
            (patch_address, patch)
        )

    def sanitize_page(address: int, data: bytes) -> bytes:
        if address == EXECUTABLE_PATH_PAGE:
            data = bytes(0x1000)
        relevant = instruction_patches_by_page.get(address, ())
        if not relevant:
            return data
        result = bytearray(data)
        for patch_address, patch in relevant:
            offset = patch_address - address
            result[offset : offset + len(patch)] = patch
        return bytes(result)

    generator.BLOCK = cfg.BLOCK
    generator.MODEL_PAGE_SANITIZER = sanitize_page
    generator.MODEL_ZERO_PAGES = (
        {
            0x700000220000,
            0x710000014000,
            0xF1000000000D8000,
            0xF1000000000E3000,
            EXECUTABLE_PATH_PAGE,
        }
        | (stack_pages - checkpoint_pages)
    )
    generator.write_private_model(
        args.model_output,
        checkpoint,
        database,
        sorted(
            checkpoint_pages
            | stack_pages
            | image_pages
            | generator.MODEL_ZERO_PAGES
        ),
        binary_hash,
        {},
    )
    print(
        "fairplay_account_entry_cfg_generated=1 "
        f"blocks={len(blocks)} events={event_count} start={START:#x} stop={STOP:#x} "
        f"go={args.go_output} model={args.model_output}"
    )


if __name__ == "__main__":
    main()
