#!/usr/bin/env python3
"""Generate the natural 26A428 source-to-SIDB-frame selection CFG."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import generate_macos26a428_bootstrap_cfg_go as cfg
import generate_macos_fairplay_go_oracle as generator
from raw_macho_db import RawMachODatabase, dyld_info_fixups


START = 0x1006B10A0
STOP = 0x10008A644
STOP_HIT = 2


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--block-profile", type=Path, action="append", required=True)
    parser.add_argument("--block-trace", type=Path, action="append", required=True)
    parser.add_argument("--go-output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.block_profile) != len(args.block_trace):
        parser.error("each block profile requires one matching block trace")

    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    fixups, _names = dyld_info_fixups(args.binary)
    database = RawMachODatabase(args.binary, fixups=fixups)
    sizes: dict[int, int] = {}
    blocks: list[int] = []
    seen: set[int] = set()
    events = 0
    for profile_path, trace_path in zip(args.block_profile, args.block_trace):
        profile = json.loads(profile_path.read_text())
        trace = json.loads(trace_path.read_text())
        for document in (profile, trace):
            if document["binary_sha256"] != binary_hash:
                raise ValueError("selection trace build mismatch")
        if int(trace["start_pc"], 16) != START or int(trace["stop"]["pc"], 16) != STOP:
            raise ValueError("selection trace has the wrong boundary")
        if int(trace["stop"]["detail"]["hit"]) != STOP_HIT:
            raise ValueError("selection trace stopped on the wrong SIDB invocation")
        for row in profile["block_counts"]:
            address, size = int(row["pc"], 16), int(row["size"])
            if address in sizes and sizes[address] != size:
                raise ValueError(f"conflicting block size at {address:#x}")
            sizes[address] = size
        raw_blocks = [int(value, 16) for value in trace["recent_pcs"]]
        events += len(raw_blocks)
        for address in raw_blocks:
            if (
                address >= cfg.EXTERNAL_BASE
                or address == cfg.NOOP_CALLBACK
                or address in seen
            ):
                continue
            seen.add(address)
            blocks.append(address)
    missing = [address for address in blocks if address not in sizes]
    if missing:
        raise ValueError(f"profiles lack {len(missing)} reached block sizes")

    generator.FAULT_SITES = {}
    original_start = cfg.START
    cfg.START = START
    try:
        source = cfg.generate_source(
            database, blocks, sizes, STOP, stop_hit=STOP_HIT
        )
    finally:
        cfg.START = original_start
    source = source.replace(
        "runRawSourceBootstrapCFG", "runRawSourceSelectionCFG"
    ).replace("rawSourceBootstrapBlock", "rawSourceSelectionBlock")
    args.go_output.parent.mkdir(parents=True, exist_ok=True)
    args.go_output.write_text(source)
    print(
        "fairplay_selection_cfg_generated=1 "
        f"blocks={len(blocks)} events={events} start={START:#x} "
        f"stop={STOP:#x} hit={STOP_HIT} go={args.go_output}"
    )


if __name__ == "__main__":
    main()
