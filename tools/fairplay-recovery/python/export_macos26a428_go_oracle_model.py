#!/usr/bin/env python3
"""Export the private model for the checked macOS 26A428 Go evaluator."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import pickle

import generate_macos_fairplay_go_oracle as common
from raw_macho_db import RawMachODatabase, dyld_info_fixups


ENTRY = 0x100234CDC
BLOCK = 0x710000014EE8
BUILD_SHA256 = "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--memory-trace", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
    args = parser.parse_args()
    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    if checkpoint.get("schema") not in {1, 2} or int(checkpoint["pc"], 16) != ENTRY:
        raise ValueError("checkpoint is not the 26A428 oracle entry")
    binary = Path(checkpoint["binary"])
    binary_hash = hashlib.sha256(binary.read_bytes()).digest()
    if binary_hash.hex() != BUILD_SHA256 or checkpoint["binary_sha256"] != BUILD_SHA256:
        raise ValueError("checkpoint does not match the checked 26A428 fairplayd")
    trace = json.loads(args.memory_trace.read_text())
    if trace.get("binary_sha256") != BUILD_SHA256:
        raise ValueError("memory trace build mismatch")
    pages = sorted(
        {
            int(event["address"], 16) & ~0xFFF
            for key in ("memory_read_events", "memory_write_events")
            for event in trace[key]
        }
    )
    if BLOCK & ~0xFFF not in pages:
        raise ValueError("memory trace does not include the oracle block")
    fixups, _names = dyld_info_fixups(binary)
    database = RawMachODatabase(binary, fixups=fixups)
    old_block = common.BLOCK
    try:
        common.BLOCK = BLOCK
        common.write_private_model(
            args.model_output,
            checkpoint,
            database,
            pages,
            binary_hash,
            {},
        )
    finally:
        common.BLOCK = old_block
    print(
        "macos26a428_go_oracle_model=1 "
        f"pages={len(pages)} output={args.model_output}"
    )


if __name__ == "__main__":
    main()
