#!/usr/bin/env python3
"""Sanitize an account-independent fairplayd startup checkpoint."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import pickle


SCHEMA = "ipatool-fairplay-startup-cache-v1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "checkpoint",
        type=Path,
        help="schema-1 checkpoint or deterministic trace startup-cache JSON",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        help="exact fairplayd image (required with a startup-cache JSON)",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output exists: {args.output}")
    if args.checkpoint.suffix == ".json":
        cache = json.loads(args.checkpoint.read_text())
        if cache.get("fingerprint", {}).get("schema") != 1:
            raise ValueError("unsupported startup-cache schema")
        if args.binary is None:
            raise ValueError("startup-cache JSON requires --binary")
        binary = args.binary
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        if binary_hash not in cache["fingerprint"].get("inputs", {}).values():
            raise ValueError("startup-cache fairplayd hash mismatch")
        startup = cache["startup"]
        memory = {
            int(address, 16): value for address, value in startup["memory"]
        }
        once_tokens = {int(value) for value in startup.get("once_tokens", ())}
    else:
        with gzip.open(args.checkpoint, "rb") as stream:
            checkpoint = pickle.load(stream)
        if checkpoint.get("schema") != 1:
            raise ValueError("unsupported startup checkpoint schema")
        binary = Path(checkpoint["binary"])
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        if binary_hash != checkpoint.get("binary_sha256"):
            raise ValueError("startup checkpoint binary hash mismatch")
        memory = checkpoint["memory"]
        once_tokens = checkpoint.get("once_tokens", ())
    # Deliberately retain no registers, paths, request buffers, account state,
    # or file payloads. A startup profile is valid only before request handling.
    document = {
        "schema": SCHEMA,
        "binary_sha256": binary_hash,
        "memory": [
            [hex(address), value]
            for address, value in sorted(memory.items())
        ],
        "once_tokens": [
            hex(value) for value in sorted(once_tokens)
        ],
    }
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as output:
            output.write(encoded)
    print(
        "fairplay_startup_profile=1 "
        f"memory_bytes={len(memory)} output={args.output}"
    )


if __name__ == "__main__":
    main()
