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
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output exists: {args.output}")
    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    if checkpoint.get("schema") != 1:
        raise ValueError("unsupported startup checkpoint schema")
    binary = Path(checkpoint["binary"])
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    if binary_hash != checkpoint.get("binary_sha256"):
        raise ValueError("startup checkpoint binary hash mismatch")
    # Deliberately retain no registers, paths, request buffers, account state,
    # or file payloads. A startup profile is valid only before request handling.
    document = {
        "schema": SCHEMA,
        "binary_sha256": binary_hash,
        "memory": [
            [hex(address), value]
            for address, value in sorted(checkpoint["memory"].items())
        ],
        "once_tokens": [
            hex(value) for value in sorted(checkpoint.get("once_tokens", ()))
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
        f"memory_bytes={len(checkpoint['memory'])} output={args.output}"
    )


if __name__ == "__main__":
    main()
