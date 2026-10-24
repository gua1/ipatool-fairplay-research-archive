#!/usr/bin/env python3
"""Derive FPSENR3 material from one recovered 26B118 checkpoint sequence."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import pickle

from Crypto.Cipher import AES


SOURCE_BYTES = 27 * 16


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_checkpoint(path: Path) -> dict[str, object]:
    with gzip.open(path, "rb") as stream:
        value = pickle.load(stream)
    if value.get("schema") not in {1, 2}:
        raise ValueError(f"unsupported checkpoint schema: {path}")
    return value


def checkpoint_bytes(checkpoint: dict[str, object], address: int, size: int) -> bytes:
    if checkpoint.get("schema") == 1:
        memory = checkpoint["memory"]
        return bytes(memory[address + offset] for offset in range(size))
    pages = checkpoint["memory_pages"]
    return bytes(
        pages[(address + offset) & ~0xFFF][(address + offset) & 0xFFF]
        for offset in range(size)
    )


def inverse_tables(tables: list[list[int]], name: str) -> list[list[int]]:
    if len(tables) != 16:
        raise ValueError(f"{name} must contain sixteen tables")
    result = []
    for position, table in enumerate(tables):
        if len(table) != 256 or sorted(table) != list(range(256)):
            raise ValueError(f"{name} table {position} is not bijective")
        inverse = [0] * 256
        for source, target in enumerate(table):
            inverse[target] = source
        result.append(inverse)
    return result


def validate_plaintext(value: bytes) -> None:
    if len(value) != SOURCE_BYTES:
        raise ValueError("version-3 plaintext has invalid size")
    expected = (
        (0, 4, b"itun", 12),
        (8, 12, b"vers", 1),
        (20, 16, b"key ", 24),
        (44, 40, b"iviv", 24),
        (68, 64, b"tmpr", 24),
        (92, 88, b"righ", 88),
        (180, 176, b"name", 264),
    )
    for marker_offset, number_offset, name, number in expected:
        if value[marker_offset : marker_offset + 4] != name:
            raise ValueError(f"version-3 plaintext has invalid {name!r} marker")
        if int.from_bytes(value[number_offset : number_offset + 4], "big") != number:
            raise ValueError(f"version-3 plaintext has invalid {name!r} geometry")


def logical_from_inner_key(inner_key: bytes) -> bytes:
    if len(inner_key) != 16:
        raise ValueError("inner key is not sixteen bytes")
    output = bytearray()
    for word in range(4):
        value = int.from_bytes(inner_key[word * 4 : word * 4 + 4], "big")
        value = (value + (13 + word) * 0xA6B13D89) & 0xFFFFFFFF
        output.extend(value.to_bytes(4, "little"))
    return bytes(output)


def write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--whitebox-entry", type=Path, required=True)
    parser.add_argument("--postcodec-entry", type=Path, required=True)
    parser.add_argument("--postcodec-exit", type=Path, required=True)
    parser.add_argument("--darkphoenix-model", type=Path, required=True)
    parser.add_argument("--buffer-address", type=lambda value: int(value, 0), default=0x710000014EE0)
    parser.add_argument("--final-xor", type=lambda value: int(value, 0), default=0x98)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not 0 <= args.final_xor <= 0xFF:
        parser.error("--final-xor must be one byte")
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)

    entry = checkpoint_bytes(load_checkpoint(args.whitebox_entry), args.buffer_address, SOURCE_BYTES)
    post_entry = checkpoint_bytes(load_checkpoint(args.postcodec_entry), args.buffer_address, SOURCE_BYTES)
    post_exit = checkpoint_bytes(load_checkpoint(args.postcodec_exit), args.buffer_address, SOURCE_BYTES)
    recovered = json.loads(args.darkphoenix_model.read_text())
    key = bytes.fromhex(recovered["key_hex"])
    if len(key) != 16:
        raise ValueError("DarkPhoenix model is not AES-128")
    input_decode = inverse_tables(recovered["input_encoding"], "input encoding")
    output_encode = recovered["output_encoding"]
    inverse_tables(output_encode, "output encoding")

    aes = AES.new(key, AES.MODE_ECB)
    masks = bytearray()
    for block_offset in range(0, SOURCE_BYTES, 16):
        external_input = entry[block_offset : block_offset + 16]
        logical_input = bytes(
            input_decode[position][value]
            for position, value in enumerate(external_input)
        )
        internal_output = aes.decrypt(logical_input)
        base_output = bytes(
            output_encode[position][value]
            for position, value in enumerate(internal_output)
        )
        observed = post_entry[block_offset : block_offset + 16]
        masks.extend(left ^ right for left, right in zip(base_output, observed))
    if any(masks[:16]):
        raise ValueError("block-zero output mask is not zero")

    post_delta = bytes(left ^ right for left, right in zip(post_entry, post_exit))
    period = post_delta[:16]
    if post_delta != period * 27:
        raise ValueError("post-codec is not a sixteen-byte XOR period")
    post_tables = b"".join(
        bytes(value ^ period[position] for value in range(256))
        for position in range(16)
    )
    plaintext = bytes(value ^ args.final_xor for value in post_exit)
    validate_plaintext(plaintext)
    logical = logical_from_inner_key(plaintext[24:40])

    write_private(args.output_dir / "output-masks.bin", bytes(masks))
    write_private(args.output_dir / "postcodec-tables.bin", post_tables)
    write_private(args.output_dir / "logical-key.bin", logical)
    write_private(args.output_dir / "private-plaintext.bin", plaintext)
    audit = {
        "schema": "fairplay.macos26b118-fpsenr3-material.v1",
        "whitebox_entry_sha256": digest(entry),
        "postcodec_entry_sha256": digest(post_entry),
        "postcodec_exit_sha256": digest(post_exit),
        "aes_key_sha256": digest(key),
        "input_encoding_sha256": digest(bytes(value for row in recovered["input_encoding"] for value in row)),
        "output_encoding_sha256": digest(bytes(value for row in output_encode for value in row)),
        "output_masks_sha256": digest(masks),
        "postcodec_tables_sha256": digest(post_tables),
        "plaintext_sha256": digest(plaintext),
        "logical_key_sha256": digest(logical),
        "raw_secret_values_retained": False,
    }
    write_private(
        args.output_dir / "audit.json",
        (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode(),
    )
    print(
        "macos26_fpsenr3_material=1 "
        f"masks={len(masks)} postcodec={len(post_tables)} "
        f"output={args.output_dir}"
    )


if __name__ == "__main__":
    main()
