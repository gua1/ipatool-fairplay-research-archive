#!/usr/bin/env python3
"""Build a selector-bound version-3 current-SINF decoder model.

This pack is the portable output of the offline recovery campaign.  Runtime
consumption uses ordinary AES and byte tables; it does not embed or execute
fairplayd, Unicorn, or the fault oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from Crypto.Cipher import AES


MAGIC = b"FPSENR3\x00"
VERSION = 3
BLOCK_BYTES = 16
SOURCE_BYTES = 27 * BLOCK_BYTES
TABLE_BYTES = BLOCK_BYTES * 256
MODEL_BYTES = 68 + BLOCK_BYTES + TABLE_BYTES + SOURCE_BYTES + TABLE_BYTES


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_selector(value: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2 or any(len(part) != 8 for part in parts):
        raise argparse.ArgumentTypeError(
            "selector must be eight hex digits:eight hex digits"
        )
    try:
        return int(parts[0], 16), int(parts[1], 16)
    except ValueError as error:
        raise argparse.ArgumentTypeError("selector contains non-hex digits") from error


def parse_fixture(value: str) -> tuple[Path, Path]:
    left, separator, right = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "fixture must be SINF=EXPECTED_LOGICAL_KEY"
        )
    return Path(left), Path(right)


def parse_byte(value: str) -> int:
    result = int(value, 0)
    if not 0 <= result <= 0xFF:
        raise argparse.ArgumentTypeError("byte value is outside 0..255")
    return result


def atoms(blob: bytes, start: int, end: int) -> list[tuple[bytes, int, int, int]]:
    result = []
    cursor = start
    while cursor < end:
        if end - cursor < 8:
            raise ValueError("atom list has a truncated header")
        size = int.from_bytes(blob[cursor : cursor + 4], "big")
        if size < 8 or size > end - cursor:
            raise ValueError("atom has invalid bounds")
        result.append((blob[cursor + 4 : cursor + 8], cursor, cursor + 8, cursor + size))
        cursor += size
    return result


def unique_atom(
    values: list[tuple[bytes, int, int, int]], name: bytes
) -> tuple[bytes, int, int, int]:
    matches = [value for value in values if value[0] == name]
    if len(matches) != 1:
        raise ValueError(f"SINF requires one {name!r} atom")
    return matches[0]


def sinf_fields(blob: bytes) -> list[tuple[bytes, int, int, int]]:
    root = unique_atom(atoms(blob, 0, len(blob)), b"sinf")
    if root[1] != 0 or root[3] != len(blob):
        raise ValueError("SINF root is invalid")
    schi = unique_atom(atoms(blob, root[2], root[3]), b"schi")
    return atoms(blob, schi[2], schi[3])


def sinf_selector(blob: bytes) -> tuple[int, int]:
    fields = sinf_fields(blob)
    result = []
    for name in (b"user", b"key "):
        atom = unique_atom(fields, name)
        if atom[3] - atom[2] != 4:
            raise ValueError(f"SINF {name!r} selector has invalid size")
        result.append(int.from_bytes(blob[atom[2] : atom[3]], "big"))
    return result[0], result[1]


def sinf_source(blob: bytes, source_offset: int) -> bytes:
    private = unique_atom(sinf_fields(blob), b"priv")
    start = source_offset
    end = start + SOURCE_BYTES
    if start < private[2] or start > private[3] or end > len(blob):
        raise ValueError("version-3 source has invalid SINF bounds")
    return blob[start:end]


def direct_tables(tables: list[list[int]], kind: str) -> bytes:
    if len(tables) != BLOCK_BYTES:
        raise ValueError(f"{kind} encoding must contain sixteen tables")
    result = bytearray()
    for index, table in enumerate(tables):
        if len(table) != 256 or sorted(table) != list(range(256)):
            raise ValueError(f"{kind} encoding table {index} is not bijective")
        result.extend(table)
    return bytes(result)


def validate_binary_tables(value: bytes, kind: str) -> None:
    if len(value) != TABLE_BYTES:
        raise ValueError(f"{kind} tables must be exactly {TABLE_BYTES} bytes")
    for position in range(BLOCK_BYTES):
        table = value[position * 256 : (position + 1) * 256]
        if sorted(table) != list(range(256)):
            raise ValueError(f"{kind} table {position} is not bijective")


def validate_plaintext(value: bytes) -> None:
    if len(value) != SOURCE_BYTES:
        raise ValueError("version-3 plaintext has invalid size")
    if value[:4] != b"itun" or int.from_bytes(value[4:8], "big") != 12:
        raise ValueError("version-3 plaintext has invalid itun header")
    if value[8:12] != b"vers" or int.from_bytes(value[12:16], "big") != 1:
        raise ValueError("version-3 plaintext has invalid version")
    expected = (
        (16, 24, b"key "),
        (40, 24, b"iviv"),
        (64, 24, b"tmpr"),
        (88, 88, b"righ"),
        (176, 264, b"name"),
    )
    for offset, size, name in expected:
        if int.from_bytes(value[offset : offset + 4], "big") != size:
            raise ValueError(f"version-3 plaintext has invalid {name!r} size")
        if value[offset + 4 : offset + 8] != name:
            raise ValueError(f"version-3 plaintext has invalid {name!r} type")
    if 176 + int.from_bytes(value[176:180], "big") != len(value) + 8:
        raise ValueError("version-3 plaintext has invalid name geometry")


def decode(
    source: bytes,
    key: bytes,
    output_encode: bytes,
    output_masks: bytes,
    post_decode: bytes,
    final_xor: int,
) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    internal = b"".join(
        aes.decrypt(source[offset : offset + BLOCK_BYTES])
        for offset in range(0, len(source), BLOCK_BYTES)
    )
    external = bytes(
        output_encode[(index % BLOCK_BYTES) * 256 + value] ^ output_masks[index]
        for index, value in enumerate(internal)
    )
    plaintext = bytes(
        post_decode[(index % BLOCK_BYTES) * 256 + value] ^ final_xor
        for index, value in enumerate(external)
    )
    validate_plaintext(plaintext)
    return plaintext


def logical_from_inner_key(inner_key: bytes) -> bytes:
    if len(inner_key) != BLOCK_BYTES:
        raise ValueError("current SINF inner key is not sixteen bytes")
    output = bytearray()
    for word in range(4):
        value = int.from_bytes(inner_key[word * 4 : word * 4 + 4], "big")
        value = (value + (13 + word) * 0xA6B13D89) & 0xFFFFFFFF
        output.extend(value.to_bytes(4, "little"))
    return bytes(output)


def write_new(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--darkphoenix-model", type=Path, required=True)
    parser.add_argument("--output-masks", type=Path, required=True)
    parser.add_argument("--postcodec-tables", type=Path, required=True)
    parser.add_argument("--fairplayd-sha256", required=True)
    parser.add_argument("--selector", type=parse_selector, required=True)
    parser.add_argument(
        "--source-offset",
        type=lambda value: int(value, 0),
        required=True,
        help="absolute source offset from the SINF root (0x1e0 on proven 26B118 fixtures)",
    )
    parser.add_argument("--final-xor", type=parse_byte, default=0x98)
    parser.add_argument("--fixture", type=parse_fixture, action="append", default=[])
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    args = parser.parse_args()

    fairplayd_hash = bytes.fromhex(args.fairplayd_sha256)
    if len(fairplayd_hash) != 32:
        raise ValueError("fairplayd SHA-256 must encode exactly 32 bytes")
    darkphoenix = json.loads(args.darkphoenix_model.read_text())
    key = bytes.fromhex(darkphoenix["key_hex"])
    if len(key) != BLOCK_BYTES:
        raise ValueError("DarkPhoenix model is not AES-128")
    input_encoding = direct_tables(darkphoenix["input_encoding"], "input")
    output_encode = direct_tables(darkphoenix["output_encoding"], "output")
    output_masks = args.output_masks.read_bytes()
    if len(output_masks) != SOURCE_BYTES:
        raise ValueError(f"output masks must be exactly {SOURCE_BYTES} bytes")
    post_decode = args.postcodec_tables.read_bytes()
    validate_binary_tables(post_decode, "post-codec")

    pack = (
        MAGIC
        + struct.pack("<II", VERSION, MODEL_BYTES)
        + fairplayd_hash
        + struct.pack("<IIiI", *args.selector, args.source_offset, SOURCE_BYTES)
        + bytes((args.final_xor, 0, 0, 0))
        + key
        + output_encode
        + output_masks
        + post_decode
    )
    if len(pack) != MODEL_BYTES:
        raise AssertionError("version-3 model size mismatch")

    if not args.fixture:
        raise ValueError(
            "version-3 model emission requires at least one end-to-end SINF fixture"
        )
    fixtures = []
    for sinf_path, expected_path in args.fixture:
        sinf = sinf_path.read_bytes()
        if sinf_selector(sinf) != args.selector:
            raise ValueError(f"fixture selector mismatch: {sinf_path}")
        source = sinf_source(sinf, args.source_offset)
        plaintext = decode(
            source,
            key,
            output_encode,
            output_masks,
            post_decode,
            args.final_xor,
        )
        logical = logical_from_inner_key(plaintext[24:40])
        if logical != expected_path.read_bytes():
            raise ValueError(f"fixture logical key mismatch: {sinf_path}")
        fixtures.append(
            {
                "sinf_sha256": digest(sinf),
                "source_sha256": digest(source),
                "plaintext_sha256": digest(plaintext),
                "logical_key_sha256": digest(logical),
            }
        )

    audit = {
        "schema": "fairplay.enrollment-model-audit.v3",
        "selector": f"{args.selector[0]:08x}:{args.selector[1]:08x}",
        "model_bytes": len(pack),
        "model_sha256": digest(pack),
        "fairplayd_sha256": fairplayd_hash.hex(),
        "aes_key_sha256": digest(key),
        "input_encoding_sha256": digest(input_encoding),
        "input_encoding_stored": False,
        "output_encode_sha256": digest(output_encode),
        "output_masks_sha256": digest(output_masks),
        "postcodec_tables_sha256": digest(post_decode),
        "source_offset_from_sinf": args.source_offset,
        "source_bytes": SOURCE_BYTES,
        "final_xor": args.final_xor,
        "fixtures": fixtures,
    }
    write_new(args.binary_output, pack, 0o600)
    write_new(
        args.audit_output,
        (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode(),
        0o644,
    )
    print(
        "macos26_current_sinf_model_v3=1 "
        f"bytes={len(pack)} fixtures={len(fixtures)} sha256={digest(pack)}"
    )


if __name__ == "__main__":
    main()
