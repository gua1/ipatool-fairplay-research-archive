#!/usr/bin/env python3
"""Build a portable macOS current-SINF decoder model.

The private DarkPhoenix JSON and Unicorn checkpoints remain research inputs.
The emitted binary contains only the fixed AES key, the 16-byte whitening
period, and the sixteen inverse external-input permutations needed by the Go
implementation.  The audit output retains hashes and validation results only.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import pickle
import struct

from Crypto.Cipher import AES


# Version 2 binds every recovered white-box to the SINF user/key selector it
# was recovered from. This lets ipatool safely keep multiple account models in
# one directory without guessing which AES model should decrypt a license.
MAGIC = b"FPSENR2\x00"
VERSION = 2
MODEL_BYTES = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256
EXPECTED_ATOMS = (
    (24, b"key "),
    (24, b"iviv"),
    (24, b"tmpr"),
    ((88, 96), b"righ"),
    (264, b"name"),
)


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
    output = bytearray()
    cursor = address
    remaining = size
    while remaining:
        page = cursor & ~0xFFF
        data = pages.get(page)
        if not isinstance(data, bytes) or len(data) != 0x1000:
            raise ValueError(
                f"checkpoint does not cover {address:#x}+{size:#x}"
            )
        offset = cursor - page
        chunk = min(remaining, 0x1000 - offset)
        output.extend(data[offset : offset + chunk])
        cursor += chunk
        remaining -= chunk
    return bytes(output)


def inverse_tables(tables: list[list[int]]) -> list[list[int]]:
    result: list[list[int]] = []
    if len(tables) != 16:
        raise ValueError("external encoding must contain sixteen tables")
    for index, table in enumerate(tables):
        if len(table) != 256 or sorted(table) != list(range(256)):
            raise ValueError(f"external encoding table {index} is not bijective")
        inverse = [0] * 256
        for source, target in enumerate(table):
            inverse[target] = source
        result.append(inverse)
    return result


def atoms(blob: bytes, start: int, end: int) -> list[tuple[bytes, int, int]]:
    result = []
    cursor = start
    while cursor < end:
        if end - cursor < 8:
            raise ValueError("atom list has a truncated header")
        size = int.from_bytes(blob[cursor : cursor + 4], "big")
        if size < 8 or size > end - cursor:
            raise ValueError("atom has invalid bounds")
        result.append((blob[cursor + 4 : cursor + 8], cursor + 8, cursor + size))
        cursor += size
    return result


def sinf_private_payload(blob: bytes) -> bytes:
    roots = atoms(blob, 0, len(blob))
    if len(roots) != 1 or roots[0][0] != b"sinf":
        raise ValueError("SINF root is invalid")
    children = atoms(blob, roots[0][1], roots[0][2])
    schi = [item for item in children if item[0] == b"schi"]
    if len(schi) != 1:
        raise ValueError("SINF requires one schi atom")
    fields = atoms(blob, schi[0][1], schi[0][2])
    private = [item for item in fields if item[0] == b"priv"]
    if len(private) != 1:
        raise ValueError("SINF requires one priv atom")
    return blob[private[0][1] : private[0][2]]


def decrypt_private(
    source: bytes,
    key: bytes,
    whitening: bytes,
    input_decode: list[list[int]],
) -> tuple[bytes, bytes]:
    if len(source) < 48 or len(whitening) != 16:
        raise ValueError("current SINF priv geometry is invalid")
    body_bytes = len(source) - 16
    trailer_bytes = body_bytes % 16
    ciphertext_bytes = body_bytes - trailer_bytes
    if ciphertext_bytes < 32 or trailer_bytes not in (0, 8):
        raise ValueError("current SINF priv block geometry is invalid")
    encoded_bytes = 16 + ciphertext_bytes
    logical = bytes(
        input_decode[index % 16][value ^ whitening[index % 16]]
        for index, value in enumerate(source[:encoded_bytes])
    )
    plaintext = AES.new(key, AES.MODE_CBC, logical[:16]).decrypt(logical[16:])
    trailer = source[encoded_bytes:]
    if any(trailer):
        raise ValueError("current SINF priv trailer is not zero")
    plaintext += trailer

    parsed = atoms(plaintext, 0, len(plaintext))
    if len(parsed) != len(EXPECTED_ATOMS):
        raise ValueError("current SINF priv atom count is invalid")
    for actual, expected in zip(parsed, EXPECTED_ATOMS):
        expected_sizes = expected[0] if isinstance(expected[0], tuple) else (expected[0],)
        if actual[0] != expected[1] or actual[2] - (actual[1] - 8) not in expected_sizes:
            raise ValueError("current SINF priv atom geometry is invalid")
    return plaintext, plaintext[parsed[0][1] : parsed[0][2]]


def logical_from_inner_key(inner_key: bytes) -> bytes:
    if len(inner_key) != 16:
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


def parse_fixture(value: str) -> tuple[Path, Path]:
    left, separator, right = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("fixture must be SINF=EXPECTED_LOGICAL_KEY")
    return Path(left), Path(right)


def parse_selector(value: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2 or any(len(part) != 8 for part in parts):
        raise argparse.ArgumentTypeError("selector must be eight hex digits:eight hex digits")
    try:
        selector = tuple(int(part, 16) for part in parts)
    except ValueError as error:
        raise argparse.ArgumentTypeError("selector contains non-hex digits") from error
    return selector[0], selector[1]


def sinf_selector(blob: bytes) -> tuple[int, int]:
    roots = atoms(blob, 0, len(blob))
    if len(roots) != 1 or roots[0][0] != b"sinf":
        raise ValueError("SINF root is invalid")
    children = atoms(blob, roots[0][1], roots[0][2])
    schi = [item for item in children if item[0] == b"schi"]
    if len(schi) != 1:
        raise ValueError("SINF requires one schi atom")
    fields = atoms(blob, schi[0][1], schi[0][2])
    result = []
    for name in (b"user", b"key "):
        matches = [item for item in fields if item[0] == name]
        if len(matches) != 1 or matches[0][2] - matches[0][1] != 4:
            raise ValueError(f"SINF requires one four-byte {name!r} atom")
        result.append(int.from_bytes(blob[matches[0][1] : matches[0][2]], "big"))
    return result[0], result[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-checkpoint", type=Path, required=True)
    parser.add_argument("--whitebox-output-checkpoint", type=Path, required=True)
    parser.add_argument("--darkphoenix-model", type=Path, required=True)
    parser.add_argument("--output-address", type=lambda value: int(value, 0), required=True)
    parser.add_argument(
        "--source-address",
        type=lambda value: int(value, 0),
        help=(
            "explicit 432-byte pre-whitening source; defaults to checkpoint X23 "
            "for the original 26A428 capture"
        ),
    )
    parser.add_argument("--selector", type=parse_selector, required=True)
    parser.add_argument("--fixture", type=parse_fixture, action="append", default=[])
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    args = parser.parse_args()

    source_checkpoint = load_checkpoint(args.source_checkpoint)
    output_checkpoint = load_checkpoint(args.whitebox_output_checkpoint)
    model = json.loads(args.darkphoenix_model.read_text())
    key = bytes.fromhex(model["key_hex"])
    if len(key) != 16:
        raise ValueError("DarkPhoenix model is not AES-128")
    input_decode = inverse_tables(model["input_encoding"])
    inverse_tables(model["output_encoding"])

    source_address = (
        args.source_address
        if args.source_address is not None
        else int(source_checkpoint["registers"]["x23"])
    )
    source = checkpoint_bytes(source_checkpoint, source_address, 432)
    encoded = checkpoint_bytes(output_checkpoint, args.output_address, 432)
    full_mask = bytes(left ^ right for left, right in zip(source, encoded))
    whitening = full_mask[:16]
    if full_mask != whitening * 27:
        raise ValueError("first protected transform is not a sixteen-byte XOR period")

    binary_hash = bytes.fromhex(str(source_checkpoint["binary_sha256"]))
    if len(binary_hash) != 32:
        raise ValueError("checkpoint binary hash is invalid")
    input_blob = bytes(value for table in input_decode for value in table)
    payload = (
        MAGIC
        + struct.pack("<II", VERSION, MODEL_BYTES)
        + binary_hash
        + struct.pack("<II", *args.selector)
        + key
        + whitening
        + input_blob
    )
    if len(payload) != MODEL_BYTES:
        raise AssertionError("model size mismatch")

    fixtures = []
    for sinf_path, expected_path in args.fixture:
        sinf = sinf_path.read_bytes()
        fixture_selector = sinf_selector(sinf)
        if fixture_selector != args.selector:
            raise ValueError(
                f"fixture selector {fixture_selector[0]:08x}:{fixture_selector[1]:08x} "
                f"does not match model selector {args.selector[0]:08x}:{args.selector[1]:08x}"
            )
        private = sinf_private_payload(sinf)
        plaintext, inner_key = decrypt_private(private, key, whitening, input_decode)
        logical = logical_from_inner_key(inner_key)
        expected = expected_path.read_bytes()
        if logical != expected:
            raise ValueError(f"fixture logical key mismatch: {sinf_path}")
        fixtures.append(
            {
                "sinf_sha256": digest(sinf),
                "private_bytes": len(private),
                "private_plaintext_sha256": digest(plaintext),
                "logical_key_sha256": digest(logical),
            }
        )

    audit = {
        "schema": "fairplay.enrollment-model-audit.v2",
        "selector": f"{args.selector[0]:08x}:{args.selector[1]:08x}",
        "model_bytes": len(payload),
        "model_sha256": digest(payload),
        "fairplayd_sha256": binary_hash.hex(),
        "aes_key_sha256": digest(key),
        "whitening_period_bytes": len(whitening),
        "whitening_sha256": digest(whitening),
        "input_decode_sha256": digest(input_blob),
        "external_encoding_validation": "DarkPhoenix Step 5 plus verifyEncodings",
        "first_transform_xor_period_exact": True,
        "fixtures": fixtures,
    }
    write_new(args.binary_output, payload, 0o600)
    write_new(
        args.audit_output,
        (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode(),
        0o644,
    )
    print(
        "macos26_current_sinf_model=1 "
        f"bytes={len(payload)} fixtures={len(fixtures)} "
        f"sha256={audit['model_sha256']}"
    )


if __name__ == "__main__":
    main()
