#!/usr/bin/env python3
"""Continue a private 26A428 evaluator checkpoint with native Unicorn ARM64.

The static evaluator establishes all protected dispatch state and dynamic
memory first.  This runner then copies that exact state into Unicorn, removes
only arm64e pointer-authentication instruction semantics (matching the static
evaluator), and executes ordinary ARM64 at native emulation speed.  It is
offline and stops on explicit code addresses, the first SINF ``priv`` read,
an external/unmapped access, or an instruction budget.
"""

from __future__ import annotations

import argparse
import gc
import gzip
import hashlib
import json
import os
import pickle
import posixpath
import re
import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import Callable

from capstone import CS_AC_READ, CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64_const import ARM64_OP_MEM, ARM64_OP_REG
from unicorn import (
    UC_ARCH_ARM64,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_INSN_INVALID,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MEM_FETCH_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_MODE_ARM,
    UC_PROT_ALL,
    Uc,
    UcError,
)
from unicorn import arm64_const

from raw_macho_db import RawMachODatabase, dyld_info_fixups


PAGE_SIZE = 0x1000
MASK64 = (1 << 64) - 1
NOP = 0xD503201F
RET_X30 = 0xD65F03C0
SYNTHETIC_ALLOCATION_BASE = 0x710100000000
SYNTHETIC_ERRNO_ADDRESS = 0x7100FFF00000
SYNTHETIC_NOOP_CALLBACK = 0x720000000000
DARWIN_VM_PAGE_SIZE = 0x4000
DARWIN_REGULAR_FILE_MODE = 0o100644
DARWIN_STAT_SIZE = 144
KNOWN_EOR3_SITES_26A428 = frozenset(
    {
        0x10022DDE8, 0x10022DDEC, 0x10022DDF0, 0x10022DDF4,
        0x10022DE54,
        0x100247238, 0x10024723C, 0x100247240, 0x100247244,
        0x1002472AC,
        0x1005DF33C, 0x1005DF340, 0x1005DF344, 0x1005DF348,
        0x1005DF3A8,
        0x1005DF8CC, 0x1005DF8D0, 0x1005DF8D4, 0x1005DF8D8,
        0x1005DF938,
        0x10051B4B8, 0x10051B4BC, 0x10051B4C0, 0x10051B4C4,
        0x10051B528,
        0x10061DC50, 0x10061DC54, 0x10061DC58, 0x10061DC5C,
        0x10061DCC0,
        0x10066ADD8, 0x10066ADDC, 0x10066ADE0, 0x10066ADE4,
        0x10066AE44,
        0x1004B2D18, 0x1004B2D1C, 0x1004B2D20, 0x1004B2D24,
        0x1004B2D88,
        0x100652ED4, 0x100652ED8, 0x100652EDC, 0x100652EE0,
        0x100652F40,
        0x10081C8C0, 0x10081C8C4, 0x10081C8C8, 0x10081C8CC,
        0x10081C930,
    }
)
PTHREAD_ONCE_STUB = b"".join(
    instruction.to_bytes(4, "little")
    for instruction in (
        0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
        0x910003FD,  # mov x29, sp
        0xD63F0020,  # blr x1
        0xA8C17BFD,  # ldp x29, x30, [sp], #16
        0x52800000,  # mov w0, #0
        RET_X30,
    )
)


def page_down(value: int) -> int:
    return value & -PAGE_SIZE


def page_up(value: int) -> int:
    return (value + PAGE_SIZE - 1) & -PAGE_SIZE


def register_id(name: str) -> int:
    if name == "sp":
        return arm64_const.UC_ARM64_REG_SP
    if name == "pc":
        return arm64_const.UC_ARM64_REG_PC
    if name[0:1] in {"v", "q", "d", "s", "h", "b"} and name[1:].isdigit():
        return getattr(arm64_const, f"UC_ARM64_REG_Q{name[1:]}")
    return getattr(arm64_const, f"UC_ARM64_REG_{name.upper()}")


def x_register_number(name: str) -> int:
    name = {"fp": "x29", "lr": "x30"}.get(name, name)
    if not name.startswith("x") or not name[1:].isdigit():
        raise ValueError(f"not an X register: {name!r}")
    return int(name[1:])


def canonical_general_register(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] in {"w", "x"} and name[1:].isdigit():
        return f"x{name[1:]}"
    return name


def register_read_sites(
    database: RawMachODatabase,
    requested_registers: set[str],
) -> set[int]:
    wanted = {canonical_general_register(name) for name in requested_registers}
    if not wanted:
        return set()
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    sites: set[int] = set()
    for section in database.sections:
        if not section.contains_instructions or not section.size:
            continue
        code = database.image[section.fileoff : section.fileoff + section.size]
        for offset in range(0, len(code) - 3, 4):
            instruction = next(
                disassembler.disasm(
                    code[offset : offset + 4],
                    section.vmaddr + offset,
                    count=1,
                ),
                None,
            )
            if instruction is None:
                continue
            read_registers, _written_registers = instruction.regs_access()
            if any(
                canonical_general_register(instruction.reg_name(register)) in wanted
                for register in read_registers
            ):
                sites.add(instruction.address)
    return sites


def patch_pointer_authentication(
    emulator: Uc,
    database: RawMachODatabase,
    pointer_auth_sites: dict[int, tuple[str, str | None]],
    eor3_sites: dict[int, tuple[str, str, str, str]],
    casal_sites: dict[int, tuple[str, str, str]],
    authenticated_load_sites: dict[int, tuple[str, str, int, bool]],
    emulate_eor3: bool,
    selected_eor3_addresses: frozenset[int],
    preserved_text_instructions: frozenset[int],
    preserve_special_instruction_bytes: bool,
    emulate_authenticated_loads: bool,
) -> dict[str, int]:
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    counts = {
        "branch": 0,
        "call": 0,
        "return": 0,
        "pac_nop": 0,
        "authenticated_load": 0,
        "eor3_hook": 0,
        "casal_hook": 0,
        "preserved_text_instruction": 0,
    }
    for section in database.sections:
        if not section.contains_instructions or not section.size:
            continue
        code = database.image[section.fileoff : section.fileoff + section.size]
        for offset in range(0, len(code) - 3, 4):
            address = section.vmaddr + offset
            instruction = next(
                disassembler.disasm(code[offset : offset + 4], address, count=1),
                None,
            )
            if instruction is None:
                continue
            mnemonic = instruction.mnemonic.lower()
            replacement: int | None = None
            if mnemonic.startswith(("braa", "brab")):
                if not instruction.operands or instruction.operands[0].type != ARM64_OP_REG:
                    raise ValueError(f"unexpected authenticated branch at {address:#x}")
                name = instruction.reg_name(instruction.operands[0].reg).lower()
                replacement = 0xD61F0000 | (x_register_number(name) << 5)
                if preserve_special_instruction_bytes or address in preserved_text_instructions:
                    pointer_auth_sites[address] = ("branch", name)
                counts["branch"] += 1
            elif mnemonic.startswith(("blraa", "blrab")):
                if not instruction.operands or instruction.operands[0].type != ARM64_OP_REG:
                    raise ValueError(f"unexpected authenticated call at {address:#x}")
                name = instruction.reg_name(instruction.operands[0].reg).lower()
                replacement = 0xD63F0000 | (x_register_number(name) << 5)
                if preserve_special_instruction_bytes or address in preserved_text_instructions:
                    pointer_auth_sites[address] = ("call", name)
                counts["call"] += 1
            elif mnemonic in {"retaa", "retab"}:
                replacement = RET_X30
                if preserve_special_instruction_bytes or address in preserved_text_instructions:
                    pointer_auth_sites[address] = ("return", None)
                counts["return"] += 1
            elif mnemonic in {"ldraa", "ldrab"}:
                if not emulate_authenticated_loads:
                    continue
                if (
                    len(instruction.operands) != 2
                    or instruction.operands[0].type != ARM64_OP_REG
                    or instruction.operands[1].type != ARM64_OP_MEM
                    or instruction.operands[1].mem.index
                    or instruction.post_index
                ):
                    raise ValueError(
                        f"unexpected authenticated load at {address:#x}"
                    )
                authenticated_load_sites[address] = (
                    instruction.reg_name(instruction.operands[0].reg).lower(),
                    instruction.reg_name(
                        instruction.operands[1].mem.base
                    ).lower(),
                    instruction.operands[1].mem.disp,
                    bool(instruction.writeback),
                )
                replacement = NOP
                counts["authenticated_load"] += 1
            elif mnemonic.startswith(("pac", "aut", "xpac")):
                replacement = NOP
                if preserve_special_instruction_bytes or address in preserved_text_instructions:
                    pointer_auth_sites[address] = ("nop", None)
                counts["pac_nop"] += 1
            elif mnemonic == "eor3" and (
                emulate_eor3 or address in selected_eor3_addresses
            ):
                names = tuple(
                    instruction.reg_name(operand.reg).lower()
                    for operand in instruction.operands
                    if operand.type == ARM64_OP_REG
                )
                if len(names) != 4:
                    raise ValueError(f"unexpected EOR3 operands at {address:#x}")
                eor3_sites[address] = names
                replacement = NOP
                counts["eor3_hook"] += 1
            elif mnemonic == "casal":
                if (
                    len(instruction.operands) != 3
                    or instruction.operands[0].type != ARM64_OP_REG
                    or instruction.operands[1].type != ARM64_OP_REG
                ):
                    raise ValueError(f"unexpected CASAL operands at {address:#x}")
                casal_sites[address] = (
                    instruction.reg_name(instruction.operands[0].reg).lower(),
                    instruction.reg_name(instruction.operands[1].reg).lower(),
                    instruction.reg_name(
                        instruction.operands[2].mem.base
                    ).lower(),
                )
                replacement = NOP
                counts["casal_hook"] += 1
            if replacement is not None:
                if preserve_special_instruction_bytes or address in preserved_text_instructions:
                    counts["preserved_text_instruction"] += 1
                else:
                    emulator.mem_write(address, replacement.to_bytes(4, "little"))
    return counts


def checkpoint_memory_pages(
    checkpoint: dict[str, object],
) -> dict[int, bytes | dict[int, int]]:
    """Return checkpoint memory as complete pages.

    Schema 1 stored every byte as a separate ``dict[int, int]`` entry.  Large
    late-stage checkpoints therefore expanded to several GiB merely to reload
    about 60 MiB of memory.  Schema 2 stores those same bytes page-packed and
    remains byte-for-byte equivalent at the emulator boundary.
    """
    schema = checkpoint.get("schema")
    if schema == 2:
        raw_pages = checkpoint.get("memory_pages")
        if not isinstance(raw_pages, dict):
            raise ValueError("schema-2 checkpoint has no memory_pages map")
        pages: dict[int, bytes | dict[int, int]] = {}
        for raw_page, raw_data in raw_pages.items():
            if not isinstance(raw_page, int) or raw_page & (PAGE_SIZE - 1):
                raise ValueError("checkpoint contains an invalid page address")
            if not isinstance(raw_data, bytes) or len(raw_data) != PAGE_SIZE:
                raise ValueError("checkpoint contains an invalid page payload")
            pages[raw_page] = raw_data
        return pages
    if schema != 1:
        raise ValueError("unsupported checkpoint schema")
    memory = checkpoint.get("memory")
    if not isinstance(memory, dict):
        raise ValueError("schema-1 checkpoint has no memory map")
    mutable_pages: dict[int, bytearray] = {}
    page_byte_counts: dict[int, int] = {}
    for address, value in memory.items():
        if not isinstance(address, int) or not isinstance(value, int):
            raise ValueError("checkpoint contains an invalid memory entry")
        if address >= 0xF000000000000000:
            continue
        page = page_down(address)
        data = mutable_pages.setdefault(page, bytearray(PAGE_SIZE))
        data[address - page] = value & 0xFF
        page_byte_counts[page] = page_byte_counts.get(page, 0) + 1
    pages: dict[int, bytes | dict[int, int]] = {}
    for page, data in mutable_pages.items():
        if page_byte_counts[page] == PAGE_SIZE:
            pages[page] = bytes(data)
        else:
            pages[page] = {
                address - page: value & 0xFF
                for address, value in memory.items()
                if page_down(address) == page
            }
    return pages


def checkpoint_memory_read(
    pages: dict[int, bytes | dict[int, int]], address: int, size: int
) -> bytes:
    payload = bytearray()
    cursor = address
    remaining = size
    while remaining:
        page = page_down(cursor)
        data = pages.get(page)
        if data is None:
            raise KeyError(cursor)
        offset = cursor - page
        chunk = min(remaining, PAGE_SIZE - offset)
        if isinstance(data, bytes):
            payload.extend(data[offset : offset + chunk])
        else:
            try:
                payload.extend(data[index] for index in range(offset, offset + chunk))
            except KeyError as error:
                raise KeyError(cursor) from error
        cursor += chunk
        remaining -= chunk
    return bytes(payload)


def map_checkpoint_memory(
    emulator: Uc,
    pages: dict[int, bytes | dict[int, int]],
    image_start: int,
    image_end: int,
) -> tuple[int, int]:
    external_pages = sorted(
        page
        for page in pages
        if page < 0xF000000000000000
        and not image_start <= page < image_end
    )
    mapped_pages = len(external_pages)
    if external_pages:
        range_start = external_pages[0]
        previous = range_start
        for page in external_pages[1:] + [external_pages[-1] + 2 * PAGE_SIZE]:
            if page != previous + PAGE_SIZE:
                emulator.mem_map(
                    range_start,
                    previous + PAGE_SIZE - range_start,
                    UC_PROT_ALL,
                )
                range_start = page
            previous = page
    overlaid_pages = 0
    for page, data in sorted(pages.items()):
        if page >= 0xF000000000000000:
            continue
        if image_start <= page < image_end:
            overlaid_pages += 1
        if isinstance(data, bytes):
            payload = data
        else:
            payload = (
                bytearray(emulator.mem_read(page, PAGE_SIZE))
                if image_start <= page < image_end
                else bytearray(PAGE_SIZE)
            )
            for offset, value in data.items():
                payload[offset] = value & 0xFF
            payload = bytes(payload)
        emulator.mem_write(page, payload)
    return mapped_pages, overlaid_pages


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument(
        "--stop-address",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
    )
    parser.add_argument(
        "--start-address",
        type=lambda value: int(value, 0),
        help="offline control: begin at this image address instead of the checkpoint PC",
    )
    parser.add_argument("--stop-hit", type=int, default=1)
    parser.add_argument("--count", type=int, default=100_000_000)
    parser.add_argument(
        "--preserve-text-instruction",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help=(
            "keep one authenticated/SIMD instruction byte-exact and emulate it "
            "with an execution hook because target code also reads it as data"
        ),
    )
    parser.add_argument(
        "--preserve-special-instruction-bytes",
        action="store_true",
        help=(
            "keep every hooked PAC/authenticated-load/EOR3/CASAL instruction "
            "byte-exact so code-as-data reads see the original Mach-O bytes"
        ),
    )
    parser.add_argument(
        "--allocation-base",
        type=lambda value: int(value, 0),
        default=SYNTHETIC_ALLOCATION_BASE,
    )
    parser.add_argument(
        "--compact-allocations",
        action="store_true",
        help=(
            "use page-rounded synthetic allocations even when an older static "
            "checkpoint contains one-MiB-spaced allocation addresses"
        ),
    )
    parser.add_argument("--iokit15-output", type=Path)
    parser.add_argument("--trace-instructions", action="store_true")
    parser.add_argument(
        "--trace-memory-reads",
        action="store_true",
        help="record read PC/address/size tuples without retaining values",
    )
    parser.add_argument("--max-memory-read-events", type=int, default=1_000_000)
    parser.add_argument("--trace-memory-writes", action="store_true")
    parser.add_argument("--max-memory-write-events", type=int, default=1_000_000)
    parser.add_argument(
        "--include-memory-write-values",
        action="store_true",
        help="include written values in full memory-write traces (private reports only)",
    )
    parser.add_argument(
        "--trace-memory-read-range",
        action="append",
        default=[],
        metavar="START:SIZE",
        help="record reads intersecting one bounded emulated memory range",
    )
    parser.add_argument(
        "--trace-memory-write-range",
        action="append",
        default=[],
        metavar="START:SIZE",
        help="record writes intersecting one bounded emulated memory range",
    )
    parser.add_argument(
        "--stop-memory-read-range",
        action="append",
        default=[],
        metavar="START:SIZE",
        help="stop before completing the first read intersecting a bounded range",
    )
    parser.add_argument(
        "--stop-memory-write-range",
        action="append",
        default=[],
        metavar="START:SIZE",
        help="stop on the first write intersecting a bounded range",
    )
    parser.add_argument(
        "--trace-dispatch-table-base",
        type=lambda value: int(value, 0),
        help="aggregate reads from this flattened dispatch-table base",
    )
    parser.add_argument(
        "--trace-dispatch-table-entries",
        type=lambda value: int(value, 0),
        default=0,
        help="number of eight-byte entries in the traced dispatch table",
    )
    parser.add_argument(
        "--include-dispatch-registers",
        action="store_true",
        help="include the first private register snapshot for each dispatch read",
    )
    parser.add_argument(
        "--force-dispatch-index",
        action="append",
        default=[],
        metavar="LOAD_PC=INDEX",
        help="offline control: replace the index register before one table load",
    )
    parser.add_argument("--recent-pcs", type=int, default=0)
    parser.add_argument(
        "--trace-code-address",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="record every execution of one code address without stopping",
    )
    parser.add_argument(
        "--trace-code-register",
        action="append",
        default=[],
        help="register to retain in --trace-code-address events",
    )
    parser.add_argument(
        "--trace-code-stack-bytes",
        action="append",
        default=[],
        metavar="OFFSET:SIZE",
        help="retain private stack bytes in each traced-code event",
    )
    parser.add_argument("--max-code-trace-events", type=int, default=10000)
    parser.add_argument(
        "--watch-register-change",
        action="append",
        default=[],
        help="record instruction addresses that change a register, without values",
    )
    parser.add_argument(
        "--stop-on-register-change",
        action="append",
        default=[],
        help="stop immediately after an instruction changes a register",
    )
    parser.add_argument(
        "--stop-on-register-read",
        action="append",
        default=[],
        help="stop before the first instruction that reads a register",
    )
    parser.add_argument(
        "--include-watched-register-values",
        action="store_true",
        help="include prior/current values in register-change events (private reports only)",
    )
    parser.add_argument("--include-registers", action="store_true")
    parser.add_argument(
        "--file-payload",
        action="append",
        default=[],
        metavar="SUFFIX=PATH",
        help="serve PATH when the emulated process opens a path ending in SUFFIX",
    )
    parser.add_argument(
        "--file-stat",
        action="append",
        default=[],
        metavar="SUFFIX=MODE,UID,GID",
        help="exact permission/owner fields for one modeled file suffix",
    )
    parser.add_argument(
        "--file-stat-field",
        action="append",
        default=[],
        metavar="SUFFIX:FIELD=VALUE",
        help="additional exact Darwin stat field for one modeled file suffix",
    )
    parser.add_argument("--missing-files-are-enoent", action="store_true")
    parser.add_argument(
        "--removed-file-suffix",
        action="append",
        default=[],
        help="mark a modeled file suffix already removed in a resumed checkpoint",
    )
    parser.add_argument(
        "--initialized-once-token",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="pthread_once token already initialized in the checkpoint's startup seed",
    )
    parser.add_argument(
        "--uninitialize-once-token",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="remove one token from the checkpoint's initialized pthread_once set",
    )
    parser.add_argument(
        "--once-return",
        action="append",
        default=[],
        metavar="SENTINEL=RESUME",
        help="restore a pending pthread_once callback return from a static checkpoint",
    )
    parser.add_argument(
        "--watch-write-address",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="record code addresses that write this exact emulated address",
    )
    parser.add_argument(
        "--include-watched-write-values",
        action="store_true",
        help="include written values in exact-address events (private reports only)",
    )
    parser.add_argument(
        "--watch-read-address",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="record code addresses that read this exact emulated address",
    )
    parser.add_argument(
        "--mac-address-from-interface",
        metavar="INTERFACE",
        help="use the host interface MAC for the modeled IOMACAddress property",
    )
    parser.add_argument(
        "--mac-address-from-hardware-interface",
        metavar="INTERFACE",
        help=(
            "use the non-randomized hardware-port MAC for the modeled "
            "IOMACAddress property"
        ),
    )
    parser.add_argument(
        "--mac-address-file",
        type=Path,
        help=(
            "read a six-byte hexadecimal or colon-separated IOMACAddress from "
            "a private file without printing or retaining its value"
        ),
    )
    parser.add_argument(
        "--map-arbitrary-data-pages",
        action="store_true",
        help="negative control: zero-map otherwise invalid data pages like the sparse evaluator",
    )
    parser.add_argument("--max-arbitrary-data-pages", type=int, default=64)
    parser.add_argument("--emulate-eor3", action="store_true")
    parser.add_argument(
        "--native-authenticated-loads",
        action="store_true",
        help=(
            "leave LDRAA/LDRAB instructions native instead of replacing them "
            "with the portable load hook; this reproduces older checkpoints"
        ),
    )
    parser.add_argument("--eor3-known-26a428", action="store_true")
    parser.add_argument(
        "--eor3-address",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
    )
    parser.add_argument(
        "--initial-random-state",
        type=lambda value: int(value, 0),
        default=0x12345678,
    )
    parser.add_argument(
        "--memory-qword",
        action="append",
        default=[],
        metavar="ADDRESS=VALUE",
        help="override one emulated qword before continuation",
    )
    parser.add_argument(
        "--memory-xor-byte",
        action="append",
        default=[],
        metavar="ADDRESS=MASK",
        help="XOR one emulated byte before continuation without retaining its value",
    )
    parser.add_argument(
        "--memory-blob",
        action="append",
        default=[],
        metavar="ADDRESS=PATH",
        help="write one private file at an emulated address before continuation",
    )
    parser.add_argument(
        "--memory-checkpoint-region",
        action="append",
        default=[],
        metavar="CHECKPOINT:ADDRESS:SIZE",
        help="overlay one private memory region from another compatible checkpoint",
    )
    parser.add_argument(
        "--memory-checkpoint-copy",
        action="append",
        default=[],
        metavar="CHECKPOINT:SOURCE:DESTINATION:SIZE",
        help="copy one private memory region from another compatible checkpoint",
    )
    parser.add_argument(
        "--register-value",
        action="append",
        default=[],
        metavar="REGISTER=VALUE",
        help="set one register to an integer value before continuation",
    )
    parser.add_argument(
        "--copy-register",
        action="append",
        default=[],
        metavar="DEST=SOURCE",
        help="forced control: copy one checkpoint register into another before continuation",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--checkpoint-output",
        type=Path,
        help="write a private resumable checkpoint at the final PC",
    )
    parser.add_argument(
        "--report-memory-range",
        action="append",
        default=[],
        metavar="START:SIZE",
        help=(
            "report only the size, SHA-256, and nonzero-byte count of one "
            "bounded final memory range; raw bytes remain private"
        ),
    )
    args = parser.parse_args()

    modeled_mac_address = b"\x02\x00\x00\x00\x00\x01"
    modeled_mac_source = "deterministic-fixture"
    mac_sources = sum(
        source is not None
        for source in (
            args.mac_address_from_interface,
            args.mac_address_from_hardware_interface,
            args.mac_address_file,
        )
    )
    if mac_sources > 1:
        parser.error(
            "choose only one MAC source: --mac-address-from-interface, "
            "--mac-address-from-hardware-interface, or --mac-address-file"
        )
    if args.mac_address_from_interface is not None:
        output = subprocess.run(
            ["/sbin/ifconfig", args.mac_address_from_interface],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        match = re.search(r"\bether\s+([0-9a-fA-F:]{17})\b", output)
        if match is None:
            parser.error(
                f"interface {args.mac_address_from_interface!r} has no Ethernet address"
            )
        modeled_mac_address = bytes.fromhex(match.group(1).replace(":", ""))
        modeled_mac_source = f"host-interface:{args.mac_address_from_interface}"
    elif args.mac_address_from_hardware_interface is not None:
        output = subprocess.run(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        hardware_mac = None
        for block in re.split(r"\n\s*\n", output):
            device_match = re.search(r"(?m)^Device:\s*(\S+)\s*$", block)
            address_match = re.search(
                r"(?m)^Ethernet Address:\s*([0-9a-fA-F:]{17})\s*$", block
            )
            if (
                device_match is not None
                and address_match is not None
                and device_match.group(1)
                == args.mac_address_from_hardware_interface
            ):
                hardware_mac = bytes.fromhex(
                    address_match.group(1).replace(":", "")
                )
                break
        if hardware_mac is None:
            parser.error(
                "hardware port for interface "
                f"{args.mac_address_from_hardware_interface!r} was not found"
            )
        modeled_mac_address = hardware_mac
        modeled_mac_source = (
            "hardware-port-interface:"
            f"{args.mac_address_from_hardware_interface}"
        )
    elif args.mac_address_file is not None:
        private_mac_data = args.mac_address_file.read_bytes()
        if len(private_mac_data) == 6:
            modeled_mac_address = private_mac_data
        else:
            try:
                private_mac_text = private_mac_data.decode("utf-8").strip()
            except UnicodeDecodeError:
                parser.error(
                    "--mac-address-file must contain six raw bytes or "
                    "exactly six hexadecimal bytes"
                )
            normalized_mac = private_mac_text.replace(":", "").replace("-", "")
            if re.fullmatch(r"[0-9a-fA-F]{12}", normalized_mac) is None:
                parser.error(
                    "--mac-address-file must contain six raw bytes or "
                    "exactly six hexadecimal bytes"
                )
            modeled_mac_address = bytes.fromhex(normalized_mac)
        modeled_mac_source = "private-file"

    file_payloads: dict[bytes, bytes] = {}
    file_stat_metadata: dict[bytes, dict[str, int]] = {}
    file_payload_metadata: list[dict[str, object]] = []
    for specification in args.file_payload:
        if "=" not in specification:
            parser.error(f"invalid --file-payload {specification!r}; expected SUFFIX=PATH")
        suffix_text, payload_path_text = specification.split("=", 1)
        if not suffix_text or not payload_path_text:
            parser.error(f"invalid --file-payload {specification!r}; expected SUFFIX=PATH")
        payload_path = Path(payload_path_text)
        payload = payload_path.read_bytes()
        suffix = suffix_text.encode("utf-8")
        file_payloads[suffix] = payload
        file_payload_metadata.append(
            {
                "suffix": suffix_text,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    for specification in args.file_stat:
        try:
            suffix_text, fields = specification.split("=", 1)
            mode_text, uid_text, gid_text = fields.split(",", 2)
            metadata = {
                "mode": int(mode_text, 0),
                "uid": int(uid_text, 0),
                "gid": int(gid_text, 0),
            }
        except ValueError as error:
            parser.error(
                f"invalid --file-stat {specification!r}; "
                "expected SUFFIX=MODE,UID,GID"
            )
        suffix = suffix_text.encode("utf-8")
        file_stat_metadata[suffix] = metadata
    valid_stat_fields = {
        "dev", "nlink", "ino", "rdev", "atime", "atime_nsec",
        "mtime", "mtime_nsec", "ctime", "ctime_nsec", "birthtime",
        "birthtime_nsec", "blocks", "blksize", "flags", "gen",
    }
    for specification in args.file_stat_field:
        try:
            suffix_text, assignment = specification.split(":", 1)
            field, raw_value = assignment.split("=", 1)
            value = int(raw_value, 0)
        except ValueError as error:
            parser.error(
                f"invalid --file-stat-field {specification!r}; "
                "expected SUFFIX:FIELD=VALUE"
            )
        if field not in valid_stat_fields:
            parser.error(f"unknown --file-stat-field name: {field}")
        suffix = suffix_text.encode("utf-8")
        file_stat_metadata.setdefault(suffix, {})[field] = value

    checkpoint_sha256 = hashlib.sha256(args.checkpoint.read_bytes()).hexdigest()
    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    memory_pages = checkpoint_memory_pages(checkpoint)
    if checkpoint.get("schema") == 1:
        checkpoint.pop("memory", None)
        gc.collect()
    reported_memory_ranges: list[tuple[int, int]] = []
    for specification in args.report_memory_range:
        try:
            start_text, size_text = specification.split(":", 1)
            start, size = int(start_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --report-memory-range {specification!r}; "
                "expected START:SIZE"
            )
        if start < 0 or size <= 0 or size > 16 * 1024 * 1024:
            parser.error("invalid reported memory range")
        reported_memory_ranges.append((start, size))
    traced_code_addresses = set(args.trace_code_address)
    traced_code_stack_ranges: list[tuple[int, int]] = []
    for specification in args.trace_code_stack_bytes:
        try:
            offset_text, size_text = specification.split(":", 1)
            offset, size = int(offset_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --trace-code-stack-bytes {specification!r}; "
                "expected OFFSET:SIZE"
            )
        if offset < 0 or size <= 0 or size > 0x10000:
            parser.error("invalid traced-code stack range")
        traced_code_stack_ranges.append((offset, size))
    traced_memory_read_ranges: list[tuple[int, int]] = []
    for specification in args.trace_memory_read_range:
        try:
            start_text, size_text = specification.split(":", 1)
            start, size = int(start_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --trace-memory-read-range {specification!r}; "
                "expected START:SIZE"
            )
        if start < 0 or size <= 0 or size > 0x10000000:
            parser.error("invalid traced memory-read range")
        traced_memory_read_ranges.append((start, start + size))
    traced_memory_write_ranges: list[tuple[int, int]] = []
    for specification in args.trace_memory_write_range:
        try:
            start_text, size_text = specification.split(":", 1)
            start, size = int(start_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --trace-memory-write-range {specification!r}; "
                "expected START:SIZE"
            )
        if start < 0 or size <= 0 or size > 0x10000000:
            parser.error("invalid traced memory-write range")
        traced_memory_write_ranges.append((start, start + size))
    stopped_memory_read_ranges: list[tuple[int, int]] = []
    for specification in args.stop_memory_read_range:
        try:
            start_text, size_text = specification.split(":", 1)
            start, size = int(start_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --stop-memory-read-range {specification!r}; "
                "expected START:SIZE"
            )
        if start < 0 or size <= 0 or size > 0x10000000:
            parser.error("invalid stopped memory-read range")
        stopped_memory_read_ranges.append((start, start + size))
    stopped_memory_write_ranges: list[tuple[int, int]] = []
    for specification in args.stop_memory_write_range:
        try:
            start_text, size_text = specification.split(":", 1)
            start, size = int(start_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --stop-memory-write-range {specification!r}; "
                "expected START:SIZE"
            )
        if start < 0 or size <= 0 or size > 0x10000000:
            parser.error("invalid stopped memory-write range")
        stopped_memory_write_ranges.append((start, start + size))
    for name in (
        args.trace_code_register
        + args.watch_register_change
        + args.stop_on_register_change
        + args.stop_on_register_read
    ):
        try:
            register_id(name)
        except (KeyError, ValueError):
            parser.error(f"unknown --trace-code-register {name!r}")

    binary = Path(checkpoint["binary"])
    actual_binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual_binary_sha256 != checkpoint["binary_sha256"]:
        raise ValueError("checkpoint binary hash mismatch")
    fixups, external_names = dyld_info_fixups(binary)
    database = RawMachODatabase(binary, fixups=fixups)
    stopped_register_read_sites = register_read_sites(
        database,
        set(args.stop_on_register_read),
    )

    forced_dispatch_specs: dict[int, tuple[str, int]] = {}
    dispatch_disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    dispatch_disassembler.detail = True
    for specification in args.force_dispatch_index:
        load_text, index_text = specification.split("=", 1)
        load_pc = int(load_text, 0)
        index = int(index_text, 0) & 0xFFFFFFFF
        raw = database.bytes.get_dword_at(
            load_pc, allow_uninitialized=True
        ).to_bytes(4, "little")
        instruction = next(
            dispatch_disassembler.disasm(raw, load_pc, count=1), None
        )
        if (
            instruction is None
            or not instruction.mnemonic.lower().startswith("ldr")
            or len(instruction.operands) < 2
            or instruction.operands[1].type != ARM64_OP_MEM
            or not instruction.operands[1].mem.index
        ):
            parser.error(
                f"--force-dispatch-index site {load_pc:#x} is not an indexed load"
            )
        register = instruction.reg_name(
            instruction.operands[1].mem.index
        ).lower()
        forced_dispatch_specs[load_pc] = (register, index)

    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    image_start = page_down(database.minimum_ea)
    image_end = page_up(database.maximum_ea)
    emulator.mem_map(image_start, image_end - image_start, UC_PROT_ALL)
    for segment in database.segments:
        if not segment.filesize or segment.name == "__PAGEZERO":
            continue
        data = database.image[segment.fileoff : segment.fileoff + segment.filesize]
        emulator.mem_write(segment.vmaddr, data)
    for location, target in fixups.items():
        if image_start <= location <= image_end - 8:
            emulator.mem_write(location, (target & MASK64).to_bytes(8, "little"))

    pointer_auth_sites: dict[int, tuple[str, str | None]] = {}
    eor3_sites: dict[int, tuple[str, str, str, str]] = {}
    casal_sites: dict[int, tuple[str, str, str]] = {}
    authenticated_load_sites: dict[int, tuple[str, str, int, bool]] = {}
    patch_counts = patch_pointer_authentication(
        emulator,
        database,
        pointer_auth_sites,
        eor3_sites,
        casal_sites,
        authenticated_load_sites,
        args.emulate_eor3,
        frozenset(args.eor3_address)
        | (KNOWN_EOR3_SITES_26A428 if args.eor3_known_26a428 else frozenset()),
        frozenset(args.preserve_text_instruction),
        args.preserve_special_instruction_bytes,
        not args.native_authenticated_loads,
    )
    mapped_pages, overlaid_pages = map_checkpoint_memory(
        emulator,
        memory_pages,
        image_start,
        image_end,
    )
    for name, value in checkpoint["registers"].items():
        if (
            name == "sp"
            or (name.startswith("x") and name[1:].isdigit())
            or (name.startswith("v") and name[1:].isdigit())
        ):
            emulator.reg_write(
                register_id(name),
                value & ((1 << 128) - 1) if name.startswith("v") else value & MASK64,
            )
    nzcv = checkpoint["nzcv"]
    emulator.reg_write(
        arm64_const.UC_ARM64_REG_NZCV,
        ((nzcv["n"] & 1) << 31)
        | ((nzcv["z"] & 1) << 30)
        | ((nzcv["c"] & 1) << 29)
        | ((nzcv["v"] & 1) << 28),
    )

    checkpoint_pc = int(checkpoint["pc"], 16)
    start_pc = args.start_address if args.start_address is not None else checkpoint_pc
    stop_addresses = set(args.stop_address)
    stop_hits: dict[int, int] = {}
    recent_pcs: deque[int] | None = (
        deque(maxlen=args.recent_pcs) if args.recent_pcs else None
    )
    state = {
        "reason": "instruction-limit",
        "pc": start_pc,
        "instructions": 0,
        "detail": None,
    }
    watched_register_names = set(args.watch_register_change) | set(
        args.stop_on_register_change
    )
    watched_register_values = {
        name: emulator.reg_read(register_id(name))
        for name in watched_register_names
    }
    watched_register_events: list[dict[str, object]] = []
    traced_code_events: list[dict[str, object]] = []
    traced_code_hit_counts: dict[int, int] = {}
    previous_pc: int | None = None
    lazy_zero_pages: set[int] = set()
    arbitrary_zero_pages: set[int] = set()
    dynamic_mapped_pages = {
        page
        for page in memory_pages
        if not image_start <= page < image_end
        and page < 0xF000000000000000
    }
    modeled_externals: dict[str, int] = {}
    file_events: list[dict[str, object]] = []
    watched_write_events: list[dict[str, object]] = []
    watched_read_events: list[dict[str, object]] = []
    memory_read_events: list[dict[str, object]] = []
    memory_write_events: list[dict[str, object]] = []
    memory_copy_events: list[dict[str, object]] = []
    memory_range_read_events: list[dict[str, object]] = []
    memory_range_write_events: list[dict[str, object]] = []
    dispatch_table_reads: dict[tuple[int, int, int], dict[str, object]] = {}
    forced_dispatch_events: list[dict[str, object]] = []
    external_stub_addresses: set[int] = set()
    open_files: dict[int, dict[str, object]] = {}
    for raw_descriptor, raw_entry in checkpoint.get("open_files", {}).items():
        if not isinstance(raw_descriptor, int) or not isinstance(raw_entry, dict):
            raise ValueError("invalid open-file state in checkpoint")
        data = raw_entry.get("data")
        offset = raw_entry.get("offset")
        path = raw_entry.get("path")
        suffix = raw_entry.get("suffix")
        if (
            not isinstance(data, bytes)
            or not isinstance(offset, int)
            or offset < 0
            or not isinstance(path, bytes)
            or not isinstance(suffix, bytes)
        ):
            raise ValueError("invalid open-file entry in checkpoint")
        open_files[raw_descriptor] = {
            "data": data,
            "offset": offset,
            "path": path,
            "suffix": suffix,
        }
    initial_open_file_count = len(open_files)
    removed_file_suffixes: set[bytes] = {
        str(value).encode("utf-8")
        for value in checkpoint.get("removed_file_suffixes", ())
    }
    removed_file_suffixes.update(
        value.encode("utf-8") for value in args.removed_file_suffix
    )
    next_fd = int(checkpoint.get("next_fd", 100))
    if next_fd < 0 or any(descriptor >= next_fd for descriptor in open_files):
        raise ValueError("invalid next file descriptor in checkpoint")
    checkpoint_has_allocator_state = "next_allocation" in checkpoint
    static_allocation_addresses = [
        page
        for page in memory_pages
        if 0x700010000000 <= page < 0x700020000000
    ]
    if args.compact_allocations:
        next_allocation = args.allocation_base
        allocation_stride = None
        allocation_mode = "compact-page-forced"
    elif checkpoint_has_allocator_state:
        next_allocation = checkpoint["next_allocation"]
        allocation_stride = None
        allocation_mode = "checkpoint-native"
    elif static_allocation_addresses:
        next_allocation = (
            max(static_allocation_addresses) + 0x100000
        ) & ~0xFFFFF
        allocation_stride = 0x100000
        allocation_mode = "static-checkpoint-1mib"
    else:
        next_allocation = args.allocation_base
        allocation_stride = None
        allocation_mode = "compact-page"
    next_io_iterator = 0x100
    next_io_service = 0x200
    next_io_connection = 0x300
    next_bootstrap_port = 0x500
    next_cf_object = 0x700070000000
    next_xpc_connection = 0x700090000000
    random_state = checkpoint.get("random_state", args.initial_random_state) & 0xFFFFFFFF
    io_iterator_services: dict[int, int] = {}
    fake_cf_values: dict[int, tuple[str, object]] = {}
    once_tokens: set[int] = set(checkpoint.get("once_tokens", ()))
    once_tokens.update(args.initialized_once_token)
    once_tokens.difference_update(args.uninitialize_once_token)
    initial_once_token_count = len(once_tokens)
    pthread_once_events: list[dict[str, object]] = []
    pending_once_returns = {
        int(sentinel, 0): int(resume, 0)
        for sentinel, resume in (
            specification.split("=", 1) for specification in args.once_return
        )
    }

    def stop(reason: str, pc: int, detail: object = None) -> None:
        state["reason"] = reason
        state["pc"] = pc
        state["detail"] = detail
        emulator.emu_stop()

    def ensure_page_mapped(address: int) -> None:
        page = page_down(address)
        if image_start <= page < image_end or page in dynamic_mapped_pages:
            return
        emulator.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
        dynamic_mapped_pages.add(page)

    def ensure_range_mapped(address: int, size: int) -> None:
        if size < 0 or size > 0x10000000:
            raise ValueError(f"invalid emulated memory range size: {size:#x}")
        if size == 0:
            return
        first = page_down(address)
        last = page_down(address + size - 1)
        for page in range(first, last + PAGE_SIZE, PAGE_SIZE):
            ensure_page_mapped(page)

    def write_memory(address: int, data: bytes) -> None:
        ensure_range_mapped(address, len(data))
        if data:
            emulator.mem_write(address, data)

    def allocate(size: int) -> int:
        nonlocal next_allocation
        if size < 0 or size > 0x10000000:
            raise ValueError(f"invalid emulated allocation size: {size:#x}")
        allocation_size = (
            allocation_stride
            if allocation_stride is not None
            else max(PAGE_SIZE, page_up(max(size, 1)))
        )
        address = next_allocation
        next_allocation += allocation_size
        ensure_range_mapped(address, allocation_size)
        return address

    errno_address = SYNTHETIC_ERRNO_ADDRESS
    ensure_page_mapped(errno_address)
    ensure_page_mapped(SYNTHETIC_NOOP_CALLBACK)
    emulator.mem_write(
        SYNTHETIC_NOOP_CALLBACK,
        RET_X30.to_bytes(4, "little"),
    )
    memory_overrides: list[dict[str, str]] = []
    for specification in args.memory_qword:
        address_text, value_text = specification.split("=", 1)
        address = int(address_text, 0)
        value = int(value_text, 0) & MASK64
        write_memory(address, value.to_bytes(8, "little"))
        memory_overrides.append({"address": hex(address), "value": hex(value)})
    for specification in args.memory_xor_byte:
        address_text, mask_text = specification.split("=", 1)
        address = int(address_text, 0)
        mask = int(mask_text, 0)
        if not 0 <= mask <= 0xFF:
            raise ValueError(f"invalid byte XOR mask: {mask:#x}")
        original = bytes(emulator.mem_read(address, 1))[0]
        write_memory(address, bytes((original ^ mask,)))
        memory_overrides.append({"address": hex(address), "xor_mask": hex(mask)})
    memory_blob_overrides: list[dict[str, object]] = []
    for specification in args.memory_blob:
        address_text, path_text = specification.split("=", 1)
        address = int(address_text, 0)
        path = Path(path_text)
        payload = path.read_bytes()
        if not payload or len(payload) > 16 * 1024 * 1024:
            raise ValueError(f"memory blob {path} has an invalid size")
        write_memory(address, payload)
        memory_blob_overrides.append(
            {
                "address": hex(address),
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    memory_checkpoint_regions: list[dict[str, object]] = []
    for specification in args.memory_checkpoint_region:
        path_text, address_text, size_text = specification.rsplit(":", 2)
        source_path = Path(path_text)
        address = int(address_text, 0)
        size = int(size_text, 0)
        if size <= 0 or size > 16 * 1024 * 1024:
            raise ValueError("checkpoint memory region has an invalid size")
        with gzip.open(source_path, "rb") as stream:
            source_checkpoint = pickle.load(stream)
        source_pages = checkpoint_memory_pages(source_checkpoint)
        if source_checkpoint.get("binary_sha256") != actual_binary_sha256:
            raise ValueError("memory-region checkpoint binary hash mismatch")
        try:
            payload = checkpoint_memory_read(source_pages, address, size)
        except KeyError as error:
            raise ValueError(
                f"memory-region checkpoint does not cover {address:#x}+{size:#x}"
            ) from error
        write_memory(address, payload)
        memory_checkpoint_regions.append(
            {
                "checkpoint_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "address": hex(address),
                "bytes": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    memory_checkpoint_copies: list[dict[str, object]] = []
    for specification in args.memory_checkpoint_copy:
        path_text, source_text, destination_text, size_text = specification.rsplit(
            ":", 3
        )
        source_path = Path(path_text)
        source_address = int(source_text, 0)
        destination_address = int(destination_text, 0)
        size = int(size_text, 0)
        if size <= 0 or size > 16 * 1024 * 1024:
            raise ValueError("checkpoint memory copy has an invalid size")
        with gzip.open(source_path, "rb") as stream:
            source_checkpoint = pickle.load(stream)
        source_pages = checkpoint_memory_pages(source_checkpoint)
        if source_checkpoint.get("binary_sha256") != actual_binary_sha256:
            raise ValueError("memory-copy checkpoint binary hash mismatch")
        try:
            payload = checkpoint_memory_read(source_pages, source_address, size)
        except KeyError as error:
            raise ValueError(
                "memory-copy checkpoint does not cover "
                f"{source_address:#x}+{size:#x}"
            ) from error
        write_memory(destination_address, payload)
        memory_checkpoint_copies.append(
            {
                "checkpoint_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "source_address": hex(source_address),
                "destination_address": hex(destination_address),
                "bytes": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    register_values: list[dict[str, str]] = []
    for specification in args.register_value:
        name, value_text = specification.split("=", 1)
        value = int(value_text, 0) & MASK64
        emulator.reg_write(register_id(name), value)
        register_values.append({"register": name, "value": hex(value)})
    register_copies: list[dict[str, str]] = []
    for specification in args.copy_register:
        destination, source = specification.split("=", 1)
        emulator.reg_write(
            register_id(destination),
            emulator.reg_read(register_id(source)),
        )
        register_copies.append({"destination": destination, "source": source})

    def read_cbytes(address: int, limit: int = 0x10000) -> bytes:
        data = bytearray()
        for offset in range(limit):
            byte = emulator.mem_read(address + offset, 1)[0]
            if byte == 0:
                return bytes(data)
            data.append(byte)
        raise ValueError(f"unterminated emulated string at {address:#x}")

    def set_x(index: int, value: int) -> None:
        emulator.reg_write(register_id(f"x{index}"), value & MASK64)

    def get_x(index: int) -> int:
        return emulator.reg_read(register_id(f"x{index}"))

    def set_errno(value: int) -> None:
        write_memory(errno_address, value.to_bytes(4, "little"))

    def match_file(path: bytes) -> tuple[bytes, bytes] | None:
        for suffix in sorted(file_payloads, key=len, reverse=True):
            if suffix not in removed_file_suffixes and path.endswith(suffix):
                return suffix, file_payloads[suffix]
        return None

    def safe_path_name(path: bytes) -> str:
        return posixpath.basename(path.decode("utf-8", "replace"))

    def record_file_event(
        symbol: str,
        path: bytes,
        result: str,
        *,
        suffix: bytes | None = None,
        size: int | None = None,
    ) -> None:
        event: dict[str, object] = {
            "function": symbol,
            "name": safe_path_name(path),
            "result": result,
            "return_address": hex(get_x(30)),
        }
        if suffix is not None:
            event["matched_suffix"] = suffix.decode("utf-8", "replace")
        if size is not None:
            event["size"] = size
        file_events.append(event)

    def write_stat_buffer(
        address: int, payload_size: int, suffix: bytes | None = None
    ) -> None:
        data = bytearray(DARWIN_STAT_SIZE)
        metadata = file_stat_metadata.get(suffix or b"", {})
        mode = metadata.get("mode", 0o644)
        uid = metadata.get("uid", 0)
        gid = metadata.get("gid", 0)
        data[0:4] = metadata.get("dev", 0).to_bytes(4, "little")
        data[4:6] = (0o100000 | (mode & 0o7777)).to_bytes(2, "little")
        data[6:8] = metadata.get("nlink", 1).to_bytes(2, "little")
        data[8:16] = metadata.get("ino", 0).to_bytes(8, "little")
        data[16:20] = uid.to_bytes(4, "little")
        data[20:24] = gid.to_bytes(4, "little")
        data[24:28] = metadata.get("rdev", 0).to_bytes(4, "little")
        for prefix, offset in (
            ("atime", 32), ("mtime", 48), ("ctime", 64), ("birthtime", 80)
        ):
            data[offset : offset + 8] = metadata.get(prefix, 0).to_bytes(8, "little")
            data[offset + 8 : offset + 16] = metadata.get(
                prefix + "_nsec", 0
            ).to_bytes(8, "little")
        data[96:104] = payload_size.to_bytes(8, "little")
        data[104:112] = metadata.get("blocks", 0).to_bytes(8, "little")
        data[112:116] = metadata.get("blksize", 0).to_bytes(4, "little")
        data[116:120] = metadata.get("flags", 0).to_bytes(4, "little")
        data[120:124] = metadata.get("gen", 0).to_bytes(4, "little")
        write_memory(address, bytes(data))

    def external_open(symbol: str) -> None:
        nonlocal next_fd
        path = read_cbytes(get_x(0))
        matched = match_file(path)
        if matched is None:
            if not args.missing_files_are_enoent:
                record_file_event(symbol, path, "unmodeled")
                stop(
                    "unmodeled-file",
                    emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                    {"function": symbol, "name": safe_path_name(path)},
                )
                return
            set_errno(2)
            set_x(0, 0xFFFFFFFF)
            record_file_event(symbol, path, "enoent")
            return
        suffix, payload = matched
        descriptor = next_fd
        next_fd += 1
        open_files[descriptor] = {
            "data": payload,
            "offset": 0,
            "path": path,
            "suffix": suffix,
        }
        set_x(0, descriptor)
        record_file_event(
            symbol,
            path,
            "opened",
            suffix=suffix,
            size=len(payload),
        )

    def external_stat(symbol: str) -> None:
        path = read_cbytes(get_x(0))
        matched = match_file(path)
        if matched is None:
            if not args.missing_files_are_enoent:
                record_file_event(symbol, path, "unmodeled")
                stop(
                    "unmodeled-file",
                    emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                    {"function": symbol, "name": safe_path_name(path)},
                )
                return
            set_errno(2)
            set_x(0, 0xFFFFFFFF)
            record_file_event(symbol, path, "enoent")
            return
        suffix, payload = matched
        write_stat_buffer(get_x(1), len(payload), suffix)
        set_x(0, 0)
        record_file_event(
            symbol,
            path,
            "found",
            suffix=suffix,
            size=len(payload),
        )

    def external_fstat(_symbol: str) -> None:
        descriptor = get_x(0)
        entry = open_files.get(descriptor)
        if entry is None:
            set_errno(9)
            set_x(0, 0xFFFFFFFF)
            return
        payload = entry["data"]
        assert isinstance(payload, bytes)
        suffix = entry.get("suffix")
        write_stat_buffer(
            get_x(1), len(payload), suffix if isinstance(suffix, bytes) else None
        )
        set_x(0, 0)

    def external_read(_symbol: str) -> None:
        descriptor = get_x(0)
        entry = open_files.get(descriptor)
        if entry is None:
            set_errno(9)
            set_x(0, 0xFFFFFFFF)
            return
        payload = entry["data"]
        offset = entry["offset"]
        assert isinstance(payload, bytes) and isinstance(offset, int)
        count = min(get_x(2), 0x10000000)
        data = payload[offset : offset + count]
        write_memory(get_x(1), data)
        entry["offset"] = offset + len(data)
        set_x(0, len(data))

    def external_close(_symbol: str) -> None:
        open_files.pop(get_x(0), None)
        set_x(0, 0)

    def external_unlink(symbol: str) -> None:
        path = read_cbytes(get_x(0))
        matched = match_file(path)
        if matched is None:
            set_errno(2)
            set_x(0, 0xFFFFFFFF)
            record_file_event(symbol, path, "enoent")
            return
        suffix, payload = matched
        removed_file_suffixes.add(suffix)
        set_x(0, 0)
        record_file_event(
            symbol,
            path,
            "removed-in-memory",
            suffix=suffix,
            size=len(payload),
        )

    def external_mmap(_symbol: str) -> None:
        descriptor = get_x(4)
        length = get_x(1)
        entry = open_files.get(descriptor)
        if entry is not None:
            payload = entry["data"]
            assert isinstance(payload, bytes)
            file_offset = get_x(5)
            accessible_length = (length + DARWIN_VM_PAGE_SIZE - 1) & -DARWIN_VM_PAGE_SIZE
            mapped = allocate(accessible_length)
            write_memory(
                mapped,
                payload[file_offset : file_offset + accessible_length],
            )
            set_x(0, mapped)
            return
        if descriptor in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF} and get_x(3) & 0x1000:
            set_x(0, allocate(length))
            return
        set_errno(9)
        set_x(0, MASK64)

    def external_malloc(symbol: str) -> None:
        if symbol in {"calloc", "malloc_type_calloc"}:
            size = get_x(0) * get_x(1)
        else:
            size = get_x(0)
        set_x(0, allocate(size))

    def external_memcpy(symbol: str) -> None:
        destination = get_x(0)
        source = get_x(1)
        count = min(get_x(2), 0x10000000)
        data = bytes(emulator.mem_read(source, count)) if count else b""
        memory_copy_events.append(
            {
                "function": symbol,
                "source": hex(source),
                "destination": hex(destination),
                "bytes": count,
                "sha256": hashlib.sha256(data).hexdigest(),
                "return_address": hex(get_x(30)),
            }
        )
        write_memory(destination, data)
        set_x(0, destination)

    def external_memset(_symbol: str) -> None:
        destination = get_x(0)
        value = get_x(1) & 0xFF
        count = min(get_x(2), 0x10000000)
        write_memory(destination, bytes([value]) * count)
        set_x(0, destination)

    def external_bzero(_symbol: str) -> None:
        destination = get_x(0)
        count = min(get_x(1), 0x10000000)
        write_memory(destination, bytes(count))

    def external_strlen(_symbol: str) -> None:
        set_x(0, len(read_cbytes(get_x(0))))

    def external_strnlen(_symbol: str) -> None:
        set_x(0, len(read_cbytes(get_x(0), min(get_x(1), 0x100000))))

    def external_errno(_symbol: str) -> None:
        set_x(0, errno_address)

    def external_zero_return(_symbol: str) -> None:
        set_x(0, 0)

    def external_free(_symbol: str) -> None:
        return

    def external_arc4random(_symbol: str) -> None:
        nonlocal random_state
        random_state = (1664525 * random_state + 1013904223) & 0xFFFFFFFF
        set_x(0, random_state)

    def external_gettimeofday(_symbol: str) -> None:
        destination = get_x(0)
        if destination:
            write_memory(
                destination,
                (1_700_000_000).to_bytes(8, "little") + bytes(8),
            )
        set_x(0, 0)

    def external_getpid(_symbol: str) -> None:
        set_x(0, 1234)

    def external_kqueue(_symbol: str) -> None:
        set_x(0, 0x900)

    def external_bootstrap_check_in(_symbol: str) -> None:
        nonlocal next_bootstrap_port
        write_memory(get_x(2), next_bootstrap_port.to_bytes(4, "little"))
        next_bootstrap_port += 1
        set_x(0, 0)

    def external_cf_mach_port_create(_symbol: str) -> None:
        nonlocal next_cf_object
        if get_x(4):
            write_memory(get_x(4), b"\0")
        set_x(0, next_cf_object)
        next_cf_object += 0x1000

    def external_cf_object_create(_symbol: str) -> None:
        nonlocal next_cf_object
        set_x(0, next_cf_object)
        next_cf_object += 0x1000

    def external_cf_run_loop_main(_symbol: str) -> None:
        set_x(0, 0x70007000F000)

    def external_xpc_connection_create(_symbol: str) -> None:
        nonlocal next_xpc_connection
        set_x(0, next_xpc_connection)
        next_xpc_connection += 0x1000

    def external_pthread_once(_symbol: str) -> None:
        token = get_x(0)
        callback = get_x(1)
        initialized = token in once_tokens
        pthread_once_events.append(
            {
                "token": hex(token),
                "callback": hex(callback),
                "already_initialized": initialized,
            }
        )
        if initialized:
            set_x(1, SYNTHETIC_NOOP_CALLBACK)
        else:
            once_tokens.add(token)

    def external_io_main_port(_symbol: str) -> None:
        destination = get_x(1)
        if destination:
            write_memory(destination, (1).to_bytes(4, "little"))
        set_x(0, 0)

    def external_io_service_matching(_symbol: str) -> None:
        set_x(0, 0x710200000000)

    def external_io_get_matching_services(_symbol: str) -> None:
        nonlocal next_io_iterator, next_io_service
        iterator = next_io_iterator
        next_io_iterator += 1
        service = next_io_service
        next_io_service += 1
        io_iterator_services[iterator] = service
        write_memory(get_x(2), iterator.to_bytes(4, "little"))
        set_x(0, 0)

    def external_io_iterator_next(_symbol: str) -> None:
        iterator = get_x(0) & 0xFFFFFFFF
        set_x(0, io_iterator_services.pop(iterator, 0))

    def external_io_service_open(_symbol: str) -> None:
        nonlocal next_io_connection
        connection = next_io_connection
        next_io_connection += 1
        write_memory(get_x(3), connection.to_bytes(4, "little"))
        set_x(0, 0)

    def read_constant_cf_string(address: int) -> str:
        cstring = int.from_bytes(emulator.mem_read(address + 16, 8), "little")
        length = int.from_bytes(emulator.mem_read(address + 24, 8), "little")
        if length > 0x1000:
            raise ValueError(f"invalid constant CFString length: {length:#x}")
        return bytes(emulator.mem_read(cstring, length)).decode("utf-8", "replace")

    def external_io_registry_property(symbol: str) -> None:
        key = read_constant_cf_string(get_x(1))
        if key == "IOBuiltin":
            value: tuple[str, object] = ("boolean", True)
        elif key == "IOMACAddress":
            value = ("data", modeled_mac_address)
        else:
            stop(
                "unmodeled-ioregistry-property",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"function": symbol, "key": key},
            )
            return
        result = allocate(1)
        fake_cf_values[result] = value
        set_x(0, result)

    def external_cf_boolean_get_value(symbol: str) -> None:
        value = fake_cf_values.get(get_x(0))
        if value is None or value[0] != "boolean":
            stop(
                "unmodeled-cf-value",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"function": symbol},
            )
            return
        set_x(0, int(bool(value[1])))

    def external_cf_data_get_bytes(symbol: str) -> None:
        value = fake_cf_values.get(get_x(0))
        if value is None or value[0] != "data" or not isinstance(value[1], bytes):
            stop(
                "unmodeled-cf-value",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"function": symbol},
            )
            return
        offset = get_x(1)
        length = get_x(2)
        write_memory(get_x(3), value[1][offset : offset + length])

    def external_cf_release(_symbol: str) -> None:
        fake_cf_values.pop(get_x(0), None)

    def external_io_registry_parent(_symbol: str) -> None:
        nonlocal next_io_service
        parent = next_io_service
        next_io_service += 1
        write_memory(get_x(2), parent.to_bytes(4, "little"))
        set_x(0, 0)

    def external_io_connect_struct_method(symbol: str) -> None:
        output_size_pointer = get_x(5)
        output_capacity = (
            int.from_bytes(emulator.mem_read(output_size_pointer, 8), "little")
            if output_size_pointer
            else 0
        )
        selector = get_x(1) & 0xFFFFFFFF
        if selector == 0x16:
            output = (0x4B130000).to_bytes(4, "little")
        elif selector == 0x17:
            output = (0x1F8).to_bytes(4, "little")
        elif selector == 0x15 and args.iokit15_output is not None:
            output = args.iokit15_output.read_bytes()
        else:
            stop(
                "unmodeled-iokit-method",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {
                    "function": symbol,
                    "selector": hex(selector),
                    "input_size": get_x(3),
                    "output_capacity": output_capacity,
                },
            )
            return
        if len(output) > output_capacity:
            raise ValueError(
                f"IOKit selector {selector:#x} output exceeds capacity"
            )
        write_memory(get_x(4), output)
        write_memory(output_size_pointer, len(output).to_bytes(8, "little"))
        set_x(0, 0)

    external_handlers: dict[str, Callable[[str], None]] = {
        "open": external_open,
        "open_dprotected_np": external_open,
        "stat": external_stat,
        "lstat": external_stat,
        "fstat": external_fstat,
        "read": external_read,
        "close": external_close,
        "unlink": external_unlink,
        "mmap": external_mmap,
        "munmap": external_zero_return,
        "malloc": external_malloc,
        "malloc_type_malloc": external_malloc,
        "calloc": external_malloc,
        "malloc_type_calloc": external_malloc,
        "free": external_free,
        "arc4random": external_arc4random,
        "gettimeofday": external_gettimeofday,
        "getpid": external_getpid,
        "kqueue": external_kqueue,
        "kevent": external_zero_return,
        "signal": external_zero_return,
        "sched_yield": external_zero_return,
        "umask": external_zero_return,
        "notify_cancel": external_zero_return,
        "notify_post": external_zero_return,
        "vm_deallocate": external_zero_return,
        "bootstrap_check_in": external_bootstrap_check_in,
        "CFMachPortCreateWithPort": external_cf_mach_port_create,
        "CFMachPortCreateRunLoopSource": external_cf_object_create,
        "CFFileDescriptorCreate": external_cf_object_create,
        "CFFileDescriptorCreateRunLoopSource": external_cf_object_create,
        "CFFileDescriptorEnableCallBacks": external_free,
        "CFRunLoopGetMain": external_cf_run_loop_main,
        "CFRunLoopAddSource": external_free,
        "xpc_connection_create_mach_service": external_xpc_connection_create,
        "xpc_connection_activate": external_free,
        "xpc_connection_cancel": external_free,
        "xpc_connection_resume": external_free,
        "xpc_connection_send_message": external_free,
        "xpc_connection_set_event_handler": external_free,
        "xpc_connection_set_target_queue": external_free,
        "memcpy": external_memcpy,
        "memmove": external_memcpy,
        "memset": external_memset,
        "bzero": external_bzero,
        "strlen": external_strlen,
        "strnlen": external_strnlen,
        "error": external_errno,
        "pthread_set_qos_class_self_np": external_zero_return,
        "pthread_mutex_destroy": external_zero_return,
        "pthread_mutex_init": external_zero_return,
        "pthread_mutex_lock": external_zero_return,
        "pthread_mutex_unlock": external_zero_return,
        "pthread_rwlock_destroy": external_zero_return,
        "pthread_rwlock_init": external_zero_return,
        "pthread_rwlock_rdlock": external_zero_return,
        "pthread_rwlock_unlock": external_zero_return,
        "pthread_rwlock_wrlock": external_zero_return,
        "chkstk_darwin": external_free,
        "pthread_once": external_pthread_once,
        "IOMainPort": external_io_main_port,
        "IOBSDNameMatching": external_io_service_matching,
        "IOServiceMatching": external_io_service_matching,
        "IOServiceGetMatchingServices": external_io_get_matching_services,
        "IOIteratorNext": external_io_iterator_next,
        "IOServiceOpen": external_io_service_open,
        "IOObjectRelease": external_zero_return,
        "IOConnectCallStructMethod": external_io_connect_struct_method,
        "IORegistryEntryCreateCFProperty": external_io_registry_property,
        "IORegistryEntryGetParentEntry": external_io_registry_parent,
        "CFBooleanGetValue": external_cf_boolean_get_value,
        "CFDataGetBytes": external_cf_data_get_bytes,
        "CFRelease": external_cf_release,
        # Best-effort backup metadata only.  A successful call returns
        # no data consumed by the FairPlay transaction itself.
        "CSBackupSetItemExcluded": external_zero_return,
    }

    def on_external_code(
        _uc: Uc,
        address: int,
        _size: int,
        user_data: object,
    ) -> None:
        symbol = str(user_data)
        handler = external_handlers[symbol]
        modeled_externals[symbol] = modeled_externals.get(symbol, 0) + 1
        try:
            handler(symbol)
        except (UcError, ValueError, OverflowError) as error:
            stop(
                "external-model-error",
                address,
                {"function": symbol, "error": str(error)},
            )

    def install_external_stub(address: int, symbol: str) -> None:
        if address in external_stub_addresses:
            return
        ensure_page_mapped(address)
        emulator.mem_write(
            address,
            PTHREAD_ONCE_STUB
            if symbol == "pthread_once"
            else RET_X30.to_bytes(4, "little"),
        )
        emulator.hook_add(
            UC_HOOK_CODE,
            on_external_code,
            user_data=symbol,
            begin=address,
            end=address,
        )
        external_stub_addresses.add(address)

    def on_once_return(
        _uc: Uc,
        _address: int,
        _size: int,
        resume: object,
    ) -> None:
        set_x(0, 0)
        set_x(30, int(resume))

    def install_once_return_stub(address: int, resume: int) -> None:
        if address in external_stub_addresses:
            return
        ensure_page_mapped(address)
        emulator.mem_write(address, RET_X30.to_bytes(4, "little"))
        emulator.hook_add(
            UC_HOOK_CODE,
            on_once_return,
            user_data=resume,
            begin=address,
            end=address,
        )
        external_stub_addresses.add(address)

    def on_code(_uc: Uc, address: int, _size: int, _user: object) -> None:
        nonlocal previous_pc
        if state["instructions"] is not None:
            state["instructions"] += 1
        state["pc"] = address
        if address in stopped_register_read_sites:
            stop(
                "register-read",
                address,
                {"registers": sorted(set(args.stop_on_register_read))},
            )
            return
        for name, previous_value in tuple(watched_register_values.items()):
            current_value = emulator.reg_read(register_id(name))
            if current_value != previous_value:
                event = {
                    "register": name,
                    "writer_pc": hex(previous_pc) if previous_pc is not None else None,
                    "observed_at": hex(address),
                }
                if args.include_watched_register_values:
                    event.update(
                        {
                            "previous_value": hex(previous_value),
                            "current_value": hex(current_value),
                        }
                    )
                watched_register_events.append(event)
                watched_register_values[name] = current_value
                if name in args.stop_on_register_change:
                    stop(
                        "register-change",
                        address,
                        {
                            "register": name,
                            "writer_pc": (
                                hex(previous_pc) if previous_pc is not None else None
                            ),
                        },
                    )
                    return
        previous_pc = address
        if recent_pcs is not None:
            recent_pcs.append(address)
        if address in stop_addresses:
            hit = stop_hits.get(address, 0) + 1
            stop_hits[address] = hit
            if hit >= args.stop_hit:
                stop("breakpoint", address, {"hit": hit})

    def on_recent_block(
        _uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        if recent_pcs is not None:
            recent_pcs.append(address)

    def on_traced_code(
        _uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        if len(traced_code_events) >= args.max_code_trace_events:
            stop(
                "code-trace-event-limit",
                address,
                {"limit": args.max_code_trace_events},
            )
            return
        hit = traced_code_hit_counts.get(address, 0) + 1
        traced_code_hit_counts[address] = hit
        stack_pointer = emulator.reg_read(arm64_const.UC_ARM64_REG_SP)
        traced_code_events.append(
            {
                "pc": hex(address),
                "hit": hit,
                "registers": {
                    name: hex(emulator.reg_read(register_id(name)))
                    for name in args.trace_code_register
                },
                "stack_bytes": [
                    {
                        "offset": hex(offset),
                        "size": size,
                        "value": bytes(
                            emulator.mem_read(stack_pointer + offset, size)
                        ).hex(),
                    }
                    for offset, size in traced_code_stack_ranges
                ],
            }
        )

    def on_breakpoint(_uc: Uc, address: int, _size: int, _user: object) -> None:
        state["pc"] = address
        hit = stop_hits.get(address, 0) + 1
        stop_hits[address] = hit
        if hit >= args.stop_hit:
            stop("breakpoint", address, {"hit": hit})

    priv_start = checkpoint["working_sinf"] + checkpoint["priv_offset"]
    priv_end = priv_start + checkpoint["priv_length"]

    def on_read(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if address < priv_end and address + size > priv_start:
            stop(
                "priv-read",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"offset": address - priv_start, "size": size},
            )

    def on_all_reads(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if len(memory_read_events) >= args.max_memory_read_events:
            stop(
                "memory-read-event-limit",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"limit": args.max_memory_read_events},
            )
            return
        memory_read_events.append(
            {
                "pc": hex(emulator.reg_read(arm64_const.UC_ARM64_REG_PC)),
                "address": hex(address),
                "size": size,
            }
        )

    def on_all_writes(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if len(memory_write_events) >= args.max_memory_write_events:
            stop(
                "memory-write-event-limit",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"limit": args.max_memory_write_events},
            )
            return
        event: dict[str, object] = {
            "pc": hex(emulator.reg_read(arm64_const.UC_ARM64_REG_PC)),
            "address": hex(address),
            "size": size,
        }
        if args.include_memory_write_values:
            event["value"] = hex(value & ((1 << (size * 8)) - 1))
        memory_write_events.append(event)

    def on_range_read(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        bounds: object,
    ) -> None:
        start, end = bounds
        if address >= end or address + size <= start:
            return
        if len(memory_range_read_events) >= args.max_memory_read_events:
            stop(
                "memory-read-event-limit",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"limit": args.max_memory_read_events},
            )
            return
        memory_range_read_events.append(
            {
                "pc": hex(emulator.reg_read(arm64_const.UC_ARM64_REG_PC)),
                "address": hex(address),
                "size": size,
            }
        )

    def on_range_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        bounds: object,
    ) -> None:
        start, end = bounds
        if address >= end or address + size <= start:
            return
        if len(memory_range_write_events) >= args.max_memory_write_events:
            stop(
                "memory-write-event-limit",
                emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                {"limit": args.max_memory_write_events},
            )
            return
        memory_range_write_events.append(
            {
                "pc": hex(emulator.reg_read(arm64_const.UC_ARM64_REG_PC)),
                "address": hex(address),
                "size": size,
            }
        )

    def on_stopped_range_read(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        bounds: object,
    ) -> None:
        start, end = bounds
        if address >= end or address + size <= start:
            return
        stop(
            "memory-range-read",
            emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
            {
                "range_start": hex(int(start)),
                "range_size": int(end) - int(start),
                "read_address": hex(address),
                "read_size": size,
            },
        )

    def on_stopped_range_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        bounds: object,
    ) -> None:
        start, end = bounds
        if address >= end or address + size <= start:
            return
        stop(
            "memory-range-write",
            emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
            {
                "range_start": hex(int(start)),
                "range_size": int(end) - int(start),
                "write_address": hex(address),
                "write_size": size,
            },
        )

    def on_dispatch_table_read(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        base = args.trace_dispatch_table_base
        if base is None or size != 8 or address < base:
            return
        index = (address - base) // 8
        if address != base + index * 8:
            return
        target = int.from_bytes(emulator.mem_read(address, 8), "little")
        pc = emulator.reg_read(arm64_const.UC_ARM64_REG_PC)
        key = (pc, index, target)
        event = dispatch_table_reads.get(key)
        if event is None:
            event = {
                "pc": hex(pc),
                "index": hex(index),
                "target": hex(target),
                "count": 1,
                "first_ordinal": len(dispatch_table_reads),
            }
            if args.include_dispatch_registers:
                event["registers"] = {
                    f"x{register_index}": hex(get_x(register_index))
                    for register_index in range(31)
                }
                event["registers"]["sp"] = hex(
                    emulator.reg_read(arm64_const.UC_ARM64_REG_SP)
                )
                event["nzcv"] = hex(
                    emulator.reg_read(arm64_const.UC_ARM64_REG_NZCV)
                )
            dispatch_table_reads[key] = event
        else:
            event["count"] = int(event["count"]) + 1

    def on_force_dispatch(
        _uc: Uc,
        address: int,
        _size: int,
        specification: object,
    ) -> None:
        register, index = specification
        register = str(register)
        previous = emulator.reg_read(register_id(register)) & 0xFFFFFFFF
        emulator.reg_write(register_id(register), int(index))
        forced_dispatch_events.append(
            {
                "pc": hex(address),
                "register": register,
                "previous_index": hex(previous),
                "forced_index": hex(int(index)),
            }
        )

    def on_watched_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        watched_address: object,
    ) -> None:
        event = {
            "watched_address": hex(int(watched_address)),
            "write_address": hex(address),
            "size": size,
            "pc": hex(emulator.reg_read(arm64_const.UC_ARM64_REG_PC)),
        }
        if args.include_watched_write_values:
            event["value"] = hex(value & ((1 << (size * 8)) - 1))
        watched_write_events.append(event)

    def on_watched_read(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        watched_address: object,
    ) -> None:
        watched_read_events.append(
            {
                "watched_address": hex(int(watched_address)),
                "read_address": hex(address),
                "size": size,
                "pc": hex(emulator.reg_read(arm64_const.UC_ARM64_REG_PC)),
            }
        )

    def on_eor3(
        _uc: Uc,
        address: int,
        _size: int,
        operands: object,
    ) -> None:
        destination, left, middle, right = operands
        emulator.reg_write(
            register_id(str(destination)),
            emulator.reg_read(register_id(str(left)))
            ^ emulator.reg_read(register_id(str(middle)))
            ^ emulator.reg_read(register_id(str(right))),
        )
        if (
            args.preserve_special_instruction_bytes
            or address in args.preserve_text_instruction
        ):
            emulator.reg_write(arm64_const.UC_ARM64_REG_PC, address + 4)

    def on_casal(
        _uc: Uc,
        _instruction_address: int,
        _size: int,
        operands: object,
    ) -> None:
        expected_name, desired_name, base_name = operands
        address = emulator.reg_read(register_id(str(base_name)))
        old = int.from_bytes(emulator.mem_read(address, 4), "little")
        expected = emulator.reg_read(register_id(str(expected_name))) & 0xFFFFFFFF
        if old == expected:
            desired = emulator.reg_read(register_id(str(desired_name))) & 0xFFFFFFFF
            emulator.mem_write(address, desired.to_bytes(4, "little"))
        emulator.reg_write(register_id(str(expected_name)), old)
        if (
            args.preserve_special_instruction_bytes
            or _instruction_address in args.preserve_text_instruction
        ):
            emulator.reg_write(
                arm64_const.UC_ARM64_REG_PC, _instruction_address + 4
            )

    def on_pointer_auth(
        _uc: Uc,
        address: int,
        _size: int,
        operation: object,
    ) -> None:
        kind, register_name = operation
        if kind == "branch":
            emulator.reg_write(
                arm64_const.UC_ARM64_REG_PC,
                emulator.reg_read(register_id(str(register_name))),
            )
        elif kind == "call":
            emulator.reg_write(arm64_const.UC_ARM64_REG_LR, address + 4)
            emulator.reg_write(
                arm64_const.UC_ARM64_REG_PC,
                emulator.reg_read(register_id(str(register_name))),
            )
        elif kind == "return":
            emulator.reg_write(
                arm64_const.UC_ARM64_REG_PC,
                emulator.reg_read(arm64_const.UC_ARM64_REG_LR),
            )
        elif kind == "nop":
            emulator.reg_write(arm64_const.UC_ARM64_REG_PC, address + 4)
        else:
            raise ValueError(f"unknown pointer-auth operation {kind!r}")

    def on_authenticated_load(
        _uc: Uc,
        instruction_address: int,
        _size: int,
        operands: object,
    ) -> None:
        destination_name, base_name, displacement, writeback = operands
        address = (
            emulator.reg_read(register_id(str(base_name))) + int(displacement)
        ) & MASK64
        value = int.from_bytes(emulator.mem_read(address, 8), "little")
        emulator.reg_write(register_id(str(destination_name)), value)
        if writeback:
            emulator.reg_write(register_id(str(base_name)), address)
        emulator.reg_write(
            arm64_const.UC_ARM64_REG_PC, instruction_address + 4
        )

    def on_invalid_memory(
        _uc: Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED and address in pending_once_returns:
            install_once_return_stub(address, pending_once_returns[address])
            return True
        if access == UC_MEM_FETCH_UNMAPPED and address in external_names:
            symbol = external_names[address].lstrip("_")
            if symbol in external_handlers:
                install_external_stub(address, symbol)
                return True
            stop(
                "unmodeled-external",
                address,
                {"function": symbol, "return_address": hex(get_x(30))},
            )
            return False
        if (
            (
                0x700000000000 <= address < 0x800000000000
                or address >= 0xF000000000000000
            )
            and access not in {UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT}
        ):
            page = page_down(address)
            ensure_page_mapped(page)
            lazy_zero_pages.add(page)
            return True
        if (
            args.map_arbitrary_data_pages
            and access not in {UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT}
            and address >= PAGE_SIZE
        ):
            page = page_down(address)
            if len(arbitrary_zero_pages) >= args.max_arbitrary_data_pages:
                stop(
                    "arbitrary-page-limit",
                    emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
                    {"address": hex(address), "limit": args.max_arbitrary_data_pages},
                )
                return False
            ensure_page_mapped(page)
            arbitrary_zero_pages.add(page)
            return True
        stop(
            "invalid-memory",
            emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
            {
                "access": access,
                "address": hex(address),
                "size": size,
                "value": hex(value),
                "x2": hex(get_x(2)),
                "x11": hex(get_x(11)),
                "return_address": hex(get_x(30)),
            },
        )
        return False

    def on_invalid_instruction(_uc: Uc, _user: object) -> bool:
        stop(
            "invalid-instruction",
            emulator.reg_read(arm64_const.UC_ARM64_REG_PC),
        )
        return False

    if (
        args.trace_instructions
        or watched_register_values
        or stopped_register_read_sites
    ):
        emulator.hook_add(UC_HOOK_CODE, on_code)
    else:
        state["instructions"] = None
        if recent_pcs is not None:
            emulator.hook_add(UC_HOOK_BLOCK, on_recent_block)
        for address in stop_addresses:
            emulator.hook_add(
                UC_HOOK_CODE,
                on_breakpoint,
                begin=address,
                end=address,
            )
    for address in traced_code_addresses:
        emulator.hook_add(
            UC_HOOK_CODE,
            on_traced_code,
            begin=address,
            end=address,
        )
    emulator.hook_add(
        UC_HOOK_MEM_READ,
        on_read,
        begin=priv_start,
        end=priv_end - 1,
    )
    if args.trace_memory_reads:
        emulator.hook_add(UC_HOOK_MEM_READ, on_all_reads)
    if args.trace_memory_writes:
        emulator.hook_add(UC_HOOK_MEM_WRITE, on_all_writes)
    for start, end in traced_memory_read_ranges:
        emulator.hook_add(
            UC_HOOK_MEM_READ,
            on_range_read,
            user_data=(start, end),
            begin=start,
            end=end - 1,
        )
    for start, end in traced_memory_write_ranges:
        emulator.hook_add(
            UC_HOOK_MEM_WRITE,
            on_range_write,
            user_data=(start, end),
            begin=start,
            end=end - 1,
        )
    for start, end in stopped_memory_read_ranges:
        emulator.hook_add(
            UC_HOOK_MEM_READ,
            on_stopped_range_read,
            user_data=(start, end),
            begin=start,
            end=end - 1,
        )
    for start, end in stopped_memory_write_ranges:
        emulator.hook_add(
            UC_HOOK_MEM_WRITE,
            on_stopped_range_write,
            user_data=(start, end),
            begin=start,
            end=end - 1,
        )
    if args.trace_dispatch_table_base is not None:
        if args.trace_dispatch_table_entries <= 0:
            parser.error(
                "--trace-dispatch-table-entries must be positive when the "
                "dispatch-table base is supplied"
            )
        dispatch_end = (
            args.trace_dispatch_table_base
            + args.trace_dispatch_table_entries * 8
            - 1
        )
        emulator.hook_add(
            UC_HOOK_MEM_READ,
            on_dispatch_table_read,
            begin=args.trace_dispatch_table_base,
            end=dispatch_end,
        )
    for load_pc, specification in forced_dispatch_specs.items():
        emulator.hook_add(
            UC_HOOK_CODE,
            on_force_dispatch,
            user_data=specification,
            begin=load_pc,
            end=load_pc,
        )
    for watched_address in args.watch_write_address:
        emulator.hook_add(
            UC_HOOK_MEM_WRITE,
            on_watched_write,
            user_data=watched_address,
            begin=watched_address,
            end=watched_address,
        )
    for watched_address in args.watch_read_address:
        emulator.hook_add(
            UC_HOOK_MEM_READ,
            on_watched_read,
            user_data=watched_address,
            begin=watched_address,
            end=watched_address,
        )
    for address, operands in eor3_sites.items():
        emulator.hook_add(
            UC_HOOK_CODE,
            on_eor3,
            user_data=operands,
            begin=address,
            end=address,
        )
    for address, operation in pointer_auth_sites.items():
        emulator.hook_add(
            UC_HOOK_CODE,
            on_pointer_auth,
            user_data=operation,
            begin=address,
            end=address,
        )
    for address, operands in casal_sites.items():
        emulator.hook_add(
            UC_HOOK_CODE,
            on_casal,
            user_data=operands,
            begin=address,
            end=address,
        )
    for address, operands in authenticated_load_sites.items():
        emulator.hook_add(
            UC_HOOK_CODE,
            on_authenticated_load,
            user_data=operands,
            begin=address,
            end=address,
        )
    emulator.hook_add(UC_HOOK_MEM_INVALID, on_invalid_memory)
    emulator.hook_add(UC_HOOK_INSN_INVALID, on_invalid_instruction)

    try:
        emulator.emu_start(start_pc, 0, count=args.count)
    except UcError as error:
        if state["reason"] == "instruction-limit":
            state["reason"] = "unicorn-error"
            state["detail"] = str(error)

    final_pc = emulator.reg_read(arm64_const.UC_ARM64_REG_PC)
    if state["reason"] == "instruction-limit" and final_pc == 0:
        state["reason"] = "return"
    registers = {
        f"x{index}": emulator.reg_read(register_id(f"x{index}"))
        for index in range(31)
    }
    registers["sp"] = emulator.reg_read(arm64_const.UC_ARM64_REG_SP)
    vector_registers = {
        f"v{index}": emulator.reg_read(register_id(f"v{index}"))
        for index in range(32)
    }
    final_nzcv_value = emulator.reg_read(arm64_const.UC_ARM64_REG_NZCV)

    if args.checkpoint_output is not None:
        checkpoint_pages: dict[int, bytes] = {}
        for page in sorted(dynamic_mapped_pages):
            if page >= 0xF000000000000000:
                continue
            page_data = bytes(emulator.mem_read(page, PAGE_SIZE))
            if any(page_data):
                checkpoint_pages[page] = page_data
        for segment in database.segments:
            if segment.name not in {"__DATA_CONST", "__DATA"} or not segment.vmsize:
                continue
            start_page = page_down(segment.vmaddr)
            end_page = page_up(segment.vmaddr + segment.vmsize)
            for page in range(start_page, end_page, PAGE_SIZE):
                page_data = bytes(emulator.mem_read(page, PAGE_SIZE))
                if any(page_data):
                    checkpoint_pages[page] = page_data
        output_checkpoint = {
            "schema": 2,
            "binary": str(binary),
            "binary_sha256": actual_binary_sha256,
            "pc": hex(final_pc),
            "registers": {**registers, **vector_registers},
            "nzcv": {
                "n": (final_nzcv_value >> 31) & 1,
                "z": (final_nzcv_value >> 30) & 1,
                "c": (final_nzcv_value >> 29) & 1,
                "v": (final_nzcv_value >> 28) & 1,
            },
            "memory_pages": checkpoint_pages,
            "working_sinf": checkpoint["working_sinf"],
            "priv_offset": checkpoint["priv_offset"],
            "priv_length": checkpoint["priv_length"],
            "state_slot": checkpoint["state_slot"],
            "once_tokens": sorted(once_tokens),
            "next_allocation": next_allocation,
            "random_state": random_state,
            "open_files": open_files,
            "next_fd": next_fd,
            "removed_file_suffixes": sorted(
                suffix.decode("utf-8", "replace")
                for suffix in removed_file_suffixes
            ),
        }
        args.checkpoint_output.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(args.checkpoint_output, "wb", compresslevel=1) as stream:
            pickle.dump(output_checkpoint, stream, protocol=pickle.HIGHEST_PROTOCOL)
        args.checkpoint_output.chmod(0o600)
    report = {
        "schema": 1,
        "checkpoint": str(args.checkpoint),
        "checkpoint_sha256": checkpoint_sha256,
        "binary_sha256": actual_binary_sha256,
        "start_pc": hex(start_pc),
        "checkpoint_pc": hex(checkpoint_pc),
        "stop": {
            "reason": state["reason"],
            "pc": hex(final_pc),
            "instructions": state["instructions"],
            "instruction_budget": args.count,
            "detail": state["detail"],
        },
        "stop_hits": {hex(address): hits for address, hits in stop_hits.items()},
        "recent_pcs": (
            [hex(address) for address in recent_pcs]
            if recent_pcs is not None
            else []
        ),
        "pointer_auth_patches": patch_counts,
        "mapped_checkpoint_pages": mapped_pages,
        "overlaid_image_pages": overlaid_pages,
        "lazy_zero_pages": len(lazy_zero_pages),
        "arbitrary_zero_pages": len(arbitrary_zero_pages),
        "modeled_externals": modeled_externals,
        "memory_overrides": memory_overrides,
        "memory_blob_overrides": memory_blob_overrides,
        "memory_checkpoint_regions": memory_checkpoint_regions,
        "memory_checkpoint_copies": memory_checkpoint_copies,
        "register_values": register_values,
        "register_copies": register_copies,
        "initial_once_token_count": initial_once_token_count,
        "initial_open_file_count": initial_open_file_count,
        "allocation_mode": allocation_mode,
        "final_once_token_count": len(once_tokens),
        "final_open_file_count": len(open_files),
        "pthread_once_events": pthread_once_events,
        "file_payloads": file_payload_metadata,
        "file_events": file_events,
        "modeled_mac_source": modeled_mac_source,
        "watched_write_events": watched_write_events,
        "watched_read_events": watched_read_events,
        "memory_read_events": memory_read_events,
        "memory_write_events": memory_write_events,
        "memory_copy_events": memory_copy_events,
        "memory_range_read_events": memory_range_read_events,
        "memory_range_write_events": memory_range_write_events,
        "dispatch_table_reads": sorted(
            dispatch_table_reads.values(),
            key=lambda event: int(event["first_ordinal"]),
        ),
        "forced_dispatch_events": forced_dispatch_events,
        "watched_register_events": watched_register_events,
        "traced_code_events": traced_code_events,
        "priv_read": state["reason"] == "priv-read",
        "return_x0_signed": (
            registers["x0"] - (1 << 64)
            if registers["x0"] & (1 << 63)
            else registers["x0"]
        ) if state["reason"] == "return" else None,
        "return_w0_signed": (
            (registers["x0"] & 0xFFFFFFFF) - (1 << 32)
            if registers["x0"] & (1 << 31)
            else registers["x0"] & 0xFFFFFFFF
        ) if state["reason"] == "return" else None,
        "checkpoint_output": (
            str(args.checkpoint_output) if args.checkpoint_output is not None else None
        ),
        "reported_memory_ranges": [
            {
                "address": hex(address),
                "bytes": size,
                "sha256": hashlib.sha256(
                    bytes(emulator.mem_read(address, size))
                ).hexdigest(),
                "nonzero_bytes": sum(
                    byte != 0 for byte in emulator.mem_read(address, size)
                ),
            }
            for address, size in reported_memory_ranges
        ],
        "register_sha256": hashlib.sha256(
            b"".join(registers[name].to_bytes(8, "little") for name in sorted(registers))
        ).hexdigest(),
        **(
            {"registers": {name: hex(value) for name, value in registers.items()}}
            if args.include_registers
            else {}
        ),
    }
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized)
        args.output.chmod(0o600)
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    status = main()
    sys.stdout.flush()
    sys.stderr.flush()
    # Unicorn teardown rebuilds a very large memory topology and can take
    # minutes after every private output has already been closed. This is a
    # one-shot command, so bypass interpreter finalizers after an explicit
    # flush instead of paying that irrelevant cleanup cost.
    os._exit(status)
