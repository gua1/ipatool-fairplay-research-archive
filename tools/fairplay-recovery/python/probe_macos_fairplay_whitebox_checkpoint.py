#!/usr/bin/env python3
"""Probe one macOS fairplayd protected 16-byte block from a saved checkpoint.

The checkpoint is taken at the first instruction of ``sub_100132A94``.  One
invocation returns to the same dispatch entry for the next aligned block, so a
persistent Unicorn instance can vary the current input and stop at that second
entry without replaying the surrounding request-502 transaction.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, replace
import gzip
import hashlib
import json
import os
from pathlib import Path
import pickle
import time
from typing import Any

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_MEM, CS_OP_REG, Cs
from capstone.arm64_const import ARM64_REG_INVALID
from unicorn import (
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
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

from continue_fairplay_checkpoint_unicorn import (
    KNOWN_EOR3_SITES_26A428,
    MASK64,
    PAGE_SIZE,
    RET_X30,
    checkpoint_memory_pages,
    checkpoint_memory_read,
    map_checkpoint_memory,
    page_down,
    page_up,
    patch_pointer_authentication,
    register_id,
)
from raw_macho_db import RawMachODatabase, dyld_info_fixups


ENTRY = 0x100132AD0
BLOCK = 0x7000000FB564

try:
    from darkphoenixAES.WhiteBoxedAES import WhiteBoxedAESAuto, WhiteBoxedAESDynamic
except ImportError:
    class WhiteBoxedAESAuto:  # type: ignore[no-redef]
        pass
    class WhiteBoxedAESDynamic:  # type: ignore[no-redef]
        pass


@dataclass(frozen=True)
class FaultSite:
    round_index: int
    byte_index: int
    pc: int
    index_register: str | None
    after_pc: int | None = None
    after_register: str | None = None
    after_shift: int = 0
    index_domain: tuple[int, ...] | None = None
    hit_target: int = 1
    pointer_register: str | None = None
    pointer_table_bytes: int = 0x400
    pointer_entry_bytes: int = 4
    restore_register: bool = True


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_private(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def inverse_tables(tables: list[list[int]]) -> list[list[int]]:
    result: list[list[int]] = []
    for table in tables:
        if len(table) != 256 or len(set(table)) != 256:
            raise ValueError("encoding table is not bijective")
        inverse = [0] * 256
        for source, target in enumerate(table):
            inverse[target] = source
        result.append(inverse)
    return result


def recover_known_key_encodings(
    oracle: "CheckpointBlockOracle",
    template: bytes,
    baseline_events: list[tuple[int, int, int]],
    dependency_events: list[int],
    dependency_pcs: list[int],
    key: bytes,
    validation_cases: int,
) -> dict[str, Any]:
    from darkphoenixAES.AES import AES, _AesInvSBox, _AesSBox, expandKey

    if len(key) != 16:
        raise ValueError("known recovery currently expects AES-128")

    input_table_indices: list[list[int]] = []
    table_bases: list[int] = []
    for position, event_index in enumerate(dependency_events):
        addresses = []
        expected_pc = dependency_pcs[position]
        for value in range(256):
            block = bytearray(template)
            block[position] = value
            _output, observed = oracle.run(bytes(block), capture_reads=True)
            if len(observed) <= event_index or observed[event_index][0] != expected_pc:
                raise ValueError("first table dependency changed position")
            if observed[event_index][2] != 4:
                raise ValueError("first table dependency is not a dword read")
            addresses.append(observed[event_index][1])
        unique = sorted(set(addresses))
        if len(unique) != 256:
            raise ValueError(f"input byte {position} table is not bijective")
        base = unique[0]
        if unique != list(range(base, base + 4 * 256, 4)):
            raise ValueError(
                f"input byte {position} table is not one contiguous dword table"
            )
        input_table_indices.append([(address - base) // 4 for address in addresses])
        table_bases.append(base)

    aes = AES(key)
    round_keys = expandKey(key, 10)

    def inverse_permutation(value: tuple[int, ...]) -> tuple[int, ...]:
        result = [0] * len(value)
        for index, mapped in enumerate(value):
            result[mapped] = index
        return tuple(result)

    def compose(
        left: tuple[int, ...], right: tuple[int, ...]
    ) -> tuple[int, ...]:
        return tuple(left[right[index]] for index in range(len(left)))

    identity = tuple(range(16))
    standard_shift = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
    transpose = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    page_whitebox_order = (0, 6, 10, 5, 9, 14, 15, 7, 11, 12, 13, 8, 2, 1, 3, 4)
    seeds = {
        identity,
        standard_shift,
        inverse_permutation(standard_shift),
        transpose,
        page_whitebox_order,
        inverse_permutation(page_whitebox_order),
    }
    candidates = set(seeds)
    for left in list(seeds):
        for right in list(seeds):
            candidates.add(compose(left, right))
            candidates.add(compose(right, left))

    def cipher_block(value: bytes, direction: str) -> bytes:
        return aes.encrypt(value) if direction == "encrypt" else aes.decrypt(value)

    input_modes = (
        "identity",
        "xor-key",
        "sbox",
        "invsbox",
        "sbox-xor-key",
        "invsbox-xor-key",
        "sbox-after-key",
        "invsbox-after-key",
    )

    def logical_input_tables(
        position_order: tuple[int, ...], core_direction: str, mode: str
    ) -> tuple[list[list[int]], list[list[int]]]:
        first_round_key = (
            round_keys[-1] if core_direction == "decrypt" else round_keys[0]
        )
        decoded = []
        for position in range(16):
            key_byte = first_round_key[position_order[position]]
            row = []
            for index in input_table_indices[position]:
                if mode == "identity":
                    value = index
                elif mode == "xor-key":
                    value = index ^ key_byte
                elif mode == "sbox":
                    value = _AesSBox[index]
                elif mode == "invsbox":
                    value = _AesInvSBox[index]
                elif mode == "sbox-xor-key":
                    value = _AesSBox[index] ^ key_byte
                elif mode == "invsbox-xor-key":
                    value = _AesInvSBox[index] ^ key_byte
                elif mode == "sbox-after-key":
                    value = _AesSBox[index ^ key_byte]
                elif mode == "invsbox-after-key":
                    value = _AesInvSBox[index ^ key_byte]
                else:
                    raise AssertionError(mode)
                row.append(value)
            decoded.append(row)
        return decoded, inverse_tables(decoded)

    def chosen_output_rows(
        position_order: tuple[int, ...],
        values: range,
        core_direction: str,
        logical_input_encode: list[list[int]],
    ) -> list[list[int]]:
        rows = [[] for _ in range(16)]
        for value in values:
            clear_output = bytes([value]) * 16
            inverse_direction = (
                "encrypt" if core_direction == "decrypt" else "decrypt"
            )
            internal_input = cipher_block(clear_output, inverse_direction)
            external_input = bytes(
                logical_input_encode[position][
                    internal_input[position_order[position]]
                ]
                for position in range(16)
            )
            external_output, _events = oracle.run(external_input)
            for position, item in enumerate(external_output):
                rows[position].append(item)
        return rows

    survivors = []
    for core_direction in ("decrypt", "encrypt"):
        for candidate in sorted(candidates):
            for input_mode in input_modes:
                _decoded, logical_encode = logical_input_tables(
                    candidate, core_direction, input_mode
                )
                rows = chosen_output_rows(
                    candidate, range(24), core_direction, logical_encode
                )
                if all(len(set(row)) == len(row) for row in rows):
                    survivors.append((core_direction, candidate, input_mode))

    complete = []
    for core_direction, candidate, input_mode in survivors:
        decoded, logical_encode = logical_input_tables(
            candidate, core_direction, input_mode
        )
        rows = chosen_output_rows(
            candidate, range(256), core_direction, logical_encode
        )
        if all(len(set(row)) == 256 for row in rows):
            complete.append(
                (core_direction, candidate, input_mode, decoded, rows)
            )
    if len(complete) != 1:
        raise ValueError(
            f"known-key mapping candidates={len(complete)} "
            f"(fast survivors={len(survivors)}, generated={len(candidates)})"
        )

    core_direction, input_order, input_mode, input_decode, output_encode = complete[0]
    input_encode = inverse_tables(input_decode)
    output_decode = inverse_tables(output_encode)

    mapping_cases = []
    for index in range(64):
        block = hashlib.sha256(
            b"macOS FairPlay output position mapping" + index.to_bytes(8, "big")
        ).digest()[:16]
        native, _events = oracle.run(block)
        external_clear = bytes(
            input_decode[position][value]
            for position, value in enumerate(block)
        )
        internal_input = bytearray(16)
        for position, value in enumerate(external_clear):
            internal_input[input_order[position]] = value
        core_output = cipher_block(bytes(internal_input), core_direction)
        decoded_output = bytes(
            output_decode[position][value]
            for position, value in enumerate(native)
        )
        mapping_cases.append((core_output, decoded_output))

    output_order = []
    for external_position in range(16):
        matches = [
            internal_position
            for internal_position in range(16)
            if all(
                decoded[external_position] == core[internal_position]
                for core, decoded in mapping_cases
            )
        ]
        if len(matches) != 1:
            raise ValueError(
                f"output position {external_position} candidates={matches}"
            )
        output_order.append(matches[0])
    if sorted(output_order) != list(range(16)):
        raise ValueError("recovered output position order is not a permutation")

    validation_hashes = []
    for index in range(validation_cases):
        block = hashlib.sha256(
            b"macOS FairPlay known-key validation" + index.to_bytes(8, "big")
        ).digest()[:16]
        native, _events = oracle.run(block)
        external_clear = bytes(
            input_decode[position][value]
            for position, value in enumerate(block)
        )
        internal_input = bytearray(16)
        for position, value in enumerate(external_clear):
            internal_input[input_order[position]] = value
        clear_output = cipher_block(bytes(internal_input), core_direction)
        portable = bytes(
            output_encode[position][clear_output[output_order[position]]]
            for position in range(16)
        )
        if native != portable:
            raise ValueError(f"known-key validation failed at case {index}")
        validation_hashes.append(digest(native))

    return {
        "key_sha256": digest(key),
        "direction": core_direction,
        "input_mode": input_mode,
        "input_position_order": list(input_order),
        "output_position_order": output_order,
        "input_table_bases": [hex(value) for value in table_bases],
        "input_decode": input_decode,
        "input_encode": input_encode,
        "output_decode": output_decode,
        "output_encode": output_encode,
        "validation_cases": validation_cases,
        "validation_digest_sha256": digest(
            "".join(validation_hashes).encode()
        ),
    }


class CheckpointBlockOracle:
    def __init__(
        self,
        checkpoint_path: Path,
        *,
        entry: int = ENTRY,
        block: int = BLOCK,
        result_block: int | None = None,
        stop_address: int | None = None,
        stop_hit: int = 2,
        instruction_limit: int = 2_000_000,
        emulate_all_eor3: bool = False,
        runtime_registers: dict[int, dict[str, int]] | None = None,
        output_permutation: list[int] | tuple[int, ...] | None = None,
        capture_read_ranges: list[tuple[int, int]] | None = None,
    ) -> None:
        with gzip.open(checkpoint_path, "rb") as stream:
            checkpoint = pickle.load(stream)
        memory_pages = checkpoint_memory_pages(checkpoint)
        if int(checkpoint["pc"], 16) != entry:
            raise ValueError(f"checkpoint PC is not {entry:#x}")

        self.entry = entry
        self.block = block
        self.result_block = block if result_block is None else result_block
        self.stop_address = entry if stop_address is None else stop_address
        self.stop_hit = stop_hit
        self.instruction_limit = instruction_limit
        self.runtime_registers = {
            int(address): {
                str(register): int(value)
                for register, value in writes.items()
            }
            for address, writes in (runtime_registers or {}).items()
        }
        self.output_permutation = tuple(
            range(16) if output_permutation is None else output_permutation
        )
        if sorted(self.output_permutation) != list(range(16)):
            raise ValueError("output permutation must contain 0..15 exactly once")
        self.capture_read_ranges = tuple(capture_read_ranges or ())
        if any(start < 0 or end <= start for start, end in self.capture_read_ranges):
            raise ValueError("capture read ranges must be nonempty and ordered")

        binary = Path(checkpoint["binary"])
        if digest(binary.read_bytes()) != checkpoint["binary_sha256"]:
            raise ValueError("checkpoint binary hash mismatch")
        fixups, self.external_names = dyld_info_fixups(binary)
        self.database = RawMachODatabase(binary, fixups=fixups)
        self.emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.image_start = page_down(self.database.minimum_ea)
        self.image_end = page_up(self.database.maximum_ea)
        self.emulator.mem_map(
            self.image_start,
            self.image_end - self.image_start,
            UC_PROT_ALL,
        )
        for segment in self.database.segments:
            if not segment.filesize or segment.name == "__PAGEZERO":
                continue
            data = self.database.image[
                segment.fileoff : segment.fileoff + segment.filesize
            ]
            self.emulator.mem_write(segment.vmaddr, data)
        for location, target in fixups.items():
            if self.image_start <= location <= self.image_end - 8:
                self.emulator.mem_write(
                    location,
                    (target & MASK64).to_bytes(8, "little"),
                )

        self.eor3_sites: dict[int, tuple[str, str, str, str]] = {}
        self.casal_sites: dict[int, tuple[str, str, str]] = {}
        patch_pointer_authentication(
            self.emulator,
            self.database,
            {},
            self.eor3_sites,
            self.casal_sites,
            {},
            emulate_all_eor3,
            frozenset() if emulate_all_eor3 else KNOWN_EOR3_SITES_26A428,
            frozenset(),
            False,
            False,
        )
        map_checkpoint_memory(
            self.emulator,
            memory_pages,
            self.image_start,
            self.image_end,
        )
        for name, value in checkpoint["registers"].items():
            if (
                name == "sp"
                or (name.startswith("x") and name[1:].isdigit())
                or (name.startswith("v") and name[1:].isdigit())
            ):
                self.emulator.reg_write(
                    register_id(name),
                    value & ((1 << 128) - 1)
                    if name.startswith("v")
                    else value & MASK64,
                )
        nzcv = checkpoint["nzcv"]
        self.emulator.reg_write(
            arm64_const.UC_ARM64_REG_NZCV,
            ((nzcv["n"] & 1) << 31)
            | ((nzcv["z"] & 1) << 30)
            | ((nzcv["c"] & 1) << 29)
            | ((nzcv["v"] & 1) << 28),
        )

        self.base_context = self.emulator.context_save()
        self.dirty_pages: dict[int, bytes] = {}
        self.entry_hits = 0
        self.result: bytes | None = None
        self.capture_reads = False
        self.read_events: list[tuple[int, int, int]] = []
        self.all_read_events: list[tuple[int, int, int]] = []
        self.invalid_access: tuple[int, int, int, int] | None = None
        self.fault_site: FaultSite | None = None
        self.fault_value = 0
        self.fault_applied = False
        self.fault_restore: tuple[int, int, int] | None = None
        self.fault_site_hits = 0
        self.external_stubs: dict[int, str] = {}
        self.allocation_base = 0x710200000000
        self.allocation_cursor = self.allocation_base
        self.capture_index_registers: dict[int, tuple[str, int]] = {}
        self.captured_index_values: dict[tuple[int, str], set[int]] = {}

        self.emulator.hook_add(UC_HOOK_CODE, self._on_code)
        self.emulator.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
        self.emulator.hook_add(UC_HOOK_MEM_READ, self._on_read)
        self.emulator.hook_add(UC_HOOK_MEM_INVALID, self._on_invalid)
        for address, operands in self.eor3_sites.items():
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._on_eor3,
                user_data=operands,
                begin=address,
                end=address,
            )
        for address, operands in self.casal_sites.items():
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._on_casal,
                user_data=operands,
                begin=address,
                end=address,
            )

    def _on_code(self, uc: Uc, address: int, _size: int, _user: object) -> None:
        for register, value in self.runtime_registers.get(address, {}).items():
            uc.reg_write(register_id(register), value)
        capture = self.capture_index_registers.get(address)
        if capture is not None:
            name, register = capture
            value = uc.reg_read(register)
            if name.startswith("w"):
                value &= 0xFFFFFFFF
            self.captured_index_values.setdefault((address, name), set()).add(value)
        if self.fault_restore is not None and address == self.fault_restore[0]:
            _restore_pc, register, value = self.fault_restore
            uc.reg_write(register, value)
            self.fault_restore = None
        external = self.external_stubs.get(address)
        if external is not None:
            if external == "malloc":
                size = max(1, uc.reg_read(arm64_const.UC_ARM64_REG_X0))
                allocation_size = page_up(size)
                result = self.allocation_cursor
                self.allocation_cursor += allocation_size
                for page in range(result, result + allocation_size, PAGE_SIZE):
                    try:
                        self.emulator.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
                    except UcError:
                        pass
                uc.reg_write(arm64_const.UC_ARM64_REG_X0, result)
            elif external == "free":
                uc.reg_write(arm64_const.UC_ARM64_REG_X0, 0)
            elif external == "arc4random":
                # The protected transform only needs a deterministic, valid
                # 32-bit result while it constructs its transient state.
                uc.reg_write(arm64_const.UC_ARM64_REG_X0, 0x4A17C39D)
            elif external == "gettimeofday":
                destination = uc.reg_read(arm64_const.UC_ARM64_REG_X0)
                if destination:
                    uc.mem_write(
                        destination,
                        (1_700_000_000).to_bytes(8, "little") + bytes(8),
                    )
                uc.reg_write(arm64_const.UC_ARM64_REG_X0, 0)
            elif external in {
                "pthread_mutex_destroy",
                "pthread_mutex_init",
                "pthread_mutex_lock",
                "pthread_mutex_unlock",
                "pthread_rwlock_destroy",
                "pthread_rwlock_init",
                "pthread_rwlock_rdlock",
                "pthread_rwlock_unlock",
                "pthread_rwlock_wrlock",
            }:
                uc.reg_write(arm64_const.UC_ARM64_REG_X0, 0)
            else:
                raise RuntimeError(f"unsupported external stub {external}")
            return
        if address == self.stop_address:
            self.entry_hits += 1
            if self.entry_hits == self.stop_hit:
                raw_result = bytes(uc.mem_read(self.result_block, 16))
                self.result = bytes(
                    raw_result[index] for index in self.output_permutation
                )
                uc.emu_stop()
                return
        if (
            self.fault_site is not None
            and not self.fault_applied
        ):
            if (
                self.fault_site.after_pc is not None
                and address == self.fault_site.after_pc
            ):
                self.fault_site_hits += 1
                if self.fault_site_hits == self.fault_site.hit_target:
                    register = register_id(str(self.fault_site.after_register))
                    value = uc.reg_read(register)
                    uc.reg_write(
                        register,
                        value ^ (self.fault_value << self.fault_site.after_shift),
                    )
                    self.fault_applied = True
            elif (
                self.fault_site.after_pc is None
                and address == self.fault_site.pc
            ):
                self.fault_site_hits += 1
                if self.fault_site_hits == self.fault_site.hit_target:
                    selected_register = (
                        self.fault_site.pointer_register
                        if self.fault_site.pointer_register is not None
                        else self.fault_site.index_register
                    )
                    register = register_id(str(selected_register))
                    value = uc.reg_read(register)
                    if self.fault_site.pointer_register is not None:
                        table_bytes = self.fault_site.pointer_table_bytes
                        entry_bytes = self.fault_site.pointer_entry_bytes
                        table_base = value & ~(table_bytes - 1)
                        offset = value - table_base
                        if offset >= table_bytes or offset % entry_bytes:
                            raise RuntimeError(
                                f"pointer fault value {value:#x} is outside its table"
                            )
                        position = offset // entry_bytes
                        faulted_value = table_base + (
                            (position ^ self.fault_value)
                            * entry_bytes
                        )
                    else:
                        if str(self.fault_site.index_register).startswith("w"):
                            value &= 0xFFFFFFFF
                        domain = self.fault_site.index_domain
                        if domain is None:
                            faulted_value = value ^ self.fault_value
                        else:
                            try:
                                position = domain.index(value)
                            except ValueError as error:
                                raise RuntimeError(
                                    f"index value {value:#x} is outside the learned domain"
                                ) from error
                            faulted_value = domain[position ^ self.fault_value]
                    uc.reg_write(register, faulted_value)
                    self.fault_restore = (
                        (address + 4, register, value)
                        if self.fault_site.restore_register
                        else None
                    )
                    self.fault_applied = True

    def _on_write(
        self,
        uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        first = page_down(address)
        last = page_down(address + max(size - 1, 0))
        for page in range(first, last + PAGE_SIZE, PAGE_SIZE):
            if page not in self.dirty_pages:
                try:
                    self.dirty_pages[page] = bytes(uc.mem_read(page, PAGE_SIZE))
                except UcError:
                    # The invalid-memory hook owns writes whose destination
                    # page is not mapped yet.  Do not mask that result while
                    # attempting to snapshot a page which does not exist.
                    continue

    def _on_read(
        self,
        uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if (
            self.capture_reads
            and (
                self.image_start <= address < self.image_end
                or any(
                    address < end and address + size > start
                    for start, end in self.capture_read_ranges
                )
            )
        ):
            event = (
                uc.reg_read(arm64_const.UC_ARM64_REG_PC),
                address,
                size,
            )
            self.all_read_events.append(event)
            if size == 4:
                self.read_events.append(event)

    def _on_invalid(
        self,
        uc: Uc,
        access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED and address in self.external_names:
            symbol = self.external_names[address].lstrip("_")
            if symbol not in {
                "malloc",
                "free",
                "arc4random",
                "gettimeofday",
                "pthread_mutex_destroy",
                "pthread_mutex_init",
                "pthread_mutex_lock",
                "pthread_mutex_unlock",
                "pthread_rwlock_destroy",
                "pthread_rwlock_init",
                "pthread_rwlock_rdlock",
                "pthread_rwlock_unlock",
                "pthread_rwlock_wrlock",
            }:
                self.invalid_access = (
                    access,
                    address,
                    size,
                    uc.reg_read(arm64_const.UC_ARM64_REG_PC),
                )
                return False
            page = page_down(address)
            try:
                self.emulator.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
            except UcError:
                pass
            self.emulator.mem_write(address, RET_X30.to_bytes(4, "little"))
            self.external_stubs[address] = symbol
            return True
        if (
            (
                0x700000000000 <= address < 0x800000000000
                or address >= 0xF000000000000000
            )
            and access not in {UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT}
        ):
            page = page_down(address)
            try:
                self.emulator.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
            except UcError:
                pass
            return True
        self.invalid_access = (
            access,
            address,
            size,
            uc.reg_read(arm64_const.UC_ARM64_REG_PC),
        )
        return False

    def _on_eor3(
        self, uc: Uc, _address: int, _size: int, operands: object
    ) -> None:
        destination, left, middle, right = operands
        uc.reg_write(
            register_id(str(destination)),
            uc.reg_read(register_id(str(left)))
            ^ uc.reg_read(register_id(str(middle)))
            ^ uc.reg_read(register_id(str(right))),
        )

    def _on_casal(
        self, uc: Uc, _address: int, _size: int, operands: object
    ) -> None:
        expected_name, desired_name, base_name = operands
        address = uc.reg_read(register_id(str(base_name)))
        old = int.from_bytes(uc.mem_read(address, 4), "little")
        expected = uc.reg_read(register_id(str(expected_name))) & 0xFFFFFFFF
        if old == expected:
            desired = uc.reg_read(register_id(str(desired_name))) & 0xFFFFFFFF
            uc.mem_write(address, desired.to_bytes(4, "little"))
        uc.reg_write(register_id(str(expected_name)), old)

    def run(
        self,
        block: bytes | None,
        *,
        capture_reads: bool = False,
        fault_site: FaultSite | None = None,
        fault_value: int = 0,
        register_values: dict[str, int] | None = None,
    ) -> tuple[bytes, list[tuple[int, int, int]]]:
        if block is not None and len(block) != 16:
            raise ValueError("oracle block must contain 16 bytes")
        self.emulator.context_restore(self.base_context)
        if block is not None:
            self.emulator.mem_write(self.block, bytes(block))
        for name, value in (register_values or {}).items():
            self.emulator.reg_write(register_id(name), int(value) & MASK64)
        self.entry_hits = 0
        self.result = None
        self.capture_reads = capture_reads
        self.read_events.clear()
        self.all_read_events.clear()
        self.invalid_access = None
        self.fault_site = fault_site
        self.fault_value = fault_value
        self.fault_applied = False
        self.fault_restore = None
        self.fault_site_hits = 0
        self.allocation_cursor = self.allocation_base
        self.dirty_pages.clear()
        try:
            self.emulator.emu_start(
                self.entry,
                0,
                count=self.instruction_limit,
            )
        except UcError as error:
            if self.invalid_access is not None:
                access, address, size, pc = self.invalid_access
                raise RuntimeError(
                    "invalid Unicorn access "
                    f"kind={access} address={address:#x} size={size} pc={pc:#x}"
                ) from error
            raise
        finally:
            for page, data in self.dirty_pages.items():
                self.emulator.mem_write(page, data)
        if self.result is None:
            raise RuntimeError("protected block did not reach the next dispatch entry")
        if fault_site is not None and not self.fault_applied:
            raise RuntimeError(f"protected block did not reach fault site {fault_site.pc:#x}")
        return self.result, list(self.read_events)

    def indexed_fault_candidates(
        self, events: list[tuple[int, int, int]]
    ) -> tuple[list[FaultSite], list[FaultSite]]:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        index_sites = []
        after_sites = []
        seen: set[int] = set()
        for pc, _address, _size in reversed(events):
            if pc in seen:
                continue
            raw = self.database.bytes.get_dword_at(
                pc, allow_uninitialized=True
            ).to_bytes(4, "little")
            instruction = next(disassembler.disasm(raw, pc, count=1), None)
            if instruction is None or not instruction.operands:
                continue
            memory = next(
                (operand for operand in instruction.operands if operand.type == CS_OP_MEM),
                None,
            )
            if memory is None or memory.mem.index == ARM64_REG_INVALID:
                continue
            if instruction.operands[0].type == CS_OP_MEM:
                continue
            destination_register = disassembler.reg_name(
                instruction.operands[0].reg
            ).lower()
            index_sites.append(
                FaultSite(
                    round_index=-1,
                    byte_index=len(index_sites),
                    pc=pc,
                    index_register=disassembler.reg_name(memory.mem.index).lower(),
                )
            )
            for shift in (0, 8, 16, 24):
                after_sites.append(
                    FaultSite(
                        round_index=-1,
                        byte_index=len(after_sites),
                        pc=pc,
                        index_register=None,
                        after_pc=pc + 4,
                        after_register=destination_register,
                        after_shift=shift,
                    )
                )
            seen.add(pc)
        return index_sites, after_sites

    def learn_index_domains(
        self,
        sites: list[FaultSite],
        *,
        maximum_inputs: int = 20_000,
    ) -> dict[tuple[int, str], tuple[int, ...]]:
        specifications = {
            (site.pc, str(site.index_register))
            for site in sites
            if site.index_register is not None
        }
        self.capture_index_registers = {
            pc: (name, register_id(name)) for pc, name in specifications
        }
        self.captured_index_values = {key: set() for key in specifications}
        try:
            for index in range(maximum_inputs):
                block = hashlib.sha256(
                    b"macOS FairPlay encoded fault domain"
                    + index.to_bytes(8, "big")
                ).digest()[:16]
                self.run(block)
                if all(
                    len(values) == 256
                    for values in self.captured_index_values.values()
                ):
                    break
        finally:
            self.capture_index_registers = {}
        incomplete = {
            key: len(values)
            for key, values in self.captured_index_values.items()
            if len(values) != 256
        }
        if incomplete:
            raise RuntimeError(f"incomplete encoded index domains: {incomplete}")
        return {
            key: tuple(sorted(values))
            for key, values in self.captured_index_values.items()
        }

    def fault_sites(
        self,
        events: list[tuple[int, int, int]],
        start: int = 3,
    ) -> list[list[FaultSite]]:
        # Most protected blocks place a small input-decoding prefix before the
        # nine groups of sixteen AES table reads.  That prefix is build- and
        # call-site-specific, so callers may provide the first round event.
        selected = events[start : start + 9 * 16]
        if len(selected) != 9 * 16:
            raise ValueError("protected block lacks nine complete table rounds")
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        sites = []
        selected_pcs: set[int] = set()
        for index, (pc, _address, size) in enumerate(selected):
            if size != 4:
                raise ValueError("fault candidate is not a dword table read")
            raw = self.database.bytes.get_dword_at(
                pc, allow_uninitialized=True
            ).to_bytes(4, "little")
            instruction = next(disassembler.disasm(raw, pc, count=1))
            memory = next(
                operand for operand in instruction.operands if operand.type == CS_OP_MEM
            )
            if memory.mem.index == ARM64_REG_INVALID:
                raise ValueError(f"fault candidate {pc:#x} has no index register")
            destination_register = disassembler.reg_name(
                instruction.operands[0].reg
            ).lower()
            sites.append(
                FaultSite(
                    round_index=index // 16,
                    byte_index=index % 16,
                    pc=pc,
                    index_register=disassembler.reg_name(memory.mem.index).lower(),
                )
            )
            for shift in (0, 8, 16, 24):
                sites.append(
                    FaultSite(
                        round_index=index // 16,
                        byte_index=index % 16,
                        pc=pc,
                        index_register=None,
                        after_pc=pc + 4,
                        after_register=destination_register,
                        after_shift=shift,
                    )
                )
            selected_pcs.add(pc)
        groups = [sites[offset : offset + 80] for offset in range(0, len(sites), 80)]
        extras = []
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        for pc, _address, size in events:
            if pc in selected_pcs or size != 4:
                continue
            raw = self.database.bytes.get_dword_at(
                pc, allow_uninitialized=True
            ).to_bytes(4, "little")
            instruction = next(disassembler.disasm(raw, pc, count=1), None)
            if instruction is None:
                continue
            memory = next(
                (operand for operand in instruction.operands if operand.type == CS_OP_MEM),
                None,
            )
            if memory is None or memory.mem.index == ARM64_REG_INVALID:
                continue
            destination_register = disassembler.reg_name(
                instruction.operands[0].reg
            ).lower()
            extras.append(
                FaultSite(
                    round_index=9,
                    byte_index=len(extras),
                    pc=pc,
                    index_register=disassembler.reg_name(memory.mem.index).lower(),
                )
            )
            for shift in (0, 8, 16, 24):
                extras.append(
                    FaultSite(
                        round_index=9,
                        byte_index=len(extras),
                        pc=pc,
                        index_register=None,
                        after_pc=pc + 4,
                        after_register=destination_register,
                        after_shift=shift,
                    )
                )
            selected_pcs.add(pc)
        if extras:
            groups.append(extras)
        return groups

    def repeated_round_fault_sites(
        self,
        events: list[tuple[int, int, int]],
        start_pc: int,
        rounds: int = 9,
    ) -> list[list[FaultSite]]:
        """Recover repeated 16-table AES rounds from one shared code body."""

        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        starts = [index for index, event in enumerate(events) if event[0] == start_pc]
        if len(starts) != rounds:
            raise ValueError(
                f"expected {rounds} repeated rounds at {start_pc:#x}, "
                f"observed {len(starts)}"
            )
        result: list[list[FaultSite]] = []
        selected_pcs: set[int] = set()
        for round_index, begin in enumerate(starts):
            end = starts[round_index + 1] if round_index + 1 < len(starts) else len(events)
            group: list[FaultSite] = []
            for pc, _address, size in events[begin:end]:
                if size != 4:
                    continue
                raw = self.database.bytes.get_dword_at(
                    pc, allow_uninitialized=True
                ).to_bytes(4, "little")
                instruction = next(disassembler.disasm(raw, pc, count=1), None)
                if instruction is None or not instruction.operands:
                    continue
                memory = next(
                    (
                        operand
                        for operand in instruction.operands
                        if operand.type == CS_OP_MEM
                    ),
                    None,
                )
                if (
                    memory is None
                    or memory.mem.index == ARM64_REG_INVALID
                    or instruction.operands[0].type == CS_OP_MEM
                ):
                    continue
                destination_register = disassembler.reg_name(
                    instruction.operands[0].reg
                ).lower()
                byte_index = len(group) // 5
                group.append(
                    FaultSite(
                        round_index=round_index,
                        byte_index=byte_index,
                        pc=pc,
                        index_register=disassembler.reg_name(
                            memory.mem.index
                        ).lower(),
                    )
                )
                for shift in (0, 8, 16, 24):
                    group.append(
                        FaultSite(
                            round_index=round_index,
                            byte_index=byte_index,
                            pc=pc,
                            index_register=None,
                            after_pc=pc + 4,
                            after_register=destination_register,
                            after_shift=shift,
                        )
                    )
                selected_pcs.add(pc)
                if len(group) == 16 * 5:
                    break
            if len(group) != 16 * 5:
                raise ValueError(
                    f"round {round_index} has {len(group) // 5} indexed tables"
                )
            result.append(group)

        extras: list[FaultSite] = []
        for pc, _address, size in events[starts[-1] :]:
            if pc in selected_pcs or size != 4:
                continue
            raw = self.database.bytes.get_dword_at(
                pc, allow_uninitialized=True
            ).to_bytes(4, "little")
            instruction = next(disassembler.disasm(raw, pc, count=1), None)
            if instruction is None or not instruction.operands:
                continue
            memory = next(
                (
                    operand
                    for operand in instruction.operands
                    if operand.type == CS_OP_MEM
                ),
                None,
            )
            if (
                memory is None
                or memory.mem.index == ARM64_REG_INVALID
                or instruction.operands[0].type == CS_OP_MEM
            ):
                continue
            destination_register = disassembler.reg_name(
                instruction.operands[0].reg
            ).lower()
            byte_index = len(extras) // 5
            extras.append(
                FaultSite(
                    round_index=rounds,
                    byte_index=byte_index,
                    pc=pc,
                    index_register=disassembler.reg_name(
                        memory.mem.index
                    ).lower(),
                )
            )
            for shift in (0, 8, 16, 24):
                extras.append(
                    FaultSite(
                        round_index=rounds,
                        byte_index=byte_index,
                        pc=pc,
                        index_register=None,
                        after_pc=pc + 4,
                        after_register=destination_register,
                        after_shift=shift,
                    )
                )
        if extras:
            result.append(extras)
        return result


_PROCESS_ORACLE: CheckpointBlockOracle | None = None


def _initialize_process_oracle(
    checkpoint: str,
    options: dict[str, object],
) -> None:
    """Create one independent Unicorn oracle inside a process worker."""

    global _PROCESS_ORACLE
    _PROCESS_ORACLE = CheckpointBlockOracle(Path(checkpoint), **options)


def _evaluate_process_chunk(
    indexed: list[tuple[int, tuple[bytes, FaultSite | None, int]]],
) -> list[tuple[int, bytes]]:
    """Evaluate one ordered job chunk using the worker-local oracle."""

    if _PROCESS_ORACLE is None:
        raise RuntimeError("process-local FairPlay oracle is not initialized")
    result = []
    for index, (data, site, xor_value) in indexed:
        value, _events = _PROCESS_ORACLE.run(
            data,
            fault_site=site,
            fault_value=xor_value,
        )
        result.append((index, value))
    return result


class MacFairPlayWhiteBox(WhiteBoxedAESDynamic):
    """DarkPhoenix-compatible persistent oracle for the checkpoint block."""

    lastRoundHasMC = False

    def __init__(
        self,
        checkpoint: str = "/private/path/whitebox-entry.checkpoint.pkl.gz",
        encrypt: bool = True,
        workers: int = 1,
        entry: int = ENTRY,
        block: int = BLOCK,
        result_block: int | None = None,
        stop_address: int | None = None,
        stop_hit: int = 2,
        instruction_limit: int = 2_000_000,
        round_start_pc: int | None = None,
        semantic_round_pc: int | None = None,
        semantic_round_pcs: dict[str, int] | None = None,
        semantic_round_hits: dict[str, int] | None = None,
        semantic_round_hit: int = 1,
        semantic_registers: list[str] | None = None,
        semantic_lanes: list[str] | None = None,
        semantic_site_pcs: list[int] | None = None,
        semantic_index_pcs: list[int] | None = None,
        semantic_index_pcs_by_round: dict[str, list[int]] | None = None,
        round_event_offset: int = 3,
        exhaustive_site_validation: bool = True,
        process_workers: bool = False,
        emulate_all_eor3: bool = False,
        runtime_registers: dict[int, dict[str, int]] | None = None,
        output_permutation: list[int] | tuple[int, ...] | None = None,
        capture_read_ranges: list[tuple[int, int]] | None = None,
    ) -> None:
        checkpoint_path = Path(checkpoint)
        oracle_options = {
            "entry": int(entry),
            "block": int(block),
            "result_block": (
                None if result_block is None else int(result_block)
            ),
            "stop_address": (
                None if stop_address is None else int(stop_address)
            ),
            "stop_hit": int(stop_hit),
            "instruction_limit": int(instruction_limit),
            "emulate_all_eor3": bool(emulate_all_eor3),
            "runtime_registers": runtime_registers,
            "output_permutation": output_permutation,
            "capture_read_ranges": capture_read_ranges,
        }
        self.oracle = CheckpointBlockOracle(
            checkpoint_path,
            **oracle_options,
        )
        self.encrypt = bool(encrypt)
        template = bytes(
            self.oracle.emulator.mem_read(self.oracle.block, 16)
        )
        _output, events = self.oracle.run(template, capture_reads=True)
        round_events = events
        if capture_read_ranges:
            # Current 26B builds construct their enrollment-bound T-tables in
            # heap memory.  Keep image-resident scalar loads available to the
            # general candidate scanner, but exclude them when partitioning
            # the exact 16-read AES round groups.
            round_events = [
                event
                for event in events
                if any(
                    event[1] < end and event[1] + event[2] > start
                    for start, end in capture_read_ranges
                )
            ]
        if round_start_pc is None:
            try:
                self.sites = self.oracle.fault_sites(
                    round_events,
                    start=int(round_event_offset),
                )
            except ValueError:
                # Some protected implementations are fully unrolled and mix
                # indexed with non-indexed reads at the same inferred round
                # boundary.  Dynamic fault-site discovery below does not use
                # this legacy grouping, so keep initialization available and
                # let prepareFaultPosition select validated semantic sites.
                self.sites = [[] for _ in range(9)]
        else:
            self.sites = self.oracle.repeated_round_fault_sites(
                round_events,
                int(round_start_pc),
            )
        self.index_sites, self.after_sites = self.oracle.indexed_fault_candidates(
            self.oracle.all_read_events
        )
        self.semantic_round_pc = (
            None if semantic_round_pc is None else int(semantic_round_pc)
        )
        self.semantic_round_pcs = {
            int(round_index, 0): int(pc)
            for round_index, pc in (semantic_round_pcs or {}).items()
        }
        self.semantic_round_hits = {
            int(round_index, 0): int(hit)
            for round_index, hit in (semantic_round_hits or {}).items()
        }
        self.semantic_registers = tuple(
            semantic_registers
            if semantic_registers is not None
            else ("w10", "w12", "w1", "w0")
        )
        self.semantic_lanes = tuple(semantic_lanes or ())
        self.semantic_site_pcs = tuple(int(pc) for pc in (semantic_site_pcs or ()))
        self.semantic_index_pcs = tuple(
            int(pc) for pc in (semantic_index_pcs or ())
        )
        self.semantic_index_pcs_by_round = {
            int(round_index, 0): tuple(int(pc) for pc in pcs)
            for round_index, pcs in (semantic_index_pcs_by_round or {}).items()
        }
        self.semantic_round_hit_offset = int(semantic_round_hit) - 8
        self.exhaustive_site_validation = bool(exhaustive_site_validation)
        self.selected: dict[tuple[int, int], FaultSite] = {}
        self.attempts: dict[tuple[int, int], int] = {}
        self.output_cache: dict[bytes, bytes] = {}
        self.workers = max(1, int(workers))
        self.process_workers = bool(process_workers and self.workers > 1)
        self.worker_oracles = [self.oracle]
        if self.process_workers:
            self.executor = ProcessPoolExecutor(
                max_workers=self.workers,
                initializer=_initialize_process_oracle,
                initargs=(str(checkpoint_path), oracle_options),
            )
        elif self.workers > 1:
            def make_worker(_index: int) -> CheckpointBlockOracle:
                return CheckpointBlockOracle(
                    checkpoint_path,
                    **oracle_options,
                )

            with ThreadPoolExecutor(max_workers=self.workers - 1) as executor:
                self.worker_oracles.extend(
                    executor.map(make_worker, range(self.workers - 1))
                )
            self.executor = ThreadPoolExecutor(max_workers=self.workers)
        else:
            self.executor = None

    def getRoundNumber(self) -> int:
        return 10

    def isEncrypt(self) -> bool:
        return self.encrypt

    def hasReverse(self) -> bool:
        return False

    def getRandomInput(self, index: int = 0) -> bytes:
        return hashlib.sha256(
            b"macOS FairPlay DarkPhoenix input" + index.to_bytes(8, "big")
        ).digest()[:16]

    def changeFaultPosition(self, fround: int, fbytes: int) -> None:
        key = (fround, fbytes)
        attempt = self.attempts.get(key, 0)
        # The repeated protected groups are AES rounds 1..9 (zero-indexed
        # groups 0..8).  DarkPhoenix's round-8 faults therefore belong in the
        # ninth repeated group directly.  Index faults are restored after the
        # single table lookup so they cannot leak into later state registers.
        protected_round = max(0, fround)
        choices = self.sites[protected_round]
        self.selected[key] = choices[(fbytes + attempt) % len(choices)]
        self.attempts[key] = attempt + 1

    def removeFaultPosition(self, fround: int, fbytes: int) -> None:
        self.selected.pop((fround, fbytes), None)

    def prepareFaultPosition(
        self,
        fround: int,
        reverseRoundMethod,
        reverseRoundMethod2=None,
    ) -> None:
        if all((fround, index) in self.selected for index in range(16)):
            return
        protected_round = max(0, fround)
        inputs = [self.getRandomInput(index) for index in range(4)]
        ordinary = {
            data: reverseRoundMethod(self.apply(data)) for data in inputs
        }
        ordinary2 = (
            {data: reverseRoundMethod2(self.apply(data)) for data in inputs}
            if reverseRoundMethod2 is not None
            else None
        )
        columns = {
            (0, 1, 2, 3),
            (4, 5, 6, 7),
            (8, 9, 10, 11),
            (12, 13, 14, 15),
        }
        selected_by_column: dict[tuple[int, ...], list[FaultSite]] = {
            column: [] for column in columns
        }
        tested = 0
        selected_kind: dict[FaultSite, str] = {}
        semantic_after_sites: list[FaultSite] = []
        explicit_after_sites: list[FaultSite] = []
        explicit_index_sites: list[FaultSite] = []
        selected_semantic_index_pcs = self.semantic_index_pcs_by_round.get(
            fround, self.semantic_index_pcs
        )
        if selected_semantic_index_pcs:
            disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            disassembler.detail = True
            for pc in selected_semantic_index_pcs:
                raw = self.oracle.database.bytes.get_dword_at(
                    pc, allow_uninitialized=True
                ).to_bytes(4, "little")
                instruction = next(disassembler.disasm(raw, pc, count=1), None)
                memory = (
                    next(
                        (
                            operand
                            for operand in instruction.operands
                            if operand.type == CS_OP_MEM
                        ),
                        None,
                    )
                    if instruction is not None
                    else None
                )
                if memory is None:
                    raise RuntimeError(
                        f"explicit index site {pc:#x} has no memory operand"
                    )
                if memory.mem.index != ARM64_REG_INVALID:
                    index_name = disassembler.reg_name(
                        memory.mem.index
                    ).lower()
                    destination_name = (
                        disassembler.reg_name(
                            instruction.operands[0].reg
                        ).lower()
                        if instruction.operands[0].type == CS_OP_REG
                        else ""
                    )
                    explicit_index_sites.append(
                        FaultSite(
                            round_index=fround,
                            byte_index=len(explicit_index_sites),
                            pc=pc,
                            index_register=index_name,
                            restore_register=(
                                destination_name[1:] != index_name[1:]
                            ),
                        )
                    )
                else:
                    pointer_name = disassembler.reg_name(
                        memory.mem.base
                    ).lower()
                    destination_name = (
                        disassembler.reg_name(
                            instruction.operands[0].reg
                        ).lower()
                        if instruction.operands[0].type == CS_OP_REG
                        else ""
                    )
                    explicit_index_sites.append(
                        FaultSite(
                            round_index=fround,
                            byte_index=len(explicit_index_sites),
                            pc=pc,
                            index_register=None,
                            pointer_register=pointer_name,
                            restore_register=(
                                destination_name[1:] != pointer_name[1:]
                            ),
                        )
                    )
        if self.semantic_site_pcs:
            disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            disassembler.detail = True
            for pc in self.semantic_site_pcs:
                raw = self.oracle.database.bytes.get_dword_at(
                    pc, allow_uninitialized=True
                ).to_bytes(4, "little")
                instruction = next(disassembler.disasm(raw, pc, count=1), None)
                if (
                    instruction is None
                    or not instruction.operands
                    or instruction.operands[0].type != CS_OP_REG
                ):
                    raise RuntimeError(
                        f"explicit semantic site {pc:#x} has no register result"
                    )
                destination_register = disassembler.reg_name(
                    instruction.operands[0].reg
                ).lower()
                for shift in (0, 8, 16, 24):
                    explicit_after_sites.append(
                        FaultSite(
                            round_index=fround,
                            byte_index=len(explicit_after_sites),
                            pc=pc,
                            index_register=None,
                            after_pc=pc + 4,
                            after_register=destination_register,
                            after_shift=shift,
                        )
                    )
        semantic_round_pc = self.semantic_round_pcs.get(
            fround, self.semantic_round_pc
        )
        semantic_hit = self.semantic_round_hits.get(
            fround,
            (
                1
                if fround in self.semantic_round_pcs
                else fround + self.semantic_round_hit_offset
            ),
        )
        if semantic_round_pc is not None and semantic_hit > 0:
            lanes = (
                [
                    (value.rsplit(":", 1)[0], int(value.rsplit(":", 1)[1], 0))
                    for value in self.semantic_lanes
                ]
                if self.semantic_lanes
                else [
                    (register, shift)
                    for register in self.semantic_registers
                    for shift in (0, 8, 16, 24)
                ]
            )
            for register, shift in lanes:
                semantic_after_sites.append(
                    FaultSite(
                        round_index=fround,
                        byte_index=len(semantic_after_sites),
                        pc=semantic_round_pc,
                        index_register=None,
                        after_pc=semantic_round_pc,
                        after_register=register,
                        after_shift=shift,
                        hit_target=semantic_hit,
                    )
                )
        # Prefer true table-index substitutions.  They preserve the protected
        # byte encoding for every XOR value and therefore satisfy Tolhuizen's
        # algebra.  Post-load byte lanes are tested only if a build-specific
        # table site is otherwise unreachable.
        preferred = (
            self.sites[protected_round]
            if protected_round < len(self.sites)
            else []
        )
        seen_candidates: set[tuple[object, ...]] = set()
        for kind, candidates in (
            ("pointer-index", explicit_index_sites),
            ("after", explicit_after_sites),
            ("after", semantic_after_sites),
            (
                "index",
                [site for site in preferred if site.index_register is not None],
            ),
            (
                "after",
                [site for site in preferred if site.index_register is None],
            ),
            ("index", self.index_sites),
            ("after", self.after_sites),
        ):
            for site in candidates:
                identity = (
                    site.pc,
                    site.index_register,
                    site.after_pc,
                    site.after_register,
                    site.after_shift,
                    site.hit_target,
                )
                if identity in seen_candidates:
                    continue
                seen_candidates.add(identity)
                expected = None
                valid = True
                for data in inputs:
                    for xor_value in (1, 2, 0x80, 0xFF):
                        try:
                            raw, _events = self.oracle.run(
                                data,
                                fault_site=site,
                                fault_value=xor_value,
                            )
                        except (RuntimeError, UcError):
                            valid = False
                            break
                        faulted = reverseRoundMethod(raw)
                        positions = tuple(
                            index
                            for index, (left, right) in enumerate(
                                zip(ordinary[data], faulted)
                            )
                            if left != right
                        )
                        if positions not in columns:
                            valid = False
                            break
                        if expected is None:
                            expected = positions
                        elif positions != expected:
                            valid = False
                            break
                        if ordinary2 is not None:
                            faulted2 = reverseRoundMethod2(raw)
                            if not all(
                                left != right
                                for left, right in zip(ordinary2[data], faulted2)
                            ):
                                valid = False
                                break
                    if not valid:
                        break
                tested += 1
                if (
                    valid
                    and expected is not None
                    and kind == "after"
                    and self.exhaustive_site_validation
                ):
                    for data in inputs:
                        seen_outputs: set[bytes] = set()
                        for xor_value in range(1, 256):
                            try:
                                raw, _events = self.oracle.run(
                                    data,
                                    fault_site=site,
                                    fault_value=xor_value,
                                )
                            except (RuntimeError, UcError):
                                valid = False
                                break
                            faulted = reverseRoundMethod(raw)
                            positions = tuple(
                                index
                                for index, (left, right) in enumerate(
                                    zip(ordinary[data], faulted)
                                )
                                if left != right
                            )
                            if positions != expected:
                                valid = False
                                break
                            short = bytes(
                                faulted[position] for position in expected
                            )
                            if short in seen_outputs:
                                valid = False
                                break
                            seen_outputs.add(short)
                        if not valid or len(seen_outputs) != 255:
                            valid = False
                            break
                if valid and expected is not None and len(selected_by_column[expected]) < 4:
                    selected_by_column[expected].append(site)
                    selected_kind[site] = kind
                if all(len(items) == 4 for items in selected_by_column.values()):
                    break
            if all(len(items) == 4 for items in selected_by_column.values()):
                break
        if not all(len(items) == 4 for items in selected_by_column.values()):
            counts = {
                str(column): len(items)
                for column, items in sorted(selected_by_column.items())
            }
            raise RuntimeError(
                f"failed to prepare semantic fault sites after {tested} candidates: {counts}"
            )
        from darkphoenixAES.AES import _AesInvShiftRow, _AesShiftRow

        position_map = _AesShiftRow if self.encrypt else _AesInvShiftRow
        indexed_sites: list[FaultSite | None] = [None] * 16
        for column in sorted(selected_by_column):
            column_index = column[0] // 4
            positions = position_map[column_index * 4 : column_index * 4 + 4]
            for position, site in zip(positions, selected_by_column[column]):
                indexed_sites[position] = site
        if any(site is None for site in indexed_sites):
            raise RuntimeError("semantic fault-site position map is incomplete")
        sites = [site for site in indexed_sites if site is not None]
        index_sites = [site for site in sites if site.index_register is not None]
        if index_sites:
            domains = self.oracle.learn_index_domains(index_sites)
            sites = [
                replace(
                    site,
                    index_domain=domains[(site.pc, str(site.index_register))],
                )
                if site.index_register is not None
                else site
                for site in sites
            ]
        for index, site in enumerate(sites):
            self.selected[(fround, index)] = site
        index_count = sum(
            site.index_register is not None or site.pointer_register is not None
            for site in sites
        )
        print(
            f"selected 16 semantic fault sites for round {fround} after {tested} candidates "
            f"(index={index_count} after={16-index_count})",
            flush=True,
        )
        for index, site in enumerate(sites):
            kind = (
                "pointer"
                if site.pointer_register is not None
                else "index"
                if site.index_register is not None
                else "after"
            )
            print(
                f"  semantic_site[{index}] kind={kind} "
                f"pc={site.pc:#x} index={site.index_register} "
                f"pointer={site.pointer_register} "
                f"after={site.after_pc!s}:{site.after_register!s}:{site.after_shift}",
                flush=True,
            )

    def apply(self, data: bytes) -> bytes:
        data = bytes(data)
        value = self.output_cache.get(data)
        if value is None:
            value, _events = self.oracle.run(data)
            self.output_cache[data] = value
        return value

    def applyFault(
        self, data: bytes, faults: list[tuple[int, int, int]]
    ) -> bytes:
        if len(faults) != 1:
            raise NotImplementedError("only one fault per invocation is supported")
        fround, fbytes, xor_value = faults[0]
        site = self.selected[(fround, fbytes)]
        value, _events = self.oracle.run(
            bytes(data), fault_site=site, fault_value=xor_value
        )
        return value

    def evalJobs(
        self, jobs: list[tuple[bytes, int, int, int]]
    ) -> list[bytes]:
        prepared = []
        for data, fround, fbytes, xor_value in jobs:
            site = None if fround == 0xFFFF else self.selected[(fround, fbytes)]
            prepared.append((bytes(data), site, xor_value))

        def evaluate_chunk(
            oracle: CheckpointBlockOracle,
            indexed: list[tuple[int, tuple[bytes, FaultSite | None, int]]],
        ) -> list[tuple[int, bytes]]:
            result = []
            for index, (data, site, xor_value) in indexed:
                value, _events = oracle.run(
                    data,
                    fault_site=site,
                    fault_value=xor_value,
                )
                result.append((index, value))
            return result

        if self.executor is None or len(prepared) < 2:
            return [
                value
                for _index, value in evaluate_chunk(
                    self.oracle, list(enumerate(prepared))
                )
            ]
        chunks = [
            []
            for _ in range(
                self.workers if self.process_workers else len(self.worker_oracles)
            )
        ]
        for item in enumerate(prepared):
            chunks[item[0] % len(chunks)].append(item)
        if self.process_workers:
            futures = [
                self.executor.submit(_evaluate_process_chunk, chunk)
                for chunk in chunks
                if chunk
            ]
        else:
            futures = [
                self.executor.submit(evaluate_chunk, oracle, chunk)
                for oracle, chunk in zip(self.worker_oracles, chunks)
                if chunk
            ]
        combined = [item for future in futures for item in future.result()]
        combined.sort(key=lambda item: item[0])
        return [value for _index, value in combined]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--entry", type=lambda value: int(value, 0), default=ENTRY)
    parser.add_argument("--block", type=lambda value: int(value, 0), default=BLOCK)
    parser.add_argument("--result-block", type=lambda value: int(value, 0))
    parser.add_argument("--stop-address", type=lambda value: int(value, 0))
    parser.add_argument("--stop-hit", type=int, default=2)
    parser.add_argument("--instruction-limit", type=int, default=2_000_000)
    parser.add_argument("--known-key", type=Path)
    parser.add_argument("--known-key-hex")
    parser.add_argument(
        "--known-key-model",
        type=Path,
        help="DarkPhoenix JSON model whose private key is used in memory",
    )
    parser.add_argument("--benchmark", type=int, default=100)
    parser.add_argument(
        "--capture-read-range",
        action="append",
        default=[],
        metavar="START:SIZE",
        help="also capture dword table reads intersecting this emulated range",
    )
    parser.add_argument("--recover-encodings", action="store_true")
    parser.add_argument("--validation-cases", type=int, default=256)
    parser.add_argument(
        "--runtime-profile",
        type=Path,
        help="JSON map of instruction addresses to register/value repairs",
    )
    parser.add_argument("--private-output", type=Path, required=True)
    args = parser.parse_args()

    started = time.monotonic()
    runtime_registers = None
    output_permutation = None
    if args.runtime_profile is not None:
        profile = json.loads(args.runtime_profile.read_text())
        runtime_registers = {
            int(address, 0): {
                register: int(value, 0) if isinstance(value, str) else int(value)
                for register, value in writes.items()
            }
            for address, writes in profile["runtime_registers"].items()
        }
        output_permutation = profile.get("output_permutation")
    capture_read_ranges = []
    for specification in args.capture_read_range:
        try:
            start_text, size_text = specification.split(":", 1)
            start, size = int(start_text, 0), int(size_text, 0)
        except ValueError:
            parser.error(
                f"invalid --capture-read-range {specification!r}; "
                "expected START:SIZE"
            )
        if start < 0 or size <= 0:
            parser.error("invalid capture read range")
        capture_read_ranges.append((start, start + size))
    oracle = CheckpointBlockOracle(
        args.checkpoint,
        entry=args.entry,
        block=args.block,
        result_block=args.result_block,
        stop_address=args.stop_address,
        stop_hit=args.stop_hit,
        instruction_limit=args.instruction_limit,
        runtime_registers=runtime_registers,
        output_permutation=output_permutation,
        capture_read_ranges=capture_read_ranges,
    )
    initialized = time.monotonic()
    with gzip.open(args.checkpoint, "rb") as stream:
        source_checkpoint = pickle.load(stream)
    baseline = checkpoint_memory_read(
        checkpoint_memory_pages(source_checkpoint), args.block, 16
    )
    output, baseline_events = oracle.run(baseline, capture_reads=True)
    dependency_events = []
    dependency_pcs = []
    for position in range(16):
        mutated = bytearray(baseline)
        mutated[position] ^= 1
        _value, events = oracle.run(bytes(mutated), capture_reads=True)
        if len(events) != len(baseline_events):
            raise ValueError("table-read event geometry changes with input")
        changed = [
            index
            for index, (left, right) in enumerate(zip(baseline_events, events))
            if left != right
        ]
        if not changed:
            raise ValueError(f"input byte {position} changes no table read")
        event_index = changed[0]
        dependency_events.append(event_index)
        dependency_pcs.append(baseline_events[event_index][0])

    bench_started = time.monotonic()
    bench_hashes = []
    for index in range(args.benchmark):
        block = hashlib.sha256(
            b"macOS fairplayd checkpoint whitebox" + index.to_bytes(8, "big")
        ).digest()[:16]
        value, _events = oracle.run(block)
        bench_hashes.append(digest(value))
    bench_elapsed = time.monotonic() - bench_started

    if sum(
        value is not None
        for value in (args.known_key, args.known_key_hex, args.known_key_model)
    ) > 1:
        parser.error("known-key options are mutually exclusive")
    known_key = (
        bytes.fromhex(args.known_key_hex)
        if args.known_key_hex
        else args.known_key.read_bytes()
        if args.known_key
        else bytes.fromhex(json.loads(args.known_key_model.read_text())["key_hex"])
        if args.known_key_model
        else None
    )
    recovery = None
    if args.recover_encodings:
        if known_key is None:
            parser.error("--recover-encodings requires --known-key")
        recovery = recover_known_key_encodings(
            oracle,
            baseline,
            baseline_events,
            dependency_events,
            dependency_pcs,
            known_key,
            args.validation_cases,
        )
    report = {
        "schema": "ipatool.macos-fairplay-checkpoint-whitebox-probe.v1",
        "checkpoint": str(args.checkpoint),
        "entry": hex(args.entry),
        "block": hex(args.block),
        "result_block": hex(
            args.block if args.result_block is None else args.result_block
        ),
        "stop_address": hex(
            args.entry if args.stop_address is None else args.stop_address
        ),
        "stop_hit": args.stop_hit,
        "baseline_input_sha256": digest(baseline),
        "baseline_output_sha256": digest(output),
        "table_read_events": len(baseline_events),
        "dependency_events": dependency_events,
        "dependency_pcs": [hex(value) for value in dependency_pcs],
        "unique_dependency_events": len(set(dependency_events)),
        "known_key_sha256": digest(known_key) if known_key else None,
        "known_key_recovery": recovery,
        "benchmark": {
            "calls": args.benchmark,
            "seconds": bench_elapsed,
            "calls_per_second": (
                args.benchmark / bench_elapsed if bench_elapsed else None
            ),
            "output_digest_sha256": digest("".join(bench_hashes).encode()),
        },
        "timing": {
            "initialization_seconds": initialized - started,
            "total_seconds": time.monotonic() - started,
        },
    }
    write_private(args.private_output, report)
    print(
        "macos_whitebox_probe=1 "
        f"table_reads={len(baseline_events)} "
        f"unique_dependencies={len(set(dependency_events))} "
        f"calls_per_second={report['benchmark']['calls_per_second']:.1f} "
        f"output={args.private_output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
