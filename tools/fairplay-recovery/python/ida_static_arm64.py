"""Small read-only AArch64 evaluator for IDA databases.

This is intentionally not a general CPU emulator.  It implements the straight-
line integer and memory instructions used by the obfuscated appstored/CoreFP
entry wrappers and stops at the first indirect branch or call.  Database bytes
are never patched: writes are kept in an in-memory overlay.

Load this file from IDAPython, then call ``resolve_first_indirect(db, ea)``.
"""

from __future__ import annotations

import re
import math
import struct
from collections import deque
from dataclasses import dataclass
from typing import Any

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64_const import *  # noqa: F403 - mirrors Capstone's operand API


MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def _mask(width: int) -> int:
    return (1 << width) - 1


def _sign_extend(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


@dataclass
class Stop:
    reason: str
    address: int
    mnemonic: str
    target: int | None
    modifier: int | None
    registers: dict[str, int]
    instructions: int


class Evaluator:
    """Evaluate a bounded AArch64 path against an IDA-domain database."""

    def __init__(
        self,
        db: Any,
        *,
        args: tuple[int, ...] = (),
        sp: int = 0x700000100000,
        chained_pointer_base: int | None = None,
        chained_pointer_format: str | None = None,
        memory_watch_ranges: tuple[tuple[int, int], ...] = (),
        memory_break_ranges: tuple[tuple[int, int], ...] = (),
        register_watch_names: tuple[str, ...] = (),
        profile_instructions: bool = False,
        recent_pc_limit: int = 0,
    ) -> None:
        self.db = db
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self.regs = {f"x{i}": 0 for i in range(31)}
        self.regs["sp"] = sp & MASK64
        self.chained_pointer_base = chained_pointer_base
        self.chained_pointer_format = chained_pointer_format
        self.memory_watch_ranges = memory_watch_ranges
        self.memory_break_ranges = memory_break_ranges
        self.memory_break_hit: dict[str, int | str] | None = None
        self.memory_accesses: list[dict[str, int | str]] = []
        self.register_watch_names = set(register_watch_names)
        self.profile_instructions = profile_instructions
        self.instruction_counts: dict[int, int] = {}
        self.recent_pcs: deque[int] | None = (
            deque(maxlen=recent_pc_limit) if recent_pc_limit else None
        )
        self.register_accesses: list[dict[str, int | str]] = []
        self.current_pc = 0
        self.stage: int | None = None
        self._db_value_cache: dict[tuple[int, int], int] = {}
        self._instruction_cache: dict[int, Any] = {}
        for index, value in enumerate(args[:8]):
            self.regs[f"x{index}"] = value & MASK64
        self.memory: dict[int, int] = {}
        self.nzcv = {"n": 0, "z": 0, "c": 0, "v": 0}

    def _reg_name(self, reg_id: int) -> str:
        name = self.md.reg_name(reg_id).lower()
        name = {"fp": "x29", "lr": "x30"}.get(name, name)
        if len(name) > 1 and name[0] == "q" and name[1:].isdigit():
            return f"v{name[1:]}"
        return name

    def _reg_width(self, name: str) -> int:
        if name.startswith("v"):
            return 128
        if len(name) > 1 and name[1:].isdigit():
            if name.startswith("d"):
                return 64
            if name.startswith("s"):
                return 32
            if name.startswith("h"):
                return 16
            if name.startswith("b"):
                return 8
        if name.startswith("w") or name == "wsp":
            return 32
        return 64

    def read_reg(self, reg_id: int) -> int:
        name = self._reg_name(reg_id)
        if name in ("xzr", "wzr"):
            return 0
        if name == "wsp":
            return self.regs["sp"] & MASK32
        if name.startswith("w") and name[1:].isdigit():
            return self.regs[f"x{name[1:]}"] & MASK32
        if len(name) > 1 and name[0] in "bhsd" and name[1:].isdigit():
            return self.regs.get(f"v{name[1:]}", 0) & _mask(self._reg_width(name))
        return self.regs.get(name, 0) & _mask(self._reg_width(name))

    def write_reg(self, reg_id: int, value: int) -> None:
        name = self._reg_name(reg_id)
        if name in ("xzr", "wzr"):
            return
        if name == "wsp":
            self.regs["sp"] = value & MASK32
            self._record_register_write("sp", name)
            return
        if name.startswith("w") and name[1:].isdigit():
            storage_name = f"x{name[1:]}"
            self.regs[storage_name] = value & MASK32
            self._record_register_write(storage_name, name)
            return
        if len(name) > 1 and name[0] in "bhsd" and name[1:].isdigit():
            # Scalar SIMD/FP writes clear the rest of the architectural vector
            # register.  Lane forms are exposed by Capstone as ``vN`` and do
            # not take this path.
            storage_name = f"v{name[1:]}"
            self.regs[storage_name] = value & _mask(self._reg_width(name))
            self._record_register_write(storage_name, name)
            return
        self.regs[name] = value & _mask(self._reg_width(name))
        self._record_register_write(name, name)

    def _record_register_write(self, storage_name: str, operand_name: str) -> None:
        if storage_name not in self.register_watch_names:
            return
        event: dict[str, int | str] = {
                "operation": "write",
                "pc": self.current_pc & MASK64,
                "register": storage_name,
                "operand": operand_name,
                "value": self.regs.get(storage_name, 0),
        }
        if self.stage is not None:
            event["stage"] = self.stage
        self.register_accesses.append(event)

    def _db_read(self, address: int, size: int) -> int:
        cache_key = (address, size)
        cached = self._db_value_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            if not all(
                self.db.bytes.is_value_initialized_at(address + offset)
                for offset in range(size)
            ):
                self._db_value_cache[cache_key] = 0
                return 0
        except Exception:
            self._db_value_cache[cache_key] = 0
            return 0
        methods = {
            1: self.db.bytes.get_byte_at,
            2: self.db.bytes.get_word_at,
            4: self.db.bytes.get_dword_at,
            8: self.db.bytes.get_qword_at,
        }
        try:
            value = methods[size](address, allow_uninitialized=True)
        except TypeError:
            try:
                value = methods[size](address)
            except Exception:
                self._db_value_cache[cache_key] = 0
                return 0
        except Exception:
            self._db_value_cache[cache_key] = 0
            return 0

        if size == 8 and hasattr(self.db, "resolve_pointer"):
            resolved = self.db.resolve_pointer(address, value)
            if resolved is not None:
                self._db_value_cache[cache_key] = resolved
                return resolved
            if getattr(self.db, "exact_pointer_fixups", False):
                self._db_value_cache[cache_key] = value
                return value

        # A fileset entry extracted from a macOS kernel collection retains
        # chained kernel pointers.  For the arm64e format encountered here the
        # low 32 bits are an offset from the collection base; the remaining
        # bits carry chain/authentication metadata.  Decode only when a base
        # was supplied explicitly and the candidate stays within the IDB's
        # overall address range.  Overlay values are deliberately not decoded.
        if size == 8 and self.chained_pointer_base is not None and value >> 32:
            if self.chained_pointer_format == "arm64e-userland":
                auth = (value >> 63) & 1
                bind = (value >> 62) & 1
                next_delta = (value >> 51) & 0x7FF
                if not bind and (auth or next_delta):
                    target_mask = MASK32 if auth else (1 << 43) - 1
                    candidate = (
                        self.chained_pointer_base + (value & target_mask)
                    ) & MASK64
                    # Protected userspace binaries deliberately add large
                    # positive chained-rebase targets to negative constants.
                    # The intermediate pointer may therefore lie outside all
                    # mapped segments; dyld still rebases it before the
                    # arithmetic. Do not require candidate validity here.
                    self._db_value_cache[cache_key] = candidate
                    return candidate
            else:
                candidate = (self.chained_pointer_base + (value & MASK32)) & MASK64
                if self.db.minimum_ea <= candidate < self.db.maximum_ea:
                    self._db_value_cache[cache_key] = candidate
                    return candidate
        self._db_value_cache[cache_key] = value
        return value

    def read_mem(self, address: int, size: int) -> int:
        address &= MASK64
        if size in (1, 2, 4, 8) and not any(
            address + offset in self.memory for offset in range(size)
        ):
            value = self._db_read(address, size) & ((1 << (8 * size)) - 1)
        else:
            value = 0
            for offset in range(size):
                byte = self.memory.get(address + offset)
                if byte is None:
                    byte = self._db_read(address + offset, 1)
                value |= (byte & 0xFF) << (8 * offset)
        self._record_memory_access("read", address, size, value)
        return value

    def write_mem(self, address: int, value: int, size: int) -> None:
        address &= MASK64
        for offset in range(size):
            self.memory[address + offset] = (value >> (8 * offset)) & 0xFF
        self._record_memory_access("write", address, size, value)

    def _record_memory_access(
        self,
        operation: str,
        address: int,
        size: int,
        value: int,
    ) -> None:
        if operation == "read":
            for start, end in self.memory_break_ranges:
                if address < end and address + size > start:
                    self.memory_break_hit = {
                        "operation": operation,
                        "pc": self.current_pc & MASK64,
                        "address": address & MASK64,
                        "size": size,
                        "value": value & ((1 << (8 * size)) - 1),
                    }
                    break
        for start, end in self.memory_watch_ranges:
            if address < end and address + size > start:
                event: dict[str, int | str] = {
                        "operation": operation,
                        "pc": self.current_pc & MASK64,
                        "address": address & MASK64,
                        "size": size,
                        "value": value & ((1 << (8 * size)) - 1),
                }
                if self.stage is not None:
                    event["stage"] = self.stage
                self.memory_accesses.append(event)
                break

    def _shift(self, value: int, shift_type: int, amount: int, width: int) -> int:
        value &= _mask(width)
        if not amount or shift_type == ARM64_SFT_INVALID:  # noqa: F405
            return value
        amount %= width
        if shift_type == ARM64_SFT_LSL:  # noqa: F405
            return (value << amount) & _mask(width)
        if shift_type == ARM64_SFT_LSR:  # noqa: F405
            return value >> amount
        if shift_type == ARM64_SFT_ASR:  # noqa: F405
            return (_sign_extend(value, width) >> amount) & _mask(width)
        if shift_type == ARM64_SFT_ROR:  # noqa: F405
            return ((value >> amount) | (value << (width - amount))) & _mask(width)
        raise NotImplementedError(f"shift type {shift_type}")

    def _modified_reg(self, operand: Any) -> int:
        value = self.read_reg(operand.reg)
        ext = operand.ext
        if ext == ARM64_EXT_UXTB:  # noqa: F405
            value &= 0xFF
        elif ext == ARM64_EXT_UXTH:  # noqa: F405
            value &= 0xFFFF
        elif ext == ARM64_EXT_UXTW:  # noqa: F405
            value &= MASK32
        elif ext == ARM64_EXT_UXTX:  # noqa: F405
            value &= MASK64
        elif ext == ARM64_EXT_SXTB:  # noqa: F405
            value = _sign_extend(value, 8) & MASK64
        elif ext == ARM64_EXT_SXTH:  # noqa: F405
            value = _sign_extend(value, 16) & MASK64
        elif ext == ARM64_EXT_SXTW:  # noqa: F405
            value = _sign_extend(value, 32) & MASK64
        elif ext == ARM64_EXT_SXTX:  # noqa: F405
            value = _sign_extend(value, 64) & MASK64
        width = self._reg_width(self._reg_name(operand.reg))
        if ext in (ARM64_EXT_UXTX, ARM64_EXT_SXTX, ARM64_EXT_SXTW):  # noqa: F405
            width = 64
        return self._shift(value, operand.shift.type, operand.shift.value, width)

    def operand_value(self, operand: Any) -> int:
        if operand.type == ARM64_OP_REG:  # noqa: F405
            return self._modified_reg(operand)
        if operand.type == ARM64_OP_IMM:  # noqa: F405
            value = operand.imm & MASK64
            return self._shift(value, operand.shift.type, operand.shift.value, 64)
        raise NotImplementedError(f"operand type {operand.type}")

    def memory_address(self, operand: Any) -> int:
        mem = operand.mem
        base = self.read_reg(mem.base) if mem.base else 0
        index = 0
        if mem.index:
            index_operand = type("IndexOperand", (), {})()
            index_operand.reg = mem.index
            index_operand.ext = operand.ext
            index_operand.shift = operand.shift
            index = self._modified_reg(index_operand)
        return (base + index + mem.disp) & MASK64

    def _set_sub_flags(self, left: int, right: int, result: int, width: int) -> None:
        mask = _mask(width)
        sign = 1 << (width - 1)
        left &= mask
        right &= mask
        result &= mask
        self.nzcv["n"] = int(bool(result & sign))
        self.nzcv["z"] = int(result == 0)
        self.nzcv["c"] = int(left >= right)
        self.nzcv["v"] = int(bool(((left ^ right) & (left ^ result) & sign)))

    def _set_add_flags(
        self,
        left: int,
        right: int,
        result: int,
        width: int,
        carry: int = 0,
    ) -> None:
        mask = _mask(width)
        sign = 1 << (width - 1)
        left_masked = left & mask
        right_masked = right & mask
        full = left_masked + right_masked + carry
        masked = result & mask
        self.nzcv["n"] = int(bool(masked & sign))
        self.nzcv["z"] = int(masked == 0)
        self.nzcv["c"] = int(full > mask)
        signed_sum = (
            _sign_extend(left_masked, width)
            + _sign_extend(right_masked, width)
            + carry
        )
        self.nzcv["v"] = int(
            signed_sum < -(1 << (width - 1))
            or signed_sum > (1 << (width - 1)) - 1
        )

    def _condition(self, cc: int) -> bool:
        n, z, c, v = (self.nzcv[k] for k in ("n", "z", "c", "v"))
        conditions = {
            ARM64_CC_EQ: z == 1,  # noqa: F405
            ARM64_CC_NE: z == 0,  # noqa: F405
            ARM64_CC_HS: c == 1,  # noqa: F405
            ARM64_CC_LO: c == 0,  # noqa: F405
            ARM64_CC_MI: n == 1,  # noqa: F405
            ARM64_CC_PL: n == 0,  # noqa: F405
            ARM64_CC_VS: v == 1,  # noqa: F405
            ARM64_CC_VC: v == 0,  # noqa: F405
            ARM64_CC_HI: c == 1 and z == 0,  # noqa: F405
            ARM64_CC_LS: c == 0 or z == 1,  # noqa: F405
            ARM64_CC_GE: n == v,  # noqa: F405
            ARM64_CC_LT: n != v,  # noqa: F405
            ARM64_CC_GT: z == 0 and n == v,  # noqa: F405
            ARM64_CC_LE: z == 1 or n != v,  # noqa: F405
            ARM64_CC_AL: True,  # noqa: F405
            ARM64_CC_NV: True,  # noqa: F405
        }
        return conditions.get(cc, False)

    def _load_store_size(self, mnemonic: str, reg_name: str) -> tuple[int, bool]:
        signed = mnemonic.startswith("ldrs")
        if reg_name.startswith("v"):
            return 16, signed
        if len(reg_name) > 1 and reg_name[0] in "bhsd" and reg_name[1:].isdigit():
            return self._reg_width(reg_name) // 8, signed
        if mnemonic.endswith("b") or mnemonic in ("ldrsb", "strb"):
            return 1, signed
        if mnemonic.endswith("h") or mnemonic in ("ldrsh", "strh"):
            return 2, signed
        if mnemonic in ("ldrsw", "ldursw"):
            return 4, True
        return (4 if reg_name.startswith("w") else 8), signed

    @staticmethod
    def _vector_lane_bits(instruction: Any) -> int:
        destination = instruction.op_str.split(",", 1)[0].strip()
        match = re.search(r"\.(?:\d+)?([bhsd])", destination)
        return {
            "b": 8,
            "h": 16,
            "s": 32,
            "d": 64,
        }.get(match.group(1) if match else "", 8)

    @staticmethod
    def _vector_arrangement(instruction: Any, operand_index: int) -> tuple[int, int]:
        operands = [part.strip() for part in instruction.op_str.split(",")]
        text = operands[operand_index] if operand_index < len(operands) else ""
        match = re.search(r"\.(\d+)([bhsd])", text)
        if not match:
            raise ValueError(f"missing vector arrangement in {instruction.op_str!r}")
        lane_bits = {"b": 8, "h": 16, "s": 32, "d": 64}[match.group(2)]
        return int(match.group(1)), lane_bits

    @staticmethod
    def _vector_operand_lane_bits(instruction: Any, operand_index: int) -> int:
        operands = [part.strip() for part in instruction.op_str.split(",")]
        text = operands[operand_index] if operand_index < len(operands) else ""
        match = re.search(r"\.(?:\d+)?([bhsd])", text)
        if not match:
            raise ValueError(f"missing vector lane type in {instruction.op_str!r}")
        return {"b": 8, "h": 16, "s": 32, "d": 64}[match.group(1)]

    @staticmethod
    def _map_vector_lanes(
        value: int,
        lane_bits: int,
        transform: Any,
        lane_count: int | None = None,
    ) -> int:
        lane_mask = _mask(lane_bits)
        result = 0
        if lane_count is None:
            lane_count = 128 // lane_bits
        for lane_index in range(lane_count):
            lane_offset = lane_index * lane_bits
            lane = (value >> lane_offset) & lane_mask
            result |= (transform(lane) & lane_mask) << lane_offset
        return result

    @staticmethod
    def _binary_vector_lanes(
        left: int,
        right: int,
        lane_count: int,
        lane_bits: int,
        operation: Any,
    ) -> int:
        lane_mask = _mask(lane_bits)
        result = 0
        for lane_index in range(lane_count):
            shift = lane_index * lane_bits
            left_lane = (left >> shift) & lane_mask
            right_lane = (right >> shift) & lane_mask
            result |= (operation(left_lane, right_lane) & lane_mask) << shift
        return result

    def _writeback(self, instruction: Any, mem_operand: Any, effective: int) -> None:
        if not instruction.writeback or not mem_operand.mem.base:
            return
        operands = instruction.operands
        post_imm = None
        if operands and operands[-1].type == ARM64_OP_IMM:  # noqa: F405
            post_imm = operands[-1].imm
        if post_imm is None:
            self.write_reg(mem_operand.mem.base, effective)
        else:
            base = self.read_reg(mem_operand.mem.base)
            self.write_reg(mem_operand.mem.base, base + post_imm)

    def snapshot(self) -> dict[str, int]:
        names = [f"x{i}" for i in range(31)] + ["sp"]
        return {name: self.regs.get(name, 0) & MASK64 for name in names}

    def run(
        self,
        start_ea: int,
        *,
        max_instructions: int = 1000,
        follow_internal_transfers: bool = False,
        breakpoints: frozenset[int] = frozenset(),
    ) -> Stop:
        pc = start_ea
        count = 0
        self.memory_break_hit = None
        while count < max_instructions:
            if count and pc in breakpoints:
                return Stop(
                    "breakpoint",
                    pc,
                    "",
                    pc,
                    None,
                    self.snapshot(),
                    count,
                )
            if self.recent_pcs is not None:
                self.recent_pcs.append(pc)
            self.current_pc = pc & MASK64
            if self.profile_instructions:
                self.instruction_counts[pc] = self.instruction_counts.get(pc, 0) + 1
            instruction = self._instruction_cache.get(pc)
            if instruction is None:
                raw = self.db.bytes.get_dword_at(pc, allow_uninitialized=True).to_bytes(4, "little")
                instruction = next(self.md.disasm(raw, pc, count=1), None)
                if instruction is not None:
                    self._instruction_cache[pc] = instruction
            if instruction is None:
                return Stop("decode-failure", pc, "", None, None, self.snapshot(), count)
            count += 1
            mnemonic = instruction.mnemonic.lower()
            operands = instruction.operands
            next_pc = pc + 4

            if mnemonic.startswith(("pac", "aut", "xpac")) or mnemonic in ("nop", "hint", "bti"):
                pass
            elif mnemonic in ("adr", "adrp"):
                self.write_reg(operands[0].reg, operands[1].imm)
            elif mnemonic == "mov" and any(
                getattr(operand, "vector_index", -1) is not None
                and getattr(operand, "vector_index", -1) >= 0
                for operand in operands[:2]
            ):
                destination_index = getattr(operands[0], "vector_index", -1)
                source_index = getattr(operands[1], "vector_index", -1)
                if (
                    destination_index is not None
                    and destination_index >= 0
                    and source_index is not None
                    and source_index >= 0
                ):
                    destination_lane_bits = self._vector_operand_lane_bits(
                        instruction, 0
                    )
                    source_lane_bits = self._vector_operand_lane_bits(
                        instruction, 1
                    )
                    if destination_lane_bits != source_lane_bits:
                        raise ValueError(
                            "MOV vector lane widths differ in "
                            f"{instruction.op_str!r}"
                        )
                    lane_mask = _mask(destination_lane_bits)
                    lane_value = (
                        self.read_reg(operands[1].reg)
                        >> (source_index * source_lane_bits)
                    ) & lane_mask
                    lane_shift = destination_index * destination_lane_bits
                    current = self.read_reg(operands[0].reg)
                    self.write_reg(
                        operands[0].reg,
                        (current & ~(lane_mask << lane_shift))
                        | (lane_value << lane_shift),
                    )
                elif source_index is not None and source_index >= 0:
                    lane_bits = self._vector_operand_lane_bits(instruction, 1)
                    value = self.read_reg(operands[1].reg) >> (
                        source_index * lane_bits
                    )
                    self.write_reg(operands[0].reg, value & _mask(lane_bits))
                elif destination_index is not None and destination_index >= 0:
                    lane_bits = self._vector_operand_lane_bits(instruction, 0)
                    lane_shift = destination_index * lane_bits
                    lane_mask = _mask(lane_bits) << lane_shift
                    current = self.read_reg(operands[0].reg)
                    value = self.operand_value(operands[1]) & _mask(lane_bits)
                    self.write_reg(
                        operands[0].reg,
                        (current & ~lane_mask) | (value << lane_shift),
                    )
                else:
                    self.write_reg(operands[0].reg, self.operand_value(operands[1]))
            elif mnemonic in ("mov", "movz"):
                self.write_reg(operands[0].reg, self.operand_value(operands[1]))
            elif mnemonic in ("movi", "mvni"):
                try:
                    lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                except ValueError:
                    # Capstone renders scalar AdvSIMD immediates as e.g.
                    # ``movi d1, #0xffffffff00000000`` without a lane
                    # arrangement.  In that form the immediate already
                    # describes the complete scalar register value.
                    lane_count = 1
                    lane_bits = self._reg_width(
                        self._reg_name(operands[0].reg)
                    )
                lane_mask = _mask(lane_bits)
                lane = self.operand_value(operands[1]) & lane_mask
                if mnemonic == "mvni":
                    lane = ~lane & lane_mask
                replicated = 0
                for lane_index in range(lane_count):
                    replicated |= lane << (lane_index * lane_bits)
                self.write_reg(operands[0].reg, replicated)
            elif mnemonic == "dup":
                # Capstone exposes the destination as a bare ``vN`` register;
                # recover the lane width from the printed arrangement (for
                # example ``v5.4s``).  CoreKE uses this scalar-to-vector form
                # while setting up operation 10.
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                lane_mask = _mask(lane_bits)
                value = self.operand_value(operands[1])
                vector_index = getattr(operands[1], "vector_index", -1)
                if vector_index is not None and vector_index >= 0:
                    value >>= vector_index * lane_bits
                lane = value & lane_mask
                replicated = 0
                for lane_index in range(lane_count):
                    replicated |= lane << (lane_index * lane_bits)
                self.write_reg(operands[0].reg, replicated)
            elif mnemonic == "fneg":
                destination = self._reg_name(operands[0].reg)
                if destination.startswith("v"):
                    lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                    sign_mask = 0
                    for lane_index in range(lane_count):
                        sign_mask |= 1 << (
                            lane_index * lane_bits + lane_bits - 1
                        )
                else:
                    width = self._reg_width(destination)
                    sign_mask = 1 << (width - 1)
                self.write_reg(
                    operands[0].reg,
                    self.operand_value(operands[1]) ^ sign_mask,
                )
            elif mnemonic == "fmov":
                # The obfuscated dispatcher uses FMOV as a bit-preserving
                # transfer between W/S and X/D register files, and some
                # protected paths also materialize an encoded FP immediate.
                if operands[1].type == ARM64_OP_FP:  # noqa: F405
                    width = self._reg_width(self._reg_name(operands[0].reg))
                    if width == 32:
                        value = int.from_bytes(
                            struct.pack("<f", operands[1].fp), "little"
                        )
                    elif width == 64:
                        value = int.from_bytes(
                            struct.pack("<d", operands[1].fp), "little"
                        )
                    else:
                        raise NotImplementedError(
                            f"FMOV immediate width {width}"
                        )
                else:
                    value = self.operand_value(operands[1])
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("ucvtf", "scvtf"):
                destination_name = self._reg_name(operands[0].reg)
                source_name = self._reg_name(operands[1].reg)
                source_width = self._reg_width(source_name)
                source = self.operand_value(operands[1]) & _mask(source_width)
                if mnemonic == "scvtf":
                    source = _sign_extend(source, source_width)
                fractional_bits = (
                    self.operand_value(operands[2]) if len(operands) > 2 else 0
                )
                converted = float(source) / float(1 << fractional_bits)
                destination_width = self._reg_width(destination_name)
                if destination_width == 32:
                    value = int.from_bytes(struct.pack("<f", converted), "little")
                elif destination_width == 64:
                    value = int.from_bytes(struct.pack("<d", converted), "little")
                else:
                    raise NotImplementedError(
                        f"{mnemonic.upper()} destination width "
                        f"{destination_width}"
                    )
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("fadd", "fsub", "fmul", "fdiv"):
                destination_name = self._reg_name(operands[0].reg)
                width = self._reg_width(destination_name)
                if width == 32:
                    format_code = "<f"
                    byte_count = 4
                elif width == 64:
                    format_code = "<d"
                    byte_count = 8
                else:
                    raise NotImplementedError(
                        f"{mnemonic.upper()} destination width {width}"
                    )

                def as_float(operand: Any) -> float:
                    bits = self.operand_value(operand) & _mask(width)
                    return struct.unpack(
                        format_code, bits.to_bytes(byte_count, "little")
                    )[0]

                left = as_float(operands[1])
                right = as_float(operands[2])
                if mnemonic == "fadd":
                    converted = left + right
                elif mnemonic == "fsub":
                    converted = left - right
                elif mnemonic == "fmul":
                    converted = left * right
                else:
                    converted = left / right
                self.write_reg(
                    operands[0].reg,
                    int.from_bytes(struct.pack(format_code, converted), "little"),
                )
            elif mnemonic in ("fcmp", "fcmpe"):
                source_name = self._reg_name(operands[0].reg)
                width = self._reg_width(source_name)
                if width == 32:
                    format_code = "<f"
                    byte_count = 4
                elif width == 64:
                    format_code = "<d"
                    byte_count = 8
                else:
                    raise NotImplementedError(
                        f"{mnemonic.upper()} source width {width}"
                    )

                def comparison_float(operand: Any) -> float:
                    if operand.type == ARM64_OP_FP:  # noqa: F405
                        return float(operand.fp)
                    bits = self.operand_value(operand) & _mask(width)
                    return struct.unpack(
                        format_code, bits.to_bytes(byte_count, "little")
                    )[0]

                left = comparison_float(operands[0])
                right = comparison_float(operands[1])
                if math.isnan(left) or math.isnan(right):
                    self.nzcv.update(n=0, z=0, c=1, v=1)
                elif left == right:
                    self.nzcv.update(n=0, z=1, c=1, v=0)
                elif left < right:
                    self.nzcv.update(n=1, z=0, c=0, v=0)
                else:
                    self.nzcv.update(n=0, z=0, c=1, v=0)
            elif mnemonic == "ext":
                # Byte extract from the concatenation Vn:Vm.
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                vector_bits = lane_count * lane_bits
                first = self.operand_value(operands[1]) & _mask(vector_bits)
                second = self.operand_value(operands[2]) & _mask(vector_bits)
                byte_offset = self.operand_value(operands[3])
                combined = first | (second << vector_bits)
                self.write_reg(
                    operands[0].reg,
                    (combined >> (byte_offset * 8)) & _mask(vector_bits),
                )
            elif mnemonic in ("tbl", "tbx"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                if lane_bits != 8:
                    raise ValueError(f"unexpected TBL arrangement {instruction.op_str!r}")
                table_operands = operands[1:-1]
                index_value = self.operand_value(operands[-1])
                table = bytearray()
                for operand_index, operand in enumerate(table_operands, start=1):
                    table_lanes, table_bits = self._vector_arrangement(
                        instruction, operand_index
                    )
                    table_bytes = table_lanes * table_bits // 8
                    table.extend(
                        self.read_reg(operand.reg).to_bytes(16, "little")[:table_bytes]
                    )
                previous = self.read_reg(operands[0].reg)
                result = 0
                for lane_index in range(lane_count):
                    index = (index_value >> (lane_index * 8)) & 0xFF
                    if index < len(table):
                        byte = table[index]
                    elif mnemonic == "tbx":
                        byte = (previous >> (lane_index * 8)) & 0xFF
                    else:
                        byte = 0
                    result |= byte << (lane_index * 8)
                self.write_reg(operands[0].reg, result)
            elif mnemonic in ("ushr", "sshr", "shl"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                shift = self.operand_value(operands[2])

                def shift_lane(lane: int) -> int:
                    if mnemonic == "ushr":
                        return lane >> shift
                    if mnemonic == "sshr":
                        return _sign_extend(lane, lane_bits) >> shift
                    return lane << shift

                self.write_reg(
                    operands[0].reg,
                    self._map_vector_lanes(
                        self.operand_value(operands[1]),
                        lane_bits,
                        shift_lane,
                        lane_count,
                    ),
                )
            elif mnemonic in ("ushl", "sshl"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                lane_mask = _mask(lane_bits)

                def variable_shift(left_lane: int, right_lane: int) -> int:
                    amount = _sign_extend(right_lane & 0xFF, 8)
                    if amount >= lane_bits or amount <= -lane_bits:
                        if mnemonic == "sshl" and amount < 0:
                            return lane_mask if left_lane & (1 << (lane_bits - 1)) else 0
                        return 0
                    if amount >= 0:
                        return (left_lane << amount) & lane_mask
                    if mnemonic == "sshl":
                        return _sign_extend(left_lane, lane_bits) >> -amount
                    return left_lane >> -amount

                self.write_reg(
                    operands[0].reg,
                    self._binary_vector_lanes(
                        self.operand_value(operands[1]),
                        self.operand_value(operands[2]),
                        lane_count,
                        lane_bits,
                        variable_shift,
                    ),
                )
            elif mnemonic in ("shrn", "shrn2", "rshrn", "rshrn2"):
                destination_lanes, destination_bits = self._vector_arrangement(
                    instruction, 0
                )
                source_lanes, source_bits = self._vector_arrangement(instruction, 1)
                shift = self.operand_value(operands[2])
                source = self.operand_value(operands[1])
                lane_mask = _mask(destination_bits)
                narrowed = 0
                for lane_index in range(source_lanes):
                    lane = (source >> (lane_index * source_bits)) & _mask(source_bits)
                    if mnemonic.startswith("rshrn") and shift:
                        lane += 1 << (shift - 1)
                    narrowed |= ((lane >> shift) & lane_mask) << (
                        lane_index * destination_bits
                    )
                if mnemonic.endswith("2"):
                    lower_bits = (destination_lanes - source_lanes) * destination_bits
                    preserved = self.read_reg(operands[0].reg) & _mask(lower_bits)
                    narrowed = preserved | (narrowed << lower_bits)
                self.write_reg(operands[0].reg, narrowed)
            elif mnemonic in (
                "ushll", "ushll2", "sshll", "sshll2", "shll", "shll2"
            ):
                destination_lanes, destination_bits = self._vector_arrangement(
                    instruction, 0
                )
                source_lanes, source_bits = self._vector_arrangement(instruction, 1)
                source = self.operand_value(operands[1])
                shift = self.operand_value(operands[2])
                source_start = source_lanes - destination_lanes if mnemonic.endswith("2") else 0
                result = 0
                for lane_index in range(destination_lanes):
                    source_index = source_start + lane_index
                    lane = (source >> (source_index * source_bits)) & _mask(source_bits)
                    if mnemonic.startswith("sshll"):
                        lane = _sign_extend(lane, source_bits)
                    result |= ((lane << shift) & _mask(destination_bits)) << (
                        lane_index * destination_bits
                    )
                self.write_reg(operands[0].reg, result)
            elif mnemonic in ("xtn", "xtn2"):
                destination_lanes, destination_bits = self._vector_arrangement(
                    instruction, 0
                )
                source_lanes, source_bits = self._vector_arrangement(instruction, 1)
                source = self.operand_value(operands[1])
                narrowed = 0
                for lane_index in range(source_lanes):
                    lane = (source >> (lane_index * source_bits)) & _mask(destination_bits)
                    narrowed |= lane << (lane_index * destination_bits)
                if mnemonic == "xtn2":
                    lower_bits = (destination_lanes - source_lanes) * destination_bits
                    narrowed = (
                        self.read_reg(operands[0].reg) & _mask(lower_bits)
                    ) | (narrowed << lower_bits)
                self.write_reg(operands[0].reg, narrowed)
            elif mnemonic in ("uzp1", "uzp2", "zip1", "zip2", "trn1", "trn2"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                lane_mask = _mask(lane_bits)
                first = self.operand_value(operands[1])
                second = self.operand_value(operands[2])
                output_lanes: list[int] = []
                if mnemonic.startswith("uzp"):
                    parity = 0 if mnemonic == "uzp1" else 1
                    for value in (first, second):
                        output_lanes.extend(
                            (value >> (index * lane_bits)) & lane_mask
                            for index in range(parity, lane_count, 2)
                        )
                elif mnemonic.startswith("zip"):
                    start = 0 if mnemonic == "zip1" else lane_count // 2
                    for index in range(start, start + lane_count // 2):
                        output_lanes.append((first >> (index * lane_bits)) & lane_mask)
                        output_lanes.append((second >> (index * lane_bits)) & lane_mask)
                else:
                    parity = 0 if mnemonic == "trn1" else 1
                    for index in range(lane_count // 2):
                        lane_index = index * 2 + parity
                        output_lanes.append(
                            (first >> (lane_index * lane_bits)) & lane_mask
                        )
                        output_lanes.append(
                            (second >> (lane_index * lane_bits)) & lane_mask
                        )
                result = 0
                for lane_index, lane in enumerate(output_lanes[:lane_count]):
                    result |= lane << (lane_index * lane_bits)
                self.write_reg(operands[0].reg, result)
            elif mnemonic in ("cas", "casa", "casl", "casal"):
                expected_name = self._reg_name(operands[0].reg)
                size = 4 if expected_name.startswith("w") else 8
                address = self.memory_address(operands[2])
                expected = self.read_reg(operands[0].reg)
                desired = self.read_reg(operands[1].reg)
                previous = self.read_mem(address, size)
                if previous == (expected & _mask(size * 8)):
                    self.write_mem(address, desired, size)
                # Acquire/release ordering is irrelevant to this
                # single-threaded static evaluator. Architecturally, CAS
                # always returns the observed old memory value in Rs.
                self.write_reg(operands[0].reg, previous)
            elif mnemonic.startswith("swp"):
                source_name = self._reg_name(operands[0].reg)
                if mnemonic.endswith("b"):
                    size = 1
                elif mnemonic.endswith("h"):
                    size = 2
                else:
                    size = 4 if source_name.startswith("w") else 8
                address = self.memory_address(operands[2])
                previous = self.read_mem(address, size)
                self.write_mem(address, self.read_reg(operands[0].reg), size)
                # SWP Ws, Wt, [Xn] stores Ws and returns the observed old
                # memory value in Wt. Acquire/release ordering is irrelevant
                # to this evaluator's single-threaded execution.
                self.write_reg(operands[1].reg, previous)
            elif mnemonic == "movn":
                width = self._reg_width(self._reg_name(operands[0].reg))
                self.write_reg(operands[0].reg, ~self.operand_value(operands[1]) & _mask(width))
            elif mnemonic == "movk":
                width = self._reg_width(self._reg_name(operands[0].reg))
                shift = operands[1].shift.value
                current = self.read_reg(operands[0].reg)
                value = operands[1].imm & 0xFFFF
                current &= ~(0xFFFF << shift) & _mask(width)
                self.write_reg(operands[0].reg, current | (value << shift))
            elif mnemonic in ("add", "sub") and self._reg_name(
                operands[0].reg
            ).startswith("v"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                operation = (
                    (lambda left, right: left + right)
                    if mnemonic == "add"
                    else (lambda left, right: left - right)
                )
                self.write_reg(
                    operands[0].reg,
                    self._binary_vector_lanes(
                        self.operand_value(operands[1]),
                        self.operand_value(operands[2]),
                        lane_count,
                        lane_bits,
                        operation,
                    ),
                )
            elif mnemonic in ("add", "adds", "sub", "subs"):
                left = self.operand_value(operands[1])
                right = self.operand_value(operands[2])
                width = self._reg_width(self._reg_name(operands[0].reg))
                result = left + right if mnemonic.startswith("add") else left - right
                self.write_reg(operands[0].reg, result)
                if mnemonic.endswith("s"):
                    if mnemonic.startswith("sub"):
                        self._set_sub_flags(left, right, result, width)
                    else:
                        self._set_add_flags(left, right, result, width)
            elif mnemonic in ("adc", "adcs", "sbc", "sbcs"):
                left = self.operand_value(operands[1])
                right = self.operand_value(operands[2])
                width = self._reg_width(self._reg_name(operands[0].reg))
                if mnemonic.startswith("ad"):
                    value = left + right + self.nzcv["c"]
                else:
                    value = left - right - (1 - self.nzcv["c"])
                self.write_reg(operands[0].reg, value)
                if mnemonic.endswith("s"):
                    if mnemonic.startswith("ad"):
                        self._set_add_flags(left, right, value, width, self.nzcv["c"])
                    else:
                        self._set_sub_flags(left, right + (1 - self.nzcv["c"]), value, width)
            elif mnemonic == "mul" and self._reg_name(
                operands[0].reg
            ).startswith("v"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                self.write_reg(
                    operands[0].reg,
                    self._binary_vector_lanes(
                        self.operand_value(operands[1]),
                        self.operand_value(operands[2]),
                        lane_count,
                        lane_bits,
                        lambda left, right: left * right,
                    ),
                )
            elif mnemonic in ("mla", "mls"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                current = self.read_reg(operands[0].reg)
                product = self._binary_vector_lanes(
                    self.operand_value(operands[1]),
                    self.operand_value(operands[2]),
                    lane_count,
                    lane_bits,
                    lambda left, right: left * right,
                )
                operation = (
                    (lambda left, right: left + right)
                    if mnemonic == "mla"
                    else (lambda left, right: left - right)
                )
                self.write_reg(
                    operands[0].reg,
                    self._binary_vector_lanes(
                        current,
                        product,
                        lane_count,
                        lane_bits,
                        operation,
                    ),
                )
            elif mnemonic in ("mul", "madd", "msub", "mneg"):
                value = self.operand_value(operands[1]) * self.operand_value(operands[2])
                if mnemonic == "madd":
                    value += self.operand_value(operands[3])
                elif mnemonic == "msub":
                    value = self.operand_value(operands[3]) - value
                elif mnemonic == "mneg":
                    value = -value
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("umulh", "smulh"):
                left = self.operand_value(operands[1])
                right = self.operand_value(operands[2])
                if mnemonic == "smulh":
                    left = _sign_extend(left, 64)
                    right = _sign_extend(right, 64)
                self.write_reg(operands[0].reg, (left * right >> 64) & MASK64)
            elif mnemonic in (
                "umull", "umull2", "smull", "smull2",
                "umaddl", "smaddl", "umsubl", "smsubl",
            ):
                if self._reg_name(operands[0].reg).startswith("v"):
                    destination_lanes, destination_bits = self._vector_arrangement(
                        instruction, 0
                    )
                    source_lanes, source_bits = self._vector_arrangement(
                        instruction, 1
                    )
                    left = self.operand_value(operands[1])
                    right = self.operand_value(operands[2])
                    result = 0
                    high_half = mnemonic.endswith("2")
                    source_start = (
                        source_lanes - destination_lanes if high_half else 0
                    )
                    for lane_index in range(destination_lanes):
                        shift = (source_start + lane_index) * source_bits
                        left_lane = (left >> shift) & _mask(source_bits)
                        right_lane = (right >> shift) & _mask(source_bits)
                        if mnemonic.startswith("sm"):
                            left_lane = _sign_extend(left_lane, source_bits)
                            right_lane = _sign_extend(right_lane, source_bits)
                        result |= (
                            (left_lane * right_lane) & _mask(destination_bits)
                        ) << (lane_index * destination_bits)
                    self.write_reg(operands[0].reg, result)
                else:
                    left = self.operand_value(operands[1]) & MASK32
                    right = self.operand_value(operands[2]) & MASK32
                    if mnemonic.startswith("sm"):
                        left = _sign_extend(left, 32)
                        right = _sign_extend(right, 32)
                    value = left * right
                    if mnemonic.endswith("addl"):
                        value += self.operand_value(operands[3])
                    elif mnemonic.endswith("subl"):
                        value = self.operand_value(operands[3]) - value
                    self.write_reg(operands[0].reg, value)
            elif mnemonic in ("udiv", "sdiv"):
                numerator = self.operand_value(operands[1])
                denominator = self.operand_value(operands[2])
                width = self._reg_width(self._reg_name(operands[0].reg))
                if denominator == 0:
                    value = 0
                elif mnemonic == "sdiv":
                    numerator = _sign_extend(numerator, width)
                    denominator = _sign_extend(denominator, width)
                    value = abs(numerator) // abs(denominator)
                    if (numerator < 0) != (denominator < 0):
                        value = -value
                else:
                    value = (numerator & _mask(width)) // (denominator & _mask(width))
                self.write_reg(operands[0].reg, value)
            elif mnemonic == "neg" and self._reg_name(
                operands[0].reg
            ).startswith("v"):
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                self.write_reg(
                    operands[0].reg,
                    self._map_vector_lanes(
                        self.operand_value(operands[1]),
                        lane_bits,
                        lambda lane: -lane,
                        lane_count,
                    ),
                )
            elif mnemonic in ("neg", "negs"):
                value = -self.operand_value(operands[1])
                self.write_reg(operands[0].reg, value)
                if mnemonic == "negs":
                    width = self._reg_width(self._reg_name(operands[0].reg))
                    self._set_sub_flags(0, self.operand_value(operands[1]), value, width)
            elif mnemonic == "mvn":
                width = self._reg_width(self._reg_name(operands[0].reg))
                self.write_reg(operands[0].reg, ~self.operand_value(operands[1]) & _mask(width))
            elif mnemonic == "eor3":
                # ARMv8.2 SHA-3 extension: bitwise XOR of three 128-bit
                # vector operands.  The operation is arrangement-independent.
                self.write_reg(
                    operands[0].reg,
                    self.operand_value(operands[1])
                    ^ self.operand_value(operands[2])
                    ^ self.operand_value(operands[3]),
                )
            elif mnemonic in ("and", "ands", "orr", "orn", "eor", "eon", "bic", "bics"):
                left = self.operand_value(operands[1])
                right = self.operand_value(operands[2])
                if mnemonic.startswith("and"):
                    value = left & right
                elif mnemonic in ("orr",):
                    value = left | right
                elif mnemonic == "orn":
                    value = left | (~right & MASK64)
                elif mnemonic == "eor":
                    value = left ^ right
                elif mnemonic == "eon":
                    value = left ^ (~right & MASK64)
                else:
                    value = left & (~right & MASK64)
                self.write_reg(operands[0].reg, value)
                if mnemonic.endswith("s"):
                    width = self._reg_width(self._reg_name(operands[0].reg))
                    value &= _mask(width)
                    self.nzcv["n"] = int(bool(value & (1 << (width - 1))))
                    self.nzcv["z"] = int(value == 0)
                    self.nzcv["c"] = 0
                    self.nzcv["v"] = 0
            elif mnemonic in ("lsl", "lsr", "asr", "ror"):
                width = self._reg_width(self._reg_name(operands[0].reg))
                kinds = {
                    "lsl": ARM64_SFT_LSL,  # noqa: F405
                    "lsr": ARM64_SFT_LSR,  # noqa: F405
                    "asr": ARM64_SFT_ASR,  # noqa: F405
                    "ror": ARM64_SFT_ROR,  # noqa: F405
                }
                value = self._shift(self.operand_value(operands[1]), kinds[mnemonic], self.operand_value(operands[2]), width)
                self.write_reg(operands[0].reg, value)
            elif mnemonic == "extr":
                width = self._reg_width(self._reg_name(operands[0].reg))
                high = self.operand_value(operands[1]) & _mask(width)
                low = self.operand_value(operands[2]) & _mask(width)
                shift = self.operand_value(operands[3]) % width
                self.write_reg(
                    operands[0].reg,
                    ((low | (high << width)) >> shift) & _mask(width),
                )
            elif mnemonic in ("uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw"):
                bits = {"uxtb": 8, "uxth": 16, "uxtw": 32, "sxtb": 8, "sxth": 16, "sxtw": 32}[mnemonic]
                value = self.operand_value(operands[1])
                if mnemonic.startswith("s"):
                    value = _sign_extend(value, bits)
                else:
                    value &= (1 << bits) - 1
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("clz", "cls"):
                width = self._reg_width(self._reg_name(operands[0].reg))
                value = self.operand_value(operands[1]) & _mask(width)
                if mnemonic == "cls":
                    if value & (1 << (width - 1)):
                        value = (~value) & _mask(width)
                    count = width if value == 0 else width - value.bit_length()
                    value = max(0, count - 1)
                else:
                    value = width if value == 0 else width - value.bit_length()
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("rev", "rev16", "rev32", "rev64"):
                width = self._reg_width(self._reg_name(operands[0].reg))
                value = self.operand_value(operands[1]) & _mask(width)
                unit_bits = {
                    "rev": width,
                    "rev16": 16,
                    "rev32": 32,
                    "rev64": 64,
                }[mnemonic]
                result = 0
                for unit_offset in range(0, width, unit_bits):
                    unit = (value >> unit_offset) & ((1 << unit_bits) - 1)
                    reversed_unit = int.from_bytes(
                        unit.to_bytes(unit_bits // 8, "little"), "big"
                    )
                    result |= reversed_unit << unit_offset
                self.write_reg(operands[0].reg, result)
            elif mnemonic in ("bfi", "bfxil"):
                width = self._reg_width(self._reg_name(operands[0].reg))
                destination = self.read_reg(operands[0].reg)
                source = self.operand_value(operands[1])
                lsb = operands[2].imm
                field_width = operands[3].imm
                field_mask = ((1 << field_width) - 1) << lsb
                if mnemonic == "bfi":
                    inserted = (source << lsb) & field_mask
                else:
                    inserted = (source >> lsb) & ((1 << field_width) - 1)
                    field_mask = (1 << field_width) - 1
                self.write_reg(
                    operands[0].reg,
                    (destination & ~field_mask) | inserted & _mask(width),
                )
            elif mnemonic in ("ubfx", "sbfx", "ubfiz", "sbfiz"):
                destination_width = self._reg_width(self._reg_name(operands[0].reg))
                source = self.operand_value(operands[1])
                lsb = operands[2].imm
                field_width = operands[3].imm
                field_mask = (1 << field_width) - 1
                if mnemonic.endswith("fx"):
                    value = (source >> lsb) & field_mask
                else:
                    value = source & field_mask
                    if mnemonic.startswith("s"):
                        value = _sign_extend(value, field_width)
                    value <<= lsb
                if mnemonic == "sbfx":
                    value = _sign_extend(value, field_width)
                self.write_reg(operands[0].reg, value & _mask(destination_width))
            elif mnemonic.startswith(("ldr", "ldur")):
                destination = self._reg_name(operands[0].reg)
                size, signed = self._load_store_size(mnemonic, destination)
                if operands[1].type == ARM64_OP_MEM:  # noqa: F405
                    address = self.memory_address(operands[1])
                else:
                    address = operands[1].imm & MASK64
                value = self.read_mem(address, size)
                if signed:
                    value = _sign_extend(value, size * 8)
                self.write_reg(operands[0].reg, value)
                if operands[1].type == ARM64_OP_MEM:  # noqa: F405
                    self._writeback(instruction, operands[1], address)
            elif mnemonic.startswith(("ldar", "ldapr")):
                destination = self._reg_name(operands[0].reg)
                if mnemonic.endswith("b"):
                    size = 1
                elif mnemonic.endswith("h"):
                    size = 2
                else:
                    size = 4 if destination.startswith("w") else 8
                address = self.memory_address(operands[1])
                self.write_reg(operands[0].reg, self.read_mem(address, size))
            elif mnemonic.startswith(("str", "stur")):
                source = self._reg_name(operands[0].reg)
                size, _ = self._load_store_size(mnemonic, source)
                address = self.memory_address(operands[1])
                self.write_mem(address, self.read_reg(operands[0].reg), size)
                self._writeback(instruction, operands[1], address)
            elif mnemonic.startswith("stlr"):
                source = self._reg_name(operands[0].reg)
                if mnemonic.endswith("b"):
                    size = 1
                elif mnemonic.endswith("h"):
                    size = 2
                else:
                    size = 4 if source.startswith("w") else 8
                address = self.memory_address(operands[1])
                self.write_mem(address, self.read_reg(operands[0].reg), size)
            elif mnemonic == "ld1r":
                register_operand = operands[0]
                memory_operand = next(
                    operand
                    for operand in operands
                    if operand.type == ARM64_OP_MEM  # noqa: F405
                )
                address = self.memory_address(memory_operand)
                lane_bits = self._vector_lane_bits(instruction)
                lane = self.read_mem(address, lane_bits // 8)
                self.write_reg(
                    register_operand.reg,
                    self._map_vector_lanes(0, lane_bits, lambda _unused: lane),
                )
                self._writeback(instruction, memory_operand, address)
            elif mnemonic in ("ld1", "st1"):
                register_operand = operands[0]
                memory_operand = next(
                    operand
                    for operand in operands
                    if operand.type == ARM64_OP_MEM  # noqa: F405
                )
                address = self.memory_address(memory_operand)
                vector_index = getattr(register_operand, "vector_index", -1)
                if vector_index is not None and vector_index >= 0:
                    lane_bits = self._vector_lane_bits(instruction)
                    lane_size = lane_bits // 8
                    lane_shift = vector_index * lane_bits
                    lane_mask = _mask(lane_bits) << lane_shift
                    if mnemonic == "ld1":
                        lane = self.read_mem(address, lane_size)
                        current = self.read_reg(register_operand.reg)
                        self.write_reg(
                            register_operand.reg,
                            (current & ~lane_mask) | ((lane << lane_shift) & lane_mask),
                        )
                    else:
                        lane = (self.read_reg(register_operand.reg) >> lane_shift) & _mask(lane_bits)
                        self.write_mem(address, lane, lane_size)
                else:
                    if mnemonic == "ld1":
                        self.write_reg(register_operand.reg, self.read_mem(address, 16))
                    else:
                        self.write_mem(address, self.read_reg(register_operand.reg), 16)
                self._writeback(instruction, memory_operand, address)
            elif mnemonic in ("ld2", "ld3", "ld4"):
                # Interleaved SIMD structure load.  For example,
                # ``ld4 {v16.16b-v19.16b}, [x20]`` deinterleaves 64 bytes so
                # each destination receives every fourth byte.  Capstone
                # exposes one register operand per destination followed by the
                # memory operand.
                register_operands = [
                    operand
                    for operand in operands
                    if operand.type == ARM64_OP_REG  # noqa: F405
                ]
                memory_operand = next(
                    operand
                    for operand in operands
                    if operand.type == ARM64_OP_MEM  # noqa: F405
                )
                if len(register_operands) != int(mnemonic[-1]):
                    raise ValueError(
                        f"unexpected {mnemonic.upper()} operand list "
                        f"{instruction.op_str!r}"
                    )
                lane_count, lane_bits = self._vector_arrangement(instruction, 0)
                lane_size = lane_bits // 8
                address = self.memory_address(memory_operand)
                structure_count = len(register_operands)
                for register_index, register_operand in enumerate(register_operands):
                    value = 0
                    for lane_index in range(lane_count):
                        lane_address = address + (
                            lane_index * structure_count + register_index
                        ) * lane_size
                        lane = self.read_mem(lane_address, lane_size)
                        value |= lane << (lane_index * lane_bits)
                    self.write_reg(register_operand.reg, value)
                self._writeback(instruction, memory_operand, address)
            elif mnemonic in ("ldp", "ldpsw"):
                address = self.memory_address(operands[2])
                first_name = self._reg_name(operands[0].reg)
                if first_name.startswith("v"):
                    size = 16
                else:
                    size = 4 if mnemonic == "ldpsw" or first_name.startswith("w") else 8
                first = self.read_mem(address, size)
                second = self.read_mem(address + size, size)
                if mnemonic == "ldpsw":
                    first = _sign_extend(first, 32)
                    second = _sign_extend(second, 32)
                self.write_reg(operands[0].reg, first)
                self.write_reg(operands[1].reg, second)
                self._writeback(instruction, operands[2], address)
            elif mnemonic == "stp":
                address = self.memory_address(operands[2])
                first_name = self._reg_name(operands[0].reg)
                if first_name.startswith("v"):
                    size = 16
                else:
                    size = 4 if first_name.startswith("w") else 8
                self.write_mem(address, self.read_reg(operands[0].reg), size)
                self.write_mem(address + size, self.read_reg(operands[1].reg), size)
                self._writeback(instruction, operands[2], address)
            elif mnemonic in ("cmp", "cmn"):
                left = self.operand_value(operands[0])
                right = self.operand_value(operands[1])
                width = self._reg_width(self._reg_name(operands[0].reg)) if operands[0].type == ARM64_OP_REG else 64  # noqa: F405
                if mnemonic == "cmp":
                    self._set_sub_flags(left, right, left - right, width)
                else:
                    self._set_add_flags(left, right, left + right, width)
            elif mnemonic == "tst":
                left = self.operand_value(operands[0])
                right = self.operand_value(operands[1])
                width = self._reg_width(self._reg_name(operands[0].reg))
                result = (left & right) & _mask(width)
                self.nzcv["n"] = int(bool(result & (1 << (width - 1))))
                self.nzcv["z"] = int(result == 0)
                self.nzcv["c"] = 0
                self.nzcv["v"] = 0
            elif mnemonic in ("ccmp", "ccmn"):
                if self._condition(instruction.cc):
                    left = self.operand_value(operands[0])
                    right = self.operand_value(operands[1])
                    width = self._reg_width(self._reg_name(operands[0].reg))
                    if mnemonic == "ccmp":
                        self._set_sub_flags(left, right, left - right, width)
                    else:
                        self._set_add_flags(left, right, left + right, width)
                else:
                    flags = operands[2].imm & 0xF
                    self.nzcv = {
                        "n": (flags >> 3) & 1,
                        "z": (flags >> 2) & 1,
                        "c": (flags >> 1) & 1,
                        "v": flags & 1,
                    }
            elif mnemonic in ("cset", "csetm"):
                value = int(self._condition(instruction.cc))
                if mnemonic == "csetm":
                    value = MASK64 if value else 0
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("csel", "csinc", "csinv", "csneg"):
                condition = self._condition(instruction.cc)
                value = self.operand_value(operands[1] if condition else operands[2])
                if not condition:
                    if mnemonic == "csinc":
                        value += 1
                    elif mnemonic == "csinv":
                        value = ~value
                    elif mnemonic == "csneg":
                        value = -value
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("cinc", "cinv", "cneg"):
                value = self.operand_value(operands[1])
                if self._condition(instruction.cc):
                    if mnemonic == "cinc":
                        value += 1
                    elif mnemonic == "cinv":
                        value = ~value
                    else:
                        value = -value
                self.write_reg(operands[0].reg, value)
            elif mnemonic in ("cbz", "cbnz"):
                zero = self.operand_value(operands[0]) == 0
                if zero == (mnemonic == "cbz"):
                    next_pc = operands[1].imm & MASK64
            elif mnemonic in ("tbz", "tbnz"):
                bit = (self.operand_value(operands[0]) >> operands[1].imm) & 1
                if bool(bit) == (mnemonic == "tbnz"):
                    next_pc = operands[2].imm & MASK64
            elif mnemonic.startswith("b."):
                if self._condition(instruction.cc):
                    next_pc = operands[0].imm & MASK64
            elif mnemonic == "b":
                target = operands[0].imm & MASK64
                if not self.db.is_valid_ea(target):
                    return Stop(
                        "direct-branch",
                        pc,
                        mnemonic,
                        target,
                        None,
                        self.snapshot(),
                        count,
                    )
                next_pc = target
            elif mnemonic == "bl":
                target = operands[0].imm & MASK64
                if follow_internal_transfers and self.db.is_valid_ea(target):
                    self.regs["x30"] = pc + 4
                    next_pc = target
                else:
                    return Stop(
                        "direct-call",
                        pc,
                        mnemonic,
                        target,
                        None,
                        self.snapshot(),
                        count,
                    )
            elif mnemonic.startswith(("blr", "bra", "brab", "br")):
                target = self.operand_value(operands[0]) if operands else None
                modifier = self.operand_value(operands[1]) if len(operands) > 1 else None
                if (
                    follow_internal_transfers
                    and target is not None
                    and self.db.is_valid_ea(target)
                ):
                    if mnemonic.startswith("blr"):
                        self.regs["x30"] = pc + 4
                    next_pc = target
                else:
                    return Stop(
                        "indirect",
                        pc,
                        mnemonic,
                        target,
                        modifier,
                        self.snapshot(),
                        count,
                    )
            elif mnemonic in ("ret", "retab", "retaa"):
                target = self.regs.get("x30", 0)
                if follow_internal_transfers and self.db.is_valid_ea(target):
                    next_pc = target
                else:
                    return Stop(
                        "return",
                        pc,
                        mnemonic,
                        target,
                        None,
                        self.snapshot(),
                        count,
                    )
            else:
                return Stop(f"unsupported:{instruction.mnemonic} {instruction.op_str}", pc, mnemonic, None, None, self.snapshot(), count)

            if self.memory_break_hit is not None:
                return Stop(
                    "memory-breakpoint",
                    pc,
                    mnemonic,
                    None,
                    None,
                    self.snapshot(),
                    count,
                )

            pc = next_pc

        return Stop("instruction-limit", pc, "", None, None, self.snapshot(), count)


def resolve_first_indirect(
    db: Any,
    start_ea: int,
    *,
    args: tuple[int, ...] = (),
    sp: int = 0x700000100000,
    chained_pointer_base: int | None = None,
    chained_pointer_format: str | None = None,
    max_instructions: int = 1000,
) -> dict[str, Any]:
    """Return a JSON-serializable description of the first indirect transfer."""

    evaluator = Evaluator(
        db,
        args=args,
        sp=sp,
        chained_pointer_base=chained_pointer_base,
        chained_pointer_format=chained_pointer_format,
    )
    stop = evaluator.run(start_ea, max_instructions=max_instructions)
    target_name = None
    if stop.target is not None and db.is_valid_ea(stop.target):
        target_name = db.names.get_at(stop.target)
        if not target_name:
            function = db.functions.get_at(stop.target)
            if function is not None:
                target_name = db.functions.get_name(function)
    return {
        "reason": stop.reason,
        "address": hex(stop.address),
        "mnemonic": stop.mnemonic,
        "target": hex(stop.target) if stop.target is not None else None,
        "target_name": target_name,
        "modifier": hex(stop.modifier) if stop.modifier is not None else None,
        "registers": {key: hex(value) for key, value in stop.registers.items()},
        "instructions": stop.instructions,
    }


def _target_name(db: Any, target: int | None) -> str | None:
    if target is None:
        return None
    try:
        name = db.names.get_at(target)
    except Exception:
        name = None
    if name:
        return name
    if not db.is_valid_ea(target):
        return None
    function = db.functions.get_at(target)
    return db.functions.get_name(function) if function is not None else None


def resolve_indirect_chain(
    db: Any,
    start_ea: int,
    *,
    args: tuple[int, ...] = (),
    sp: int = 0x700000100000,
    chained_pointer_base: int | None = None,
    chained_pointer_format: str | None = None,
    max_stages: int = 32,
    max_instructions_per_stage: int = 4000,
) -> dict[str, Any]:
    """Follow internal calls/tail branches while preserving emulated state.

    The stack-probe helper is treated as a register-preserving no-op.  Other
    direct or indirect transfers outside the database terminate the trace.
    """

    evaluator = Evaluator(
        db,
        args=args,
        sp=sp,
        chained_pointer_base=chained_pointer_base,
        chained_pointer_format=chained_pointer_format,
    )
    pc = start_ea
    stages: list[dict[str, Any]] = []
    total_instructions = 0

    for _ in range(max_stages):
        stop = evaluator.run(pc, max_instructions=max_instructions_per_stage)
        total_instructions += stop.instructions
        name = _target_name(db, stop.target)
        stages.append(
            {
                "start": hex(pc),
                "reason": stop.reason,
                "address": hex(stop.address),
                "mnemonic": stop.mnemonic,
                "target": hex(stop.target) if stop.target is not None else None,
                "target_name": name,
                "modifier": hex(stop.modifier) if stop.modifier is not None else None,
                "x0": hex(stop.registers.get("x0", 0)),
                "sp": hex(stop.registers.get("sp", 0)),
                "instructions": stop.instructions,
            }
        )

        if stop.reason == "direct-call":
            if name == "___chkstk_darwin":
                pc = stop.address + 4
                continue
            if stop.target is not None and db.is_valid_ea(stop.target):
                evaluator.regs["x30"] = stop.address + 4
                pc = stop.target
                continue
            break

        if stop.reason == "indirect":
            if name == "___chkstk_darwin" and stop.mnemonic.startswith("blr"):
                pc = stop.address + 4
                continue
            if stop.target is None or not db.is_valid_ea(stop.target):
                break
            if stop.mnemonic.startswith("blr"):
                evaluator.regs["x30"] = stop.address + 4
            pc = stop.target
            continue

        if stop.reason == "return":
            if stop.target in (None, 0) or not db.is_valid_ea(stop.target):
                break
            pc = stop.target
            continue

        break

    return {
        "start": hex(start_ea),
        "stages": stages,
        "total_instructions": total_instructions,
        "final_registers": {key: hex(value) for key, value in evaluator.snapshot().items()},
    }
