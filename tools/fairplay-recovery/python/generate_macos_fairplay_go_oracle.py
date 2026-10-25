#!/usr/bin/env python3
"""Generate the straight-line Go oracle and its private checkpoint model.

The generated Go source contains only instruction semantics and fixed fault
site metadata for the exact fairplayd build. Dynamic registers and memory are
written to a separate mode-0600 gzip model and must never be committed.
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

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import (
    ARM64_CC_EQ,
    ARM64_CC_HI,
    ARM64_CC_LO,
    ARM64_CC_NE,
    ARM64_EXT_SXTB,
    ARM64_EXT_SXTH,
    ARM64_EXT_SXTW,
    ARM64_EXT_SXTX,
    ARM64_EXT_UXTB,
    ARM64_EXT_UXTH,
    ARM64_EXT_UXTW,
    ARM64_EXT_UXTX,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
    ARM64_REG_INVALID,
    ARM64_SFT_ASR,
    ARM64_SFT_LSL,
    ARM64_SFT_LSR,
    ARM64_SFT_ROR,
)

from continue_fairplay_checkpoint_unicorn import checkpoint_memory_pages
from probe_macos_fairplay_whitebox_checkpoint import CheckpointBlockOracle, FaultSite
from raw_macho_db import RawMachODatabase, dyld_info_fixups


START = 0x100221894
STOP = 0x100223A30
BLOCK = 0x710000014EE0
RESULT_BLOCK = BLOCK
COPY_RESULT_TO_BLOCK = False
INSTRUCTION_PATH: tuple[int, ...] | None = None
INSTRUCTION_PATH_FIRST_REPEAT = False
REPEAT_COUNT = 1
MODEL_PAGE_SANITIZER = None
MODEL_INITIAL_READ_BYTES: set[int] = set()
MAGIC = b"FPGOOR1\x00"
VERSION = 2

FAULT_SITES = {
    8: (
        (0x100222E04, "w9", "index"),
        (0x100222F1C, "x7", "pointer"),
        (0x100222FA0, "x14", "pointer"),
        (0x100222F64, "x22", "pointer"),
        (0x100222F18, "x3", "pointer"),
        (0x100222F88, "x9", "pointer"),
        (0x100222ED8, "w2", "index"),
        (0x100222F80, "x1", "pointer"),
        (0x100222EBC, "w21", "index"),
        (0x100222ECC, "w23", "index"),
        (0x100222F6C, "x4", "pointer"),
        (0x100222F48, "w15", "index"),
        (0x100222EB0, "w19", "index"),
        (0x100222EA4, "w8", "index"),
        (0x100222F2C, "x6", "pointer"),
        (0x100222FAC, "x24", "pointer"),
    ),
    7: (
        (0x100222DBC, "x7", "pointer"),
        (0x100222D90, "x3", "pointer"),
        (0x100222DEC, "x24", "pointer"),
        (0x100222C58, "w9", "index-after"),
        (0x100222D8C, "x15", "pointer"),
        (0x100222D20, "w19", "index"),
        (0x100222D84, "x8", "pointer"),
        (0x100222DD8, "x25", "pointer"),
        (0x100222D14, "w19", "index"),
        (0x100222C84, "w15", "index"),
        (0x100222DD0, "x6", "pointer"),
        (0x100222DB4, "x2", "pointer"),
        (0x100222C74, "w9", "index"),
        (0x100222DC0, "x22", "pointer"),
        (0x100222DA4, "x4", "pointer"),
        (0x100222DF4, "x23", "pointer"),
    ),
    6: (
        (0x100222AC4, "w12", "index"),
        (0x100222BE4, "x21", "pointer"),
        (0x100222BDC, "x4", "pointer"),
        (0x100222C20, "x3", "pointer"),
        (0x100222AB0, "w14", "index"),
        (0x100222BCC, "x19", "pointer"),
        (0x100222C18, "x2", "pointer"),
        (0x100222C40, "x23", "pointer"),
        (0x100222B98, "w8", "index"),
        (0x100222AE0, "w1", "index"),
        (0x100222C38, "x22", "pointer"),
        (0x100222C04, "x24", "pointer"),
        (0x100222AD0, "w14", "index"),
        (0x100222C28, "x7", "pointer"),
        (0x100222BF4, "x6", "pointer"),
        (0x100222C54, "w9", "index"),
    ),
}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reg_name(disassembler: Cs, operand) -> str:
    return disassembler.reg_name(operand.reg).lower()


def reg_index(name: str) -> int:
    name = {"fp": "x29", "lr": "x30"}.get(name, name)
    if name in {"xzr", "wzr"}:
        return -1
    if len(name) >= 2 and name[0] in "xw" and name[1:].isdigit():
        value = int(name[1:])
        if 0 <= value <= 30:
            return value
    raise ValueError(f"unsupported register {name!r}")


def reg_width(name: str) -> int:
    name = {"fp": "x29", "lr": "x30"}.get(name, name)
    if name == "sp" or name.startswith("x"):
        return 64
    if name.startswith("w"):
        return 32
    raise ValueError(f"unsupported register width {name!r}")


def read_register(name: str) -> str:
    name = {"fp": "x29", "lr": "x30"}.get(name, name)
    if name in {"xzr", "wzr"}:
        return "uint64(0)"
    if name == "sp":
        return "s.sp"
    index = reg_index(name)
    if name.startswith("w"):
        return f"uint64(uint32(s.x[{index}]))"
    return f"s.x[{index}]"


def write_register(name: str, expression: str) -> str:
    name = {"fp": "x29", "lr": "x30"}.get(name, name)
    if name in {"xzr", "wzr"}:
        return f"_ = {expression}"
    if name == "sp":
        return f"s.sp = uint64({expression})"
    index = reg_index(name)
    if name.startswith("w"):
        return f"s.x[{index}] = uint64(uint32({expression}))"
    return f"s.x[{index}] = uint64({expression})"


def shifted(expression: str, shift_type: int, amount: int, width: int) -> str:
    if shift_type == 0 or amount == 0:
        return expression
    helper = {
        ARM64_SFT_LSL: "shiftLeft",
        ARM64_SFT_LSR: "shiftRight",
        ARM64_SFT_ASR: "shiftRightArithmetic",
        ARM64_SFT_ROR: "rotateRight",
    }.get(shift_type)
    if helper is None:
        raise ValueError(f"unsupported shift type {shift_type}")
    return f"{helper}({expression}, {amount}, {width})"


def extended(expression: str, extension: int) -> str:
    helpers = {
        0: None,
        ARM64_EXT_UXTB: "uint64(uint8({}))",
        ARM64_EXT_UXTH: "uint64(uint16({}))",
        ARM64_EXT_UXTW: "uint64(uint32({}))",
        ARM64_EXT_UXTX: "uint64({})",
        ARM64_EXT_SXTB: "uint64(int64(int8({})))",
        ARM64_EXT_SXTH: "uint64(int64(int16({})))",
        ARM64_EXT_SXTW: "signExtend32(uint32({}))",
        ARM64_EXT_SXTX: "uint64(int64({}))",
    }
    template = helpers.get(extension)
    if extension not in helpers:
        raise ValueError(f"unsupported extension {extension}")
    return expression if template is None else template.format(expression)


def operand_expression(disassembler: Cs, operand, width: int) -> str:
    if operand.type == ARM64_OP_REG:
        expression = read_register(reg_name(disassembler, operand))
        expression = extended(expression, operand.ext)
        return shifted(expression, operand.shift.type, operand.shift.value, width)
    if operand.type == ARM64_OP_IMM:
        value = int(operand.imm) & ((1 << width) - 1)
        expression = f"uint64({value:#x})"
        return shifted(expression, operand.shift.type, operand.shift.value, width)
    raise ValueError("operand is not a register or immediate")


def memory_address(disassembler: Cs, operand) -> str:
    if operand.type != ARM64_OP_MEM:
        raise ValueError("operand is not memory")
    base_name = disassembler.reg_name(operand.mem.base).lower()
    base = "s.sp" if base_name == "sp" else read_register(base_name)
    expression = base
    if operand.mem.index != ARM64_REG_INVALID:
        index_name = disassembler.reg_name(operand.mem.index).lower()
        index = read_register(index_name)
        index = extended(index, operand.ext)
        index = shifted(index, operand.shift.type, operand.shift.value, 64)
        expression = f"({expression} + {index})"
    if operand.mem.disp:
        expression = f"addOffset({expression}, {int(operand.mem.disp)})"
    return expression


def condition_name(code: int) -> str:
    return {
        ARM64_CC_EQ: "eq",
        ARM64_CC_NE: "ne",
        ARM64_CC_LO: "lo",
        ARM64_CC_HI: "hi",
    }[code]


def emit_instruction(disassembler: Cs, instruction, ordinal: int) -> list[str]:
    mnemonic = instruction.mnemonic.lower()
    operands = instruction.operands
    pc = instruction.address
    output: list[str] = []

    if pc in {site[0] for sites in FAULT_SITES.values() for site in sites}:
        output.extend(
            [
                f"old{ordinal}, restore{ordinal}, err := s.beforeFault(selected, {pc:#x})",
                "if err != nil { return err }",
            ]
        )

    def binary_expression(operator: str) -> str:
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        return write_register(destination, f"({left} {operator} {right})")

    if mnemonic in {"add", "sub", "eor", "and", "orr"}:
        output.append(binary_expression({"add": "+", "sub": "-", "eor": "^", "and": "&", "orr": "|"}[mnemonic]))
    elif mnemonic in {"bic", "orn"}:
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        operator = "&^" if mnemonic == "bic" else "|"
        expression = f"({left} {operator} {right})" if mnemonic == "bic" else f"({left} | ^{right})"
        output.append(write_register(destination, expression))
    elif mnemonic == "mov":
        destination = reg_name(disassembler, operands[0])
        output.append(write_register(destination, operand_expression(disassembler, operands[1], reg_width(destination))))
    elif mnemonic == "movk":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        shift = operands[1].shift.value
        value = int(operands[1].imm) & 0xFFFF
        output.append(write_register(destination, f"insertBits({read_register(destination)}, {value:#x}, {shift}, 16, {width})"))
    elif mnemonic in {"ldr", "ldur", "ldrb", "ldurb"}:
        destination = reg_name(disassembler, operands[0])
        size = 1 if mnemonic in {"ldrb", "ldurb"} else 8 if reg_width(destination) == 64 else 4
        output.extend(
            [
                f"value{ordinal}, err := s.load({memory_address(disassembler, operands[1])}, {size})",
                "if err != nil { return err }",
                write_register(destination, f"value{ordinal}"),
            ]
        )
    elif mnemonic == "ldp":
        first = reg_name(disassembler, operands[0])
        second = reg_name(disassembler, operands[1])
        size = 8 if reg_width(first) == 64 else 4
        address = memory_address(disassembler, operands[2])
        output.extend(
            [
                f"value{ordinal}a, err := s.load({address}, {size})",
                "if err != nil { return err }",
                f"value{ordinal}b, err := s.load(({address}) + {size}, {size})",
                "if err != nil { return err }",
                write_register(first, f"value{ordinal}a"),
                write_register(second, f"value{ordinal}b"),
            ]
        )
    elif mnemonic == "stp":
        first = reg_name(disassembler, operands[0])
        second = reg_name(disassembler, operands[1])
        size = 8 if reg_width(first) == 64 else 4
        address = memory_address(disassembler, operands[2])
        output.extend(
            [
                f"if err := s.storeValue({address}, {read_register(first)}, {size}); err != nil {{ return err }}",
                f"if err := s.storeValue(({address}) + {size}, {read_register(second)}, {size}); err != nil {{ return err }}",
            ]
        )
    elif mnemonic in {"str", "stur", "strb"}:
        source = reg_name(disassembler, operands[0])
        size = 1 if mnemonic == "strb" else 8 if reg_width(source) == 64 else 4
        output.extend(
            [
                f"if err := s.storeValue({memory_address(disassembler, operands[1])}, {read_register(source)}, {size}); err != nil {{ return err }}",
            ]
        )
    elif mnemonic in {"lsl", "lsr", "ror"}:
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        amount = operand_expression(disassembler, operands[2], width)
        helper = {"lsl": "shiftLeft", "lsr": "shiftRight", "ror": "rotateRight"}[mnemonic]
        output.append(write_register(destination, f"{helper}({left}, int({amount}), {width})"))
    elif mnemonic == "neg":
        destination = reg_name(disassembler, operands[0])
        output.append(write_register(destination, f"-({operand_expression(disassembler, operands[1], reg_width(destination))})"))
    elif mnemonic == "mvn":
        destination = reg_name(disassembler, operands[0])
        output.append(write_register(destination, f"^({operand_expression(disassembler, operands[1], reg_width(destination))})"))
    elif mnemonic == "mul":
        output.append(binary_expression("*"))
    elif mnemonic == "madd":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        addend = operand_expression(disassembler, operands[3], width)
        output.append(write_register(destination, f"({left}*{right} + {addend})"))
    elif mnemonic == "msub":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        minuend = operand_expression(disassembler, operands[3], width)
        output.append(write_register(destination, f"({minuend} - {left}*{right})"))
    elif mnemonic == "umull":
        destination = reg_name(disassembler, operands[0])
        left = operand_expression(disassembler, operands[1], 32)
        right = operand_expression(disassembler, operands[2], 32)
        output.append(write_register(destination, f"uint64(uint32({left})) * uint64(uint32({right}))"))
    elif mnemonic == "ubfx":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        source = operand_expression(disassembler, operands[1], width)
        lsb, bits = int(operands[2].imm), int(operands[3].imm)
        output.append(write_register(destination, f"({source} >> {lsb}) & bitMask({bits}, {width})"))
    elif mnemonic == "bfxil":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        source = operand_expression(disassembler, operands[1], width)
        lsb, bits = int(operands[2].imm), int(operands[3].imm)
        output.append(write_register(destination, f"insertBits({read_register(destination)}, {source} >> {lsb}, 0, {bits}, {width})"))
    elif mnemonic == "bfi":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        source = operand_expression(disassembler, operands[1], width)
        lsb, bits = int(operands[2].imm), int(operands[3].imm)
        output.append(write_register(destination, f"insertBits({read_register(destination)}, {source}, {lsb}, {bits}, {width})"))
    elif mnemonic == "extr":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        high = operand_expression(disassembler, operands[1], width)
        low = operand_expression(disassembler, operands[2], width)
        amount = int(operands[3].imm)
        output.append(write_register(destination, f"extractPair({high}, {low}, {amount}, {width})"))
    elif mnemonic == "cmp":
        left = operand_expression(disassembler, operands[0], 32)
        right = operand_expression(disassembler, operands[1], 32)
        output.append(f"s.compare32(uint32({left}), uint32({right}))")
    elif mnemonic == "tst":
        left = operand_expression(disassembler, operands[0], 32)
        right = operand_expression(disassembler, operands[1], 32)
        output.append(f"s.test32(uint32({left} & {right}))")
    elif mnemonic == "cset":
        destination = reg_name(disassembler, operands[0])
        output.append(write_register(destination, f"boolValue(s.condition(\"{condition_name(instruction.cc)}\"))"))
    elif mnemonic == "csel":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        output.append(write_register(destination, f"selectValue(s.condition(\"{condition_name(instruction.cc)}\"), {left}, {right})"))
    elif mnemonic == "cneg":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        source = operand_expression(disassembler, operands[1], width)
        output.append(write_register(destination, f"selectValue(s.condition(\"{condition_name(instruction.cc)}\"), -({source}), {source})"))
    elif mnemonic == "csneg":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        output.append(write_register(destination, f"selectValue(s.condition(\"{condition_name(instruction.cc)}\"), {left}, -({right}))"))
    elif mnemonic == "bics":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        left = operand_expression(disassembler, operands[1], width)
        right = operand_expression(disassembler, operands[2], width)
        output.append(f"result{ordinal} := uint32({left} &^ {right})")
        output.append(write_register(destination, f"result{ordinal}"))
        output.append(f"s.test32(result{ordinal})")
    elif mnemonic == "ubfiz":
        destination = reg_name(disassembler, operands[0])
        width = reg_width(destination)
        source = operand_expression(disassembler, operands[1], width)
        lsb, bits = int(operands[2].imm), int(operands[3].imm)
        output.append(write_register(destination, f"(({source}) & bitMask({bits}, {width})) << {lsb}"))
    elif mnemonic == "adrp":
        destination = reg_name(disassembler, operands[0])
        output.append(write_register(destination, f"{int(operands[1].imm):#x}"))
    elif mnemonic in {"braa", "brab"}:
        # The generated evaluator is already laid out in the one validated
        # runtime trace order, so authenticated control transfers are edges,
        # not operations on architectural state.
        pass
    else:
        raise ValueError(f"unsupported instruction {pc:#x}: {mnemonic} {instruction.op_str}")

    if pc in {site[0] for sites in FAULT_SITES.values() for site in sites}:
        output.append(f"s.afterFault(selected, {pc:#x}, old{ordinal}, restore{ordinal})")
    return output


def helper_source() -> str:
    return r'''
func shiftLeft(value uint64, amount int, width int) uint64 {
	if width == 32 { return uint64(uint32(value) << (uint(amount) & 31)) }
	return value << (uint(amount) & 63)
}

func shiftRight(value uint64, amount int, width int) uint64 {
	if width == 32 { return uint64(uint32(value) >> (uint(amount) & 31)) }
	return value >> (uint(amount) & 63)
}

func shiftRightArithmetic(value uint64, amount int, width int) uint64 {
	if width == 32 { return uint64(uint32(int32(value) >> (uint(amount) & 31))) }
	return uint64(int64(value) >> (uint(amount) & 63))
}

func rotateRight(value uint64, amount int, width int) uint64 {
	if width == 32 { return uint64(rotateRight32(uint32(value), uint32(amount))) }
	amount &= 63
	if amount == 0 { return value }
	return value>>amount | value<<(64-amount)
}

func bitMask(bits int, width int) uint64 {
	if bits >= width {
		if width == 32 { return uint64(^uint32(0)) }
		return ^uint64(0)
	}
	return uint64(1)<<bits - 1
}

func insertBits(destination, source uint64, lsb, bits, width int) uint64 {
	mask := bitMask(bits, width) << lsb
	value := (destination &^ mask) | ((source << lsb) & mask)
	if width == 32 { return uint64(uint32(value)) }
	return value
}

func extractPair(high, low uint64, amount, width int) uint64 {
	if width == 32 {
		combined := uint64(uint32(high))<<32 | uint64(uint32(low))
		return uint64(uint32(combined >> amount))
	}
	if amount == 0 { return low }
	return high<<(64-amount) | low>>amount
}

func addOffset(value uint64, offset int64) uint64 { return value + uint64(offset) }

func boolValue(value bool) uint64 {
	if value { return 1 }
	return 0
}

func selectValue(condition bool, left, right uint64) uint64 {
	if condition { return left }
	return right
}
'''


def unpack_fault_site(site: tuple[object, ...]) -> tuple[int, str, str, int]:
    if len(site) == 3:
        pc, register, kind = site
        shift = 0
    elif len(site) == 4:
        pc, register, kind, shift = site
    else:
        raise ValueError(f"invalid fault-site tuple {site!r}")
    return int(pc), str(register), str(kind), int(shift)


def generate_go(
    database: RawMachODatabase,
    binary_hash: bytes,
    *,
    build_tag: str | None = None,
) -> str:
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    if INSTRUCTION_PATH is None:
        code = bytes(
            database.bytes.get_byte_at(address, allow_uninitialized=True)
            for address in range(START, STOP)
        )
        instructions = list(disassembler.disasm(code, START))
        if len(instructions) != (STOP - START) // 4 or any(
            instruction.address != START + index * 4
            for index, instruction in enumerate(instructions)
        ):
            raise ValueError("oracle path is not one complete straight-line instruction range")
    else:
        instructions = []
        for address in INSTRUCTION_PATH:
            raw = bytes(
                database.bytes.get_byte_at(address + offset, allow_uninitialized=True)
                for offset in range(4)
            )
            decoded = list(disassembler.disasm(raw, address, count=1))
            if len(decoded) != 1 or decoded[0].address != address:
                raise ValueError(f"cannot decode oracle instruction at {address:#x}")
            instructions.append(decoded[0])

    by_pc = {instruction.address: instruction for instruction in instructions}
    site_rows = []
    for round_index in sorted(FAULT_SITES):
        values = []
        for raw_site in FAULT_SITES[round_index]:
            pc, register, kind, shift = unpack_fault_site(raw_site)
            register_number = reg_index(register)
            if kind == "index-after":
                restore = False
                actual_kind = "faultIndex"
            elif kind == "index-shift":
                restore = False
                actual_kind = "faultIndex"
            else:
                instruction = by_pc[pc]
                destination = reg_name(disassembler, instruction.operands[0])
                restore = reg_index(destination) != register_number
                actual_kind = "faultPointer" if kind == "pointer" else "faultIndex"
            values.append(
                "{pc: %#x, register: %d, shift: %d, kind: %s, restore: %s, tableBytes: 0x400, entryBytes: 4}"
                % (pc, register_number, shift, actual_kind, str(restore).lower())
            )
        site_rows.append(f"\t{round_index}: {{" + ", ".join(values) + "},")

    lines = []
    if build_tag:
        lines.extend([f"//go:build {build_tag}", ""])
    lines.extend([
        "// Code generated by generate_macos_fairplay_go_oracle.py; DO NOT EDIT.",
        "package main",
        "",
        'import "fmt"',
        "",
        "var generatedBinaryHash = [32]byte{" + ",".join(f"0x{value:02x}" for value in binary_hash) + "}",
        "",
        "var generatedFaultSites = map[uint16][16]fault{",
        *site_rows,
        "}",
        "",
        "func generatedFault(meta uint32) (fault, error) {",
        "\tround := uint16(meta & 0xffff)",
        "\tif round == 0xffff { return fault{}, nil }",
    ])
    if not FAULT_SITES:
        lines.extend([
            "\treturn fault{}, fmt.Errorf(\"this evaluator does not expose fault sites\")",
            "}",
            "",
            helper_source(),
            "func runGenerated(s *state, selected fault) error {",
        ])
    else:
        lines.extend([
            "\tvar siteRound uint16",
            "\tswitch round {",
            "\tcase 9: siteRound = 8",
            "\tcase 8: siteRound = 7",
            "\tcase 6, 7: siteRound = 6",
            "\tdefault: return fault{}, fmt.Errorf(\"unsupported oracle fault round=%d\", round)",
            "\t}",
            "\tbyteIndex := uint8(meta >> 16)",
            "\txorValue := uint8(meta >> 24)",
            "\tsites, ok := generatedFaultSites[siteRound]",
            "\tif !ok || byteIndex >= 16 || xorValue == 0 { return fault{}, fmt.Errorf(\"unsupported oracle fault round=%d byte=%d xor=%d\", round, byteIndex, xorValue) }",
            "\tresult := sites[byteIndex]",
            "\tresult.value = xorValue",
            "\treturn result, nil",
            "}",
            "",
            helper_source(),
            "func runGenerated(s *state, selected fault) error {",
        ])
    if REPEAT_COUNT != 1:
        lines.append(f"\tfor repeat := 0; repeat < {REPEAT_COUNT}; repeat++ {{")
    instruction_indent = "\t\t" if REPEAT_COUNT != 1 else "\t"
    for ordinal, instruction in enumerate(instructions):
        lines.append(f"{instruction_indent}// {instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")
        for statement in emit_instruction(disassembler, instruction, ordinal):
            lines.append(instruction_indent + statement)
    if REPEAT_COUNT != 1:
        lines.append("\t}")
    if COPY_RESULT_TO_BLOCK and RESULT_BLOCK != BLOCK:
        for offset in range(16):
            lines.extend(
                [
                    f"\tresultByte{offset}, err := s.load({RESULT_BLOCK + offset:#x}, 1)",
                    "\tif err != nil { return err }",
                    f"\tif err := s.storeValue({BLOCK + offset:#x}, resultByte{offset}, 1); err != nil {{ return err }}",
                ]
            )
    lines.extend(["\treturn nil", "}", ""])
    return "\n".join(lines)


def page_from_image(database: RawMachODatabase, address: int) -> bytes:
    return bytes(
        database.bytes.get_byte_at(address + offset, allow_uninitialized=True)
        for offset in range(0x1000)
    )


def recover_index_domains(
    checkpoint_path: Path,
    database: RawMachODatabase,
) -> dict[tuple[int, int], tuple[int, ...]]:
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    sites: dict[tuple[int, str], FaultSite] = {}
    for round_index, rows in FAULT_SITES.items():
        for byte_index, raw_site in enumerate(rows):
            pc, register, kind, _shift = unpack_fault_site(raw_site)
            if kind != "index":
                continue
            raw = database.bytes.get_dword_at(
                pc, allow_uninitialized=True
            ).to_bytes(4, "little")
            instruction = next(disassembler.disasm(raw, pc, count=1))
            destination = reg_name(disassembler, instruction.operands[0])
            sites[(pc, register)] = FaultSite(
                round_index=round_index,
                byte_index=byte_index,
                pc=pc,
                index_register=register,
                restore_register=reg_index(destination) != reg_index(register),
            )
    oracle = CheckpointBlockOracle(
        checkpoint_path,
        entry=START,
        block=BLOCK,
        result_block=BLOCK,
        stop_address=STOP,
        stop_hit=1,
        instruction_limit=200_000,
    )
    values = oracle.learn_index_domains(list(sites.values()))
    return {
        (pc, reg_index(register)): tuple(int(value) for value in domain)
        for (pc, register), domain in values.items()
    }


def write_private_model(
    path: Path,
    checkpoint: dict[str, object],
    database: RawMachODatabase,
    pages: list[int],
    binary_hash: bytes,
    domains: dict[tuple[int, int], tuple[int, ...]],
) -> None:
    checkpoint_pages = checkpoint_memory_pages(checkpoint)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as output:
            output.write(MAGIC)
            output.write(struct.pack("<I", VERSION))
            output.write(binary_hash)
            output.write(struct.pack("<Q", BLOCK))
            registers = checkpoint["registers"]
            for index in range(31):
                output.write(struct.pack("<Q", int(registers[f"x{index}"])))
            output.write(struct.pack("<Q", int(registers["sp"])))
            nzcv = checkpoint["nzcv"]
            output.write(bytes((int(nzcv["n"]), int(nzcv["z"]), int(nzcv["c"]), int(nzcv["v"]))))
            output.write(struct.pack("<I", len(pages)))
            for address in pages:
                data = checkpoint_pages.get(address)
                if data is None:
                    data = page_from_image(database, address)
                if not isinstance(data, bytes) or len(data) != 0x1000:
                    raise ValueError(f"invalid model page {address:#x}")
                if MODEL_PAGE_SANITIZER is not None:
                    data = MODEL_PAGE_SANITIZER(address, data)
                    if not isinstance(data, bytes) or len(data) != 0x1000:
                        raise ValueError(f"invalid sanitized model page {address:#x}")
                output.write(struct.pack("<Q", address))
                output.write(data)
            output.write(struct.pack("<I", len(domains)))
            for (pc, register), values in sorted(domains.items()):
                if len(values) != 256 or len(set(values)) != 256:
                    raise ValueError(f"invalid index domain {pc:#x}/x{register}")
                output.write(struct.pack("<Q", pc))
                output.write(bytes((register,)) + bytes(7))
                for value in values:
                    output.write(struct.pack("<Q", value))
    path.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument(
        "--memory-trace",
        type=Path,
        action="append",
        required=True,
        help=(
            "private validation trace used to collect model pages; repeat "
            "the option to include every validated control-flow variant"
        ),
    )
    parser.add_argument("--go-output", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
    parser.add_argument("--build-tag")
    parser.add_argument(
        "--instruction-trace",
        type=Path,
        help="private validation trace whose recent_pcs define a non-linear path",
    )
    args = parser.parse_args()

    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    if checkpoint.get("schema") not in {1, 2} or int(checkpoint["pc"], 16) != START:
        raise ValueError("checkpoint is not the configured oracle entry")
    binary = Path(checkpoint["binary"])
    binary_bytes = binary.read_bytes()
    if digest(binary_bytes) != checkpoint["binary_sha256"]:
        raise ValueError("checkpoint binary hash mismatch")
    binary_hash = hashlib.sha256(binary_bytes).digest()
    fixups, _names = dyld_info_fixups(binary)
    database = RawMachODatabase(binary, fixups=fixups)

    traces = [json.loads(path.read_text()) for path in args.memory_trace]
    if any(
        trace.get("binary_sha256") != checkpoint["binary_sha256"]
        for trace in traces
    ):
        raise ValueError("memory trace build mismatch")
    pages = sorted(
        {
            int(event["address"], 16) & ~0xFFF
            for trace in traces
            for key in ("memory_read_events", "memory_write_events")
            for event in trace[key]
        }
    )
    if BLOCK & ~0xFFF not in pages:
        raise ValueError("memory trace does not include the oracle block")

    global MODEL_INITIAL_READ_BYTES
    for trace in traces:
        written_bytes: set[int] = set()
        for _ordinal, kind, event in sorted(
            [
                (int(event.get("ordinal", index * 2)), "read", event)
                for index, event in enumerate(trace["memory_read_events"])
            ]
            + [
                (int(event.get("ordinal", index * 2 + 1)), "write", event)
                for index, event in enumerate(trace["memory_write_events"])
            ],
            key=lambda item: item[0],
        ):
            address = int(event["address"], 16)
            size = int(event["size"])
            if kind == "write":
                written_bytes.update(range(address, address + size))
            else:
                MODEL_INITIAL_READ_BYTES.update(
                    value
                    for value in range(address, address + size)
                    if value not in written_bytes
                )

    global INSTRUCTION_PATH
    if args.instruction_trace is not None:
        instruction_trace = json.loads(args.instruction_trace.read_text())
        if instruction_trace.get("binary_sha256") != checkpoint["binary_sha256"]:
            raise ValueError("instruction trace build mismatch")
        path = [int(value, 16) for value in instruction_trace.get("recent_pcs", [])]
        if path and path[-1] == STOP:
            path.pop()
        if not path or path[0] != START:
            raise ValueError("instruction trace does not begin at the oracle entry")
        if INSTRUCTION_PATH_FIRST_REPEAT:
            try:
                path = path[: path[1:].index(START) + 1]
            except ValueError as error:
                raise ValueError("instruction trace has no repeated oracle entry") from error
        INSTRUCTION_PATH = tuple(path)

    domains = recover_index_domains(args.checkpoint, database)

    source = generate_go(database, binary_hash, build_tag=args.build_tag)
    args.go_output.parent.mkdir(parents=True, exist_ok=True)
    if args.go_output.exists():
        raise FileExistsError(args.go_output)
    args.go_output.write_text(source)
    write_private_model(
        args.model_output,
        checkpoint,
        database,
        pages,
        binary_hash,
        domains,
    )
    print(
        "fairplay_go_oracle_generated=1 "
        f"instructions={len(INSTRUCTION_PATH) if INSTRUCTION_PATH is not None else (STOP-START)//4} pages={len(pages)} domains={len(domains)} "
        f"go={args.go_output} model={args.model_output}"
    )


if __name__ == "__main__":
    main()
