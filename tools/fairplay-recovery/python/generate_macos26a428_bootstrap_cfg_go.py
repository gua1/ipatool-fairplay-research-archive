#!/usr/bin/env python3
"""Generate the pure-Go 26A428 bootstrap CFG along one verified natural path."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pickle
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

import generate_macos_fairplay_go_oracle as generator
from continue_fairplay_checkpoint_unicorn import (
    KNOWN_EOR3_SITES_26A428,
    NOP,
    RET_X30,
    checkpoint_memory_pages,
    x_register_number,
)
from raw_macho_db import RawMachODatabase, dyld_info_fixups


EXTERNAL_BASE = 0xF000000000000000
NOOP_CALLBACK = 0x720000000000
START = 0x10057AE74
BLOCK = 0x7000000EC3A0


def decode_block(database: RawMachODatabase, disassembler: Cs, start: int, size: int):
    result = []
    for address in range(start, start + size, 4):
        raw = bytes(
            database.bytes.get_byte_at(address + offset, allow_uninitialized=True)
            for offset in range(4)
        )
        decoded = list(disassembler.disasm(raw, address, count=1))
        if len(decoded) != 1:
            raise ValueError(f"cannot decode CFG instruction at {address:#x}")
        result.append(decoded[0])
    return result


def patched_instruction_bytes(database: RawMachODatabase) -> dict[int, bytes]:
    """Reproduce the native reference runner's non-preserving code patches."""
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    result: dict[int, bytes] = {}
    for section in database.sections:
        if not section.contains_instructions or not section.size:
            continue
        code = database.image[section.fileoff : section.fileoff + section.size]
        for offset in range(0, len(code) - 3, 4):
            address = section.vmaddr + offset
            instruction = next(disassembler.disasm(code[offset : offset + 4], address, count=1), None)
            if instruction is None:
                continue
            mnemonic = instruction.mnemonic.lower()
            replacement = None
            if mnemonic.startswith(("braa", "brab")):
                replacement = 0xD61F0000 | (x_register_number(disassembler.reg_name(instruction.operands[0].reg)) << 5)
            elif mnemonic.startswith(("blraa", "blrab")):
                replacement = 0xD63F0000 | (x_register_number(disassembler.reg_name(instruction.operands[0].reg)) << 5)
            elif mnemonic in {"retaa", "retab"}:
                replacement = RET_X30
            elif mnemonic in {"ldraa", "ldrab"}:
                replacement = NOP
            elif mnemonic.startswith(("pac", "aut", "xpac")):
                replacement = NOP
            elif mnemonic == "eor3" and address in KNOWN_EOR3_SITES_26A428:
                replacement = NOP
            elif mnemonic == "casal":
                replacement = NOP
            if replacement is not None:
                result[address] = replacement.to_bytes(4, "little")
    return result


def branch_lines(disassembler: Cs, instruction) -> list[str] | None:
    mnemonic = instruction.mnemonic.lower()
    operands = instruction.operands
    fallthrough = instruction.address + 4
    if mnemonic in {"braa", "brab", "br"}:
        target = generator.read_register(generator.reg_name(disassembler, operands[0]))
        return [f"pc = {target}", "continue"]
    if mnemonic in {"blraa", "blr"}:
        target = generator.read_register(generator.reg_name(disassembler, operands[0]))
        return [f"s.x[30] = {fallthrough:#x}", f"pc = {target}", "continue"]
    if mnemonic in {"ret", "retab"}:
        target = (
            generator.read_register(generator.reg_name(disassembler, operands[0]))
            if operands and operands[0].type == ARM64_OP_REG
            else "s.x[30]"
        )
        return [f"pc = {target}", "continue"]
    if mnemonic == "b":
        return [f"pc = {int(operands[0].imm):#x}", "continue"]
    if mnemonic == "bl":
        return [
            f"s.x[30] = {fallthrough:#x}",
            f"pc = {int(operands[0].imm):#x}",
            "continue",
        ]
    if mnemonic.startswith("b."):
        condition = mnemonic.removeprefix("b.")
        return [
            f"if s.condition(\"{condition}\") {{",
            f"\tpc = {int(operands[0].imm):#x}",
            "} else {",
            f"\tpc = {fallthrough:#x}",
            "}",
            "continue",
        ]
    if mnemonic in {"cbz", "cbnz"}:
        register = generator.read_register(generator.reg_name(disassembler, operands[0]))
        operator = "==" if mnemonic == "cbz" else "!="
        return [
            f"if {register} {operator} 0 {{",
            f"\tpc = {int(operands[1].imm):#x}",
            "} else {",
            f"\tpc = {fallthrough:#x}",
            "}",
            "continue",
        ]
    if mnemonic in {"tbz", "tbnz"}:
        register = generator.read_register(generator.reg_name(disassembler, operands[0]))
        bit = int(operands[1].imm)
        operator = "==" if mnemonic == "tbz" else "!="
        return [
            f"if ({register} & (uint64(1) << {bit})) {operator} 0 {{",
            f"\tpc = {int(operands[2].imm):#x}",
            "} else {",
            f"\tpc = {fallthrough:#x}",
            "}",
            "continue",
        ]
    return None


def branch_return_lines(disassembler: Cs, instruction) -> list[str] | None:
    lines = branch_lines(disassembler, instruction)
    if lines is None:
        return None
    result: list[str] = []
    for line in lines:
        if line.lstrip().startswith("pc = "):
            result.append(line.replace("pc = ", "next = ", 1))
        elif line == "continue":
            result.append("return next, false, nil")
        else:
            result.append(line)
    return result


def generate_source(
    database: RawMachODatabase,
    blocks: list[int],
    sizes: dict[int, int],
    stop_pc: int,
) -> str:
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    generator.FAULT_SITES = {}
    lines = [
        "//go:build fairplayrawsource && !fairplaysidb && !fairplayframe && !fairplaystate && !fairplay26a428",
        "",
        "// Code generated by generate_macos26a428_bootstrap_cfg_go.py; DO NOT EDIT.",
        "package main",
        "",
        'import "fmt"',
        "",
        "func runRawSourceBootstrapCFG(s *state, runtime *rawSourceRuntime, maxBlocks int) (uint64, int, error) {",
        f"\tpc := uint64({START:#x})",
        "\tfor blockCount := 0; blockCount < maxBlocks; blockCount++ {",
        f"\t\tif pc == {stop_pc:#x} {{ return pc, blockCount, nil }}",
        "\t\tif runtime != nil && runtime.stopPC != 0 && pc == runtime.stopPC { return pc, blockCount, nil }",
        f"\t\tif pc >= {EXTERNAL_BASE:#x} || pc == {NOOP_CALLBACK:#x} {{",
        "\t\t\tif runtime == nil { return pc, blockCount, fmt.Errorf(\"bootstrap runtime is unavailable\") }",
        "\t\t\tnext, err := runtime.handle(s, pc)",
        "\t\t\tif err != nil { return pc, blockCount, err }",
        "\t\t\tpc = next",
        "\t\t\tcontinue",
        "\t\t}",
        "\t\tswitch pc {",
    ]
    for start in blocks:
        lines.append(f"\t\tcase {start:#x}:")
        lines.extend(
            [
                "\t\t\t{",
                f"\t\t\t\tnext, stopped, err := rawSourceBootstrapBlock{start:x}(s, runtime)",
                "\t\t\t\tif err != nil { return pc, blockCount, fmt.Errorf(\"bootstrap CFG %#x: %w\", pc, err) }",
                "\t\t\t\tif stopped { return next, blockCount, nil }",
                "\t\t\t\tpc = next",
                "\t\t\t\tcontinue",
                "\t\t\t}",
            ]
        )
    lines.extend(
        [
            "\t\tdefault:",
            "\t\t\treturn pc, blockCount, fmt.Errorf(\"bootstrap CFG reached unknown block %#x\", pc)",
            "\t\t}",
            "\t}",
            "\treturn pc, maxBlocks, fmt.Errorf(\"bootstrap CFG exceeded %d blocks\", maxBlocks)",
            "}",
            "",
        ]
    )
    for start in blocks:
        size = sizes[start]
        instructions = decode_block(database, disassembler, start, size)
        lines.extend(
            [
                f"func rawSourceBootstrapBlock{start:x}(s *state, runtime *rawSourceRuntime) (next uint64, stopped bool, err error) {{",
            ]
        )
        terminated = False
        for ordinal, instruction in enumerate(instructions):
            lines.append(
                f"\tif runtime != nil && runtime.stopPC == {instruction.address:#x} {{ return {instruction.address:#x}, true, nil }}"
            )
            lines.append(f"\t// {instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")
            branch = branch_return_lines(disassembler, instruction)
            if branch is not None:
                lines.extend(f"\t{statement}" for statement in branch)
                terminated = True
                break
            statements = generator.emit_instruction(disassembler, instruction, ordinal)
            for statement in statements:
                statement = statement.replace("return err", "return 0, false, err")
                lines.append(f"\t{statement}")
        if not terminated:
            lines.append(f"\treturn {start + size:#x}, false, nil")
        lines.extend(["}", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--block-profile", type=Path, required=True)
    parser.add_argument("--block-trace", type=Path, required=True)
    parser.add_argument("--go-output", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
    args = parser.parse_args()

    with gzip.open(args.checkpoint, "rb") as stream:
        checkpoint = pickle.load(stream)
    if int(checkpoint["pc"], 16) != START:
        raise ValueError("checkpoint is not at the bootstrap CFG entry")
    binary = Path(checkpoint["binary"])
    binary_hash = hashlib.sha256(binary.read_bytes()).digest()
    if binary_hash.hex() != checkpoint["binary_sha256"]:
        raise ValueError("checkpoint binary hash mismatch")
    fixups, _names = dyld_info_fixups(binary)
    database = RawMachODatabase(binary, fixups=fixups)

    profile = json.loads(args.block_profile.read_text())
    trace = json.loads(args.block_trace.read_text())
    if profile["binary_sha256"] != checkpoint["binary_sha256"] or trace["binary_sha256"] != checkpoint["binary_sha256"]:
        raise ValueError("bootstrap trace build mismatch")
    raw_blocks = [int(value, 16) for value in trace["recent_pcs"]]
    sizes = {int(row["pc"], 16): int(row["size"]) for row in profile["block_counts"]}
    stop_pc = int(trace["stop"]["pc"], 16)
    stop_index = raw_blocks.index(stop_pc)
    path_blocks = raw_blocks[:stop_index]
    blocks = list(
        dict.fromkeys(
            address
            for address in path_blocks
            if address < EXTERNAL_BASE and address != NOOP_CALLBACK
        )
    )
    missing = [address for address in blocks if address not in sizes]
    if missing:
        raise ValueError(f"profile lacks {len(missing)} reached block sizes")

    source = generate_source(database, blocks, sizes, stop_pc)
    args.go_output.parent.mkdir(parents=True, exist_ok=True)
    args.go_output.write_text(source)

    checkpoint_pages = set(checkpoint_memory_pages(checkpoint))
    stack_pages = set(range(0x7000000E0000, 0x700000110000, 0x1000))
    image_pages = {
        address
        for segment in database.segments
        if segment.name != "__PAGEZERO"
        for address in range(
            segment.vmaddr & ~0xFFF,
            (segment.end_ea + 0xFFF) & ~0xFFF,
            0x1000,
        )
    }
    generator.BLOCK = BLOCK
    instruction_patches_by_page: dict[int, list[tuple[int, bytes]]] = {}
    for patch_address, patch in patched_instruction_bytes(database).items():
        instruction_patches_by_page.setdefault(patch_address & ~0xFFF, []).append(
            (patch_address, patch)
        )

    def sanitize_page(address: int, data: bytes) -> bytes:
        relevant = instruction_patches_by_page.get(address, ())
        if not relevant:
            return data
        result = bytearray(data)
        for patch_address, patch in relevant:
            offset = patch_address - address
            result[offset : offset + len(patch)] = patch
        return bytes(result)

    generator.MODEL_PAGE_SANITIZER = sanitize_page
    generator.MODEL_ZERO_PAGES = (
        {0xF1000000000D8000, 0xF1000000000E3000}
        | (stack_pages - checkpoint_pages)
    )
    generator.write_private_model(
        args.model_output,
        checkpoint,
        database,
        sorted(
            checkpoint_pages
            | stack_pages
            | image_pages
            | generator.MODEL_ZERO_PAGES
        ),
        binary_hash,
        {},
    )
    print(
        "fairplay_bootstrap_cfg_generated=1 "
        f"blocks={len(blocks)} events={stop_index} stop={stop_pc:#x} "
        f"go={args.go_output} model={args.model_output}"
    )


if __name__ == "__main__":
    main()
