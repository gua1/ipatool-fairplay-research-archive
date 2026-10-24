"""Replay FairPlayIOKit's selector-0x15 versioned command in memory.

No target code is executed natively: :class:`ida_static_arm64.Evaluator`
interprets the command dispatcher while this driver models only allocation,
deallocation, and fixed clock plumbing.  Build profiles are provided for the
symbol-rich macOS 25G83 fileset entry and the stripped iOS 23E246 kext
extracted from the exact IPSW.  The defaults reproduce the first selector-
0x15 request reached by the exact iOS 23E246 fairplayd replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from ida_static_arm64 import Evaluator, _target_name
from raw_macho_db import RawMachODatabase


RUN_VERSIONED_IMPL = 0xFFFFFE0009DC6868
MACOS_26A428_RUN_VERSIONED_IMPL = 0xFFFFFE000A56CA80
MACOS_26B118_RUN_VERSIONED_IMPL = 0xFFFFFE000A5EFA5C
KERNEL_COLLECTION_BASE = 0xFFFFFE0007004000

IOS_23E246_RUN_VERSIONED_IMPL = 0xFFFFFFF00988A914
IOS_23E246_FP_MESSAGE_IMPL = 0xFFFFFFF0098B9488
IOS_23E246_FP_CLIENT_INIT_IMPL = 0xFFFFFFF009923FE0
IOS_23E246_KERNEL_COLLECTION_BASE = 0xFFFFFFF007004000
IOS_23E246_EXTERNAL_NAMES = {
    0xFFFFFFF00AD63E5C: "_IOMallocAligned",
    0xFFFFFFF00AD64510: "_IOMallocTypeImpl",
    0xFFFFFFF00AD64A24: "_IOMallocTypeVarImpl",
    0xFFFFFFF00AD64B54: "_IOFreeTypeVarImpl",
    0xFFFFFFF00AD64BF4: "_IOMallocTypeVarExternalImpl",
    0xFFFFFFF00AD64C0C: "_IOFreeTypeVarExternalImpl",
    0xFFFFFFF00A847920: "_random",
    0xFFFFFFF00ABB3A70: "_sysctlbyname",
    0xFFFFFFF00A67A1DC: "_clock_get_calendar_microtime",
    0xFFFFFFF00AD6470C: "_IOFreeTypeImpl",
    0xFFFFFFF00AD63E78: "_IOFreeAligned",
    0xFFFFFFF00AD94EAC: (
        "__ZN9IOService15serviceMatchingEPKcP12OSDictionary"
    ),
    0xFFFFFFF00AD936D8: (
        "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec"
    ),
    0xFFFFFFF00ADC8958: (
        "__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm"
    ),
    0xFFFFFFF00A63CAF0: "_memmove",
    0xFFFFFFF00A63CD50: "_memset",
    0xFFFFFFF00AD64E30: "_IOLog",
}

IOS_17_21A329_RUN_VERSIONED_IMPL = 0xFFFFFFF0294DC6F4
IOS_17_21A329_KERNEL_COLLECTION_BASE = 0xFFFFFFF027004000
IOS_17_21A329_EXTERNAL_NAMES = {
    0xFFFFFFF02830E9B0: "_IOMallocAligned",
    0xFFFFFFF02830F028: "_IOMallocTypeImpl",
    0xFFFFFFF02830F21C: "_IOFreeTypeImpl",
    0xFFFFFFF02830E9CC: "_IOFreeAligned",
}

IOS_18_22G100_RUN_VERSIONED_IMPL = 0xFFFFFFF009E12B10
IOS_18_22G100_FP_MESSAGE_IMPL = 0xFFFFFFF009E19C28
IOS_18_22G100_FP_CLIENT_INIT_IMPL = 0xFFFFFFF009E18950
IOS_18_22G100_KERNEL_COLLECTION_BASE = 0xFFFFFFF007004000
IOS_18_22G100_EXTERNAL_NAMES = {
    0xFFFFFFF0081009F0: "_memmove",
    0xFFFFFFF008100C20: "_memset",
    0xFFFFFFF008106B70: "_strlen",
    0xFFFFFFF0081290A4: "_ipc_port_release_send",
    0xFFFFFFF00816AC48: "_host_get_special_port",
    0xFFFFFFF00816AE40: "_host_priv_self",
    0xFFFFFFF00816ECD0: "_mach_msg_rpc_from_kernel_proper",
    0xFFFFFFF00816EDC4: "_mig_get_reply_port",
    0xFFFFFFF00813A510: "_clock_get_calendar_microtime",
    # Fast-path mutex acquisition in XNU's lock_mtx.c.  The routine stores
    # the current thread ID at lock + 8 when the owner word is zero and only
    # enters the contended slow path otherwise.  Offline replay is
    # single-threaded, so model the uncontended path explicitly below.
    0xFFFFFFF00817D214: "_lck_mtx_lock",
    0xFFFFFFF00817DF6C: "_lck_mtx_unlock",
    0xFFFFFFF00817F328: "_IORWLockWrite",
    0xFFFFFFF008180038: "_IORWLockUnlock",
    0xFFFFFFF0082275D8: "_kmem_alloc",
    0xFFFFFFF008228B2C: "_kmem_free",
    0xFFFFFFF008238DA4: "_vm_map_wire",
    0xFFFFFFF008238E10: "_vm_map_unwire",
    0xFFFFFFF00823BCD0: "_vm_map_copyout",
    0xFFFFFFF00823BCF4: "_vm_map_copyin",
    0xFFFFFFF0082828F8: "_vm_deallocate",
    0xFFFFFFF0082A0B48: "_read_random",
    0xFFFFFFF0087C4250: "_IOMallocAligned",
    0xFFFFFFF0087C426C: "_IOFreeAligned",
    0xFFFFFFF0087C4918: "_IOMallocTypeImpl",
    0xFFFFFFF0087C4AF8: "_IOFreeTypeImpl",
    0xFFFFFFF0087C4E18: "_IOMallocTypeVarImpl",
    0xFFFFFFF0087C4EB0: "_IOFreeTypeVarImpl",
    0xFFFFFFF0087C4F00: "_IOMallocTypeVarExternalImpl",
    0xFFFFFFF0087C4F18: "_IOFreeTypeVarExternalImpl",
    0xFFFFFFF0087C5134: "_IOLog",
    0xFFFFFFF0087C57C4: "_IOLockAlloc",
    0xFFFFFFF0087C5BE8: "_IORWLockAlloc",
    0xFFFFFFF0082E58A4: "_random",
    0xFFFFFFF00863A198: "_sysctlbyname",
    0xFFFFFFF0087F836C: (
        "__ZN9IOService15serviceMatchingEPKcP12OSDictionary"
    ),
    0xFFFFFFF0087F69A8: (
        "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec"
    ),
    0xFFFFFFF00882DF40: (
        "__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm"
    ),
    0xFFFFFFF00882E4D0: (
        "__ZN24IOBufferMemoryDescriptor9withBytesEPKvmjb"
    ),
}

BUILD_PROFILES: dict[str, dict[str, Any]] = {
    "macos-25G83": {
        "binary": Path("artifacts/fairplay/FairPlayIOKit-arm64e-25G83"),
        "run_versioned_impl": RUN_VERSIONED_IMPL,
        "kernel_collection_base": KERNEL_COLLECTION_BASE,
        "external_names": {},
    },
    "macos-26A428": {
        "binary": Path("artifacts/fairplay/FairPlayIOKit-arm64e-26A428"),
        "run_versioned_impl": MACOS_26A428_RUN_VERSIONED_IMPL,
        "kernel_collection_base": KERNEL_COLLECTION_BASE,
        "external_names": {},
    },
    "macos-26B118": {
        "binary": Path(
            "artifacts/fairplay/macos-26B118-kernel/kexts/"
            "com.apple.driver.FairPlayIOKit"
        ),
        "run_versioned_impl": MACOS_26B118_RUN_VERSIONED_IMPL,
        "kernel_collection_base": KERNEL_COLLECTION_BASE,
        "external_names": {},
    },
    "ios-23E246": {
        "binary": Path(
            "artifacts/fairplay/fairplayiokit-ios-23E246-release/"
            "com.apple.driver.FairPlayIOKit"
        ),
        "run_versioned_impl": IOS_23E246_RUN_VERSIONED_IMPL,
        "fp_message_impl": IOS_23E246_FP_MESSAGE_IMPL,
        "fp_client_init_impl": IOS_23E246_FP_CLIENT_INIT_IMPL,
        "version": 0x4B130000,
        "protocol_capabilities": 0x1F8,
        "monotonic_clock_size": 16,
        "kernel_collection_base": IOS_23E246_KERNEL_COLLECTION_BASE,
        "external_names": IOS_23E246_EXTERNAL_NAMES,
    },
    "ios17-21A329": {
        "binary": Path(
            "artifacts/fairplay/fairplayiokit-ios17-21A329-release/"
            "com.apple.driver.FairPlayIOKit"
        ),
        "run_versioned_impl": IOS_17_21A329_RUN_VERSIONED_IMPL,
        "kernel_collection_base": IOS_17_21A329_KERNEL_COLLECTION_BASE,
        "external_names": IOS_17_21A329_EXTERNAL_NAMES,
    },
    "ios18-22G100": {
        "binary": Path(
            "artifacts/fairplay/fairplayiokit-ios18-22G100-release/"
            "com.apple.driver.FairPlayIOKit"
        ),
        "run_versioned_impl": IOS_18_22G100_RUN_VERSIONED_IMPL,
        "fp_message_impl": IOS_18_22G100_FP_MESSAGE_IMPL,
        "fp_client_init_impl": IOS_18_22G100_FP_CLIENT_INIT_IMPL,
        "provider_init_impls": (
            0xFFFFFFF009D360CC,
            0xFFFFFFF009E13EB0,
            0xFFFFFFF009DED0E0,
        ),
        "version": 0x4A1C0000,
        "protocol_capabilities": 0x1F8,
        "monotonic_clock_size": 4,
        "kernel_collection_base": IOS_18_22G100_KERNEL_COLLECTION_BASE,
        "external_names": IOS_18_22G100_EXTERNAL_NAMES,
    },
}

SYNTHETIC_SP = 0xFFFFFE1000100000
SYNTHETIC_INPUT = 0xFFFFFE1000200000
SYNTHETIC_OUTPUT_AUX = 0xFFFFFE1000300000
SYNTHETIC_OUTPUT_DATA = 0xFFFFFE1000400000
SYNTHETIC_OUTPUT_LENGTH = 0xFFFFFE1000500000
SYNTHETIC_FP_MESSAGE = 0xFFFFFE1000600000
SYNTHETIC_FP_STATE = 0xFFFFFE1000700000
SYNTHETIC_ALLOCATION_BASE = 0xFFFFFE1001000000
SYNTHETIC_ALLOCATION_STRIDE = 0x100000
SYNTHETIC_TASK = 0x12345678

# Opaque IOKit objects used only to preserve the object/vtable ABI around the
# IOAESAccelerator service.  The sentinel targets are outside every analyzed
# image and are intercepted before target-code execution.
SYNTHETIC_IO_MATCHING = 0xFFFFFEF000100000
SYNTHETIC_AES_SERVICE = 0xFFFFFEF000200000
SYNTHETIC_AES_VTABLE = 0xFFFFFEF000300000
SYNTHETIC_IO_BUFFER_VTABLE = 0xFFFFFEF000400000
SYNTHETIC_AES_SENTINEL = 0xFFFFFEF100000000
FP3000_KNOWN_INPUT_SHA256 = (
    "eb0142a24df5e282e10d02516dee8dc7d06250b9ca2f925d5b995a4e642a3779"
)
FP3000_KNOWN_IV_SHA256 = (
    "9641196cbf41f5a525f5d14e9d1933766c0a6ce65defe87dbfb650851a29d34e"
)
FP3000_KNOWN_OUTPUT_SHA256 = (
    "a69d982d3e2cb9f75427debf56c25805d4d0f78bab5de19fb966abb7fa0fdd07"
)
SYNTHETIC_IO_BUFFER_SENTINEL = 0xFFFFFEF200000000

DEFAULT_AUX = bytes.fromhex("00000000ee408aed9ded39fe060537b816875967")
DEFAULT_INPUT = bytes.fromhex("5817645ddc55fe54031c44a84e9b4d0f")

ALLOCATION_NAMES = frozenset(
    {
        "_IOMalloc",
        "_IOMallocAligned",
        "_IOMallocData",
        "_IOMallocTypeImpl",
        "_IOMallocTypeVarImpl",
        "_IOMallocTypeVarExternalImpl",
    }
)
FREE_NAMES = frozenset(
    {
        "_IOFreeTypeImpl",
        "_IOFreeTypeVarImpl",
        "_IOFreeTypeVarExternalImpl",
        "_IOFreeAligned",
        "_IOFreeData",
    }
)


def nm_names(path: Path) -> dict[int, str]:
    output = subprocess.run(
        ["nm", "-nm", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names: dict[int, str] = {}
    for line in output.splitlines():
        match = re.match(r"^([0-9a-fA-F]{16}) .* (\S+)$", line)
        if match:
            names[int(match.group(1), 16)] = match.group(2)
    return names


def read_cbytes(evaluator: Evaluator, address: int, limit: int = 256) -> bytes:
    data = bytearray()
    for offset in range(limit):
        byte = evaluator.read_mem(address + offset, 1)
        if byte == 0:
            break
        data.append(byte)
    return bytes(data)


def run_versioned(
    db: Any,
    *,
    command: int,
    token0: int,
    token1: int,
    auxiliary: bytes,
    input_data: bytes,
    monotonic_clock: bytes,
    calendar_seconds: int,
    calendar_microseconds: int,
    trace_dataflow: bool = False,
    trace_static_reads: bool = False,
    probe_addresses: tuple[int, ...] = (),
    probe_register_overrides: dict[int, dict[str, int]] | None = None,
    run_versioned_impl: int = RUN_VERSIONED_IMPL,
    kernel_collection_base: int = KERNEL_COLLECTION_BASE,
    return_evaluator: bool = False,
    initial_memory: dict[int, int] | None = None,
    allocation_base: int = SYNTHETIC_ALLOCATION_BASE,
    task: int = SYNTHETIC_TASK,
    extra_memory_watch_ranges: tuple[tuple[int, int], ...] = (),
    register_watch_names: tuple[str, ...] = (),
    hardware_aes_mode: str = "passthrough",
    hardware_aes_output: bytes | None = None,
) -> dict[str, Any]:
    if len(auxiliary) != 20:
        raise ValueError("the auxiliary field must contain exactly 20 bytes")
    if len(input_data) > 0x200:
        raise ValueError("the versioned-command input exceeds 0x200 bytes")
    if not 0 < len(monotonic_clock) <= 0x100:
        raise ValueError("kern.monotonicclock must contain 1..256 bytes")
    if hardware_aes_mode not in {"passthrough", "zero", "xor-ff", "counter"}:
        raise ValueError(f"unsupported hardware AES mode {hardware_aes_mode!r}")
    if hardware_aes_output is not None and hardware_aes_mode != "passthrough":
        raise ValueError(
            "an explicit hardware AES output cannot be combined with a "
            "synthetic hardware AES mode"
        )

    memory_watch_ranges: list[tuple[int, int]] = []
    if trace_dataflow:
        memory_watch_ranges.extend(
            (
                (SYNTHETIC_INPUT, SYNTHETIC_INPUT + 0x228),
                (SYNTHETIC_OUTPUT_AUX, SYNTHETIC_OUTPUT_AUX + 20),
                (SYNTHETIC_OUTPUT_DATA, SYNTHETIC_OUTPUT_DATA + 0x200),
                (SYNTHETIC_OUTPUT_LENGTH, SYNTHETIC_OUTPUT_LENGTH + 4),
                (
                    SYNTHETIC_ALLOCATION_BASE,
                    SYNTHETIC_ALLOCATION_BASE + 0x20000000,
                ),
            )
        )
    if trace_static_reads:
        memory_watch_ranges.append((db.minimum_ea, db.maximum_ea))
    memory_watch_ranges.extend(extra_memory_watch_ranges)

    evaluator = Evaluator(
        db,
        args=(
            task,
            command,
            token0,
            token1,
            SYNTHETIC_INPUT + 0xC,
            SYNTHETIC_INPUT + 0x20,
            len(input_data),
            SYNTHETIC_OUTPUT_AUX,
        ),
        sp=SYNTHETIC_SP,
        chained_pointer_base=kernel_collection_base,
        recent_pc_limit=32,
        memory_watch_ranges=tuple(memory_watch_ranges),
        register_watch_names=register_watch_names,
    )
    if initial_memory is not None:
        evaluator.memory.update(initial_memory)

    input_structure = bytearray(0x228)
    input_structure[0:4] = command.to_bytes(4, "little")
    input_structure[4:8] = token0.to_bytes(4, "little")
    input_structure[8:12] = token1.to_bytes(4, "little")
    input_structure[0xC:0x20] = auxiliary
    input_structure[0x20 : 0x20 + len(input_data)] = input_data
    input_structure[0x220:0x224] = len(input_data).to_bytes(4, "little")
    for offset, byte in enumerate(input_structure):
        evaluator.write_mem(SYNTHETIC_INPUT + offset, byte, 1)

    # qtQQt tail-calls the implementation after shifting stack arguments: the
    # output-data pointer and output-length pointer occupy the first two slots.
    evaluator.write_mem(SYNTHETIC_SP, SYNTHETIC_OUTPUT_DATA, 8)
    evaluator.write_mem(SYNTHETIC_SP + 8, SYNTHETIC_OUTPUT_LENGTH, 8)
    evaluator.write_mem(SYNTHETIC_OUTPUT_LENGTH, 0x200, 4)
    evaluator.memory_accesses.clear()

    pc = run_versioned_impl
    next_allocation = allocation_base
    random_state = 0x12345678
    stages: list[dict[str, Any]] = []
    hardware_aes_events: list[dict[str, Any]] = []
    io_descriptors: dict[int, tuple[int, int]] = {}

    for slot in range(512):
        evaluator.write_mem(
            SYNTHETIC_AES_VTABLE + slot * 8,
            SYNTHETIC_AES_SENTINEL + slot,
            8,
        )
        evaluator.write_mem(
            SYNTHETIC_IO_BUFFER_VTABLE + slot * 8,
            SYNTHETIC_IO_BUFFER_SENTINEL + slot,
            8,
        )
    evaluator.write_mem(SYNTHETIC_AES_SERVICE, SYNTHETIC_AES_VTABLE, 8)

    def allocate_sparse(size: int) -> int:
        nonlocal next_allocation
        address = next_allocation
        next_allocation += max(
            SYNTHETIC_ALLOCATION_STRIDE,
            (size + SYNTHETIC_ALLOCATION_STRIDE - 1)
            & ~(SYNTHETIC_ALLOCATION_STRIDE - 1),
        )
        return address

    def make_io_descriptor(backing: int, size: int) -> int:
        descriptor = allocate_sparse(0x1000)
        evaluator.write_mem(descriptor, SYNTHETIC_IO_BUFFER_VTABLE, 8)
        io_descriptors[descriptor] = (backing, size)
        return descriptor

    probe_events: list[dict[str, Any]] = []
    effective_probe_addresses = frozenset(probe_addresses) | frozenset(
        (probe_register_overrides or {}).keys()
    )
    for index in range(500):
        stop = evaluator.run(
            pc,
            max_instructions=50_000_000,
            follow_internal_transfers=True,
            breakpoints=effective_probe_addresses,
        )
        target_name = _target_name(db, stop.target)
        args = [evaluator.regs[f"x{register}"] for register in range(8)]
        stages.append(
            {
                "index": index,
                "reason": stop.reason,
                "site": hex(stop.address),
                "mnemonic": stop.mnemonic,
                "target": hex(stop.target) if stop.target is not None else None,
                "target_name": target_name,
                "instructions": stop.instructions,
                "args": [hex(value) for value in args],
                "recent_pcs": [hex(address) for address in evaluator.recent_pcs],
            }
        )

        if stop.reason == "breakpoint" and stop.address in effective_probe_addresses:
            overrides = (probe_register_overrides or {}).get(stop.address, {})
            probe_events.append(
                {
                    "address": hex(stop.address),
                    "registers": {
                        name: hex(value) for name, value in stop.registers.items()
                    },
                    "vector_registers": {
                        f"v{index}": hex(evaluator.regs.get(f"v{index}", 0))
                        for index in range(32)
                    },
                    "register_overrides": {
                        name: hex(value) for name, value in overrides.items()
                    },
                }
            )
            for name, value in overrides.items():
                if name.startswith("w") and name[1:].isdigit():
                    evaluator.regs[f"x{name[1:]}"] = value & 0xFFFFFFFF
                elif name in evaluator.regs:
                    evaluator.regs[name] = value & ((1 << 64) - 1)
                else:
                    raise ValueError(f"unknown probe register {name!r}")
            pc = stop.address
            continue

        if stop.reason == "return" and stop.target in (None, 0):
            break

        call_like = stop.mnemonic.startswith(("bl", "blr"))
        resume = stop.address + 4 if call_like else evaluator.regs["x30"]

        if target_name in ("_IOMalloc", "_IOMallocAligned", "_IOMallocData"):
            size = args[0]
            evaluator.regs["x0"] = next_allocation
            next_allocation += (size + 0xFFFF) & ~0xFFFF
        elif target_name in (
            "_IOMallocTypeImpl",
            "_IOMallocTypeVarImpl",
            "_IOMallocTypeVarExternalImpl",
        ):
            # Current XNU call sites pass a kalloc type descriptor in x0.  Its
            # encoded allocation size is not an x1 argument; x1 is simply a
            # stale caller register and can even be zero or a prior allocation
            # address.  Every modeled call only needs a distinct sparse range,
            # so keep them a generous fixed distance apart.
            evaluator.regs["x0"] = next_allocation
            next_allocation += SYNTHETIC_ALLOCATION_STRIDE
        elif target_name in (
            "_IOFreeTypeImpl",
            "_IOFreeTypeVarImpl",
            "_IOFreeTypeVarExternalImpl",
            "_IOFreeAligned",
            "_IOFreeData",
        ):
            pass
        elif target_name == "_sysctlbyname":
            sysctl_name = read_cbytes(evaluator, args[0]).decode("ascii", "replace")
            if sysctl_name != "kern.monotonicclock":
                raise RuntimeError(f"unexpected sysctl {sysctl_name!r}")
            capacity = evaluator.read_mem(args[2], 8)
            if capacity < len(monotonic_clock):
                raise RuntimeError("kern.monotonicclock output buffer is too small")
            for offset, byte in enumerate(monotonic_clock):
                evaluator.write_mem(args[1] + offset, byte, 1)
            evaluator.write_mem(args[2], len(monotonic_clock), 8)
            evaluator.regs["x0"] = 0
            stages[-1]["sysctl_name"] = sysctl_name
            stages[-1]["modeled_size"] = len(monotonic_clock)
        elif target_name == "_clock_get_calendar_microtime":
            evaluator.write_mem(args[0], calendar_seconds, 8)
            evaluator.write_mem(args[1], calendar_microseconds, 4)
            stages[-1]["modeled_seconds"] = calendar_seconds
            stages[-1]["modeled_microseconds"] = calendar_microseconds
        elif target_name == "_IOLog":
            # Diagnostic-only kernel logging has no dataflow effect on the
            # selector result.  Preserve the call in the stage report and
            # continue without rendering potentially sensitive arguments.
            stages[-1]["modeled_diagnostic_log"] = True
        elif target_name == "_memmove":
            if args[2] > 0x1000000:
                raise RuntimeError(f"unreasonable memmove size {args[2]:#x}")
            moved = bytes(
                evaluator.read_mem(args[1] + offset, 1)
                for offset in range(args[2])
            )
            for offset, byte in enumerate(moved):
                evaluator.write_mem(args[0] + offset, byte, 1)
            evaluator.regs["x0"] = args[0]
        elif target_name == "_memset":
            if args[2] > 0x1000000:
                raise RuntimeError(f"unreasonable memset size {args[2]:#x}")
            for offset in range(args[2]):
                evaluator.write_mem(args[0] + offset, args[1] & 0xFF, 1)
            evaluator.regs["x0"] = args[0]
        elif target_name == "_lck_mtx_lock":
            owner_address = args[0] + 8
            owner = evaluator.read_mem(owner_address, 4)
            if owner != 0:
                raise RuntimeError(
                    "modeled lck_mtx_lock encountered a contended mutex: "
                    f"lock={args[0]:#x}, owner={owner:#x}"
                )
            # The real fast path stores the current thread's 28-bit ID.  Its
            # precise value is opaque to FairPlayIOKit; a stable nonzero owner
            # preserves the lock invariant until the matching unlock.
            evaluator.write_mem(owner_address, 1, 4)
            stages[-1]["modeled_owner"] = "0x1"
        elif target_name == "_lck_mtx_unlock":
            owner_address = args[0] + 8
            owner = evaluator.read_mem(owner_address, 4)
            if owner == 0:
                raise RuntimeError(
                    "modeled lck_mtx_unlock encountered an unlocked mutex: "
                    f"lock={args[0]:#x}"
                )
            evaluator.write_mem(owner_address, 0, 4)
            stages[-1]["released_owner"] = hex(owner)
        elif target_name and "serviceMatching" in target_name:
            stages[-1]["service_name"] = read_cbytes(
                evaluator, args[0]
            ).decode("ascii", "replace")
            evaluator.regs["x0"] = SYNTHETIC_IO_MATCHING
        elif target_name and "waitForService" in target_name:
            evaluator.regs["x0"] = SYNTHETIC_AES_SERVICE
        elif target_name and "IOBufferMemoryDescriptor17inTaskWithOptions" in target_name:
            backing = allocate_sparse(args[2])
            evaluator.regs["x0"] = make_io_descriptor(backing, args[2])
            stages[-1]["modeled_backing"] = hex(backing)
            stages[-1]["modeled_size"] = args[2]
        elif target_name and "IOBufferMemoryDescriptor9withBytes" in target_name:
            evaluator.regs["x0"] = make_io_descriptor(args[0], args[1])
            stages[-1]["modeled_backing"] = hex(args[0])
            stages[-1]["modeled_size"] = args[1]
        elif (
            SYNTHETIC_IO_BUFFER_SENTINEL
            <= (stop.target or 0)
            < SYNTHETIC_IO_BUFFER_SENTINEL + 512
        ):
            slot = (stop.target or 0) - SYNTHETIC_IO_BUFFER_SENTINEL
            descriptor = io_descriptors.get(args[0])
            stages[-1]["io_buffer_vcall_slot"] = slot
            if descriptor is None:
                raise RuntimeError(
                    "IOBufferMemoryDescriptor vcall used an unknown object: "
                    f"{args[0]:#x}"
                )
            backing, size = descriptor
            # Slot 41 is getBytesNoCopy() on this exact build.  prepare(),
            # complete(), retain(), and release() can all return success in a
            # single-threaded sparse-memory replay.
            evaluator.regs["x0"] = backing if slot == 41 else 0
            stages[-1]["modeled_backing"] = hex(backing)
            stages[-1]["modeled_size"] = size
        elif (
            SYNTHETIC_AES_SENTINEL
            <= (stop.target or 0)
            < SYNTHETIC_AES_SENTINEL + 512
        ):
            slot = (stop.target or 0) - SYNTHETIC_AES_SENTINEL
            stages[-1]["aes_service_vcall_slot"] = slot
            input_descriptor = io_descriptors.get(args[1])
            output_descriptor = io_descriptors.get(args[2])
            if input_descriptor is not None and output_descriptor is not None:
                input_backing, input_capacity = input_descriptor
                output_backing, output_capacity = output_descriptor
                length = args[3]
                if length > input_capacity or length > output_capacity:
                    raise RuntimeError(
                        "IOAESAccelerator request exceeds descriptor capacity: "
                        f"length={length:#x}, input={input_capacity:#x}, "
                        f"output={output_capacity:#x}"
                    )
                aes_input = bytes(
                    evaluator.read_mem(input_backing + offset, 1)
                    for offset in range(length)
                )
                if hardware_aes_output is not None:
                    if len(hardware_aes_output) != length:
                        raise ValueError(
                            "the explicit hardware AES output has the wrong "
                            f"length: expected {length}, got "
                            f"{len(hardware_aes_output)}"
                        )
                    aes_output = hardware_aes_output
                    effective_hardware_aes_mode = "explicit-output"
                elif hardware_aes_mode == "zero":
                    aes_output = bytes(length)
                    effective_hardware_aes_mode = hardware_aes_mode
                elif hardware_aes_mode == "xor-ff":
                    aes_output = bytes(byte ^ 0xFF for byte in aes_input)
                    effective_hardware_aes_mode = hardware_aes_mode
                elif hardware_aes_mode == "counter":
                    aes_output = bytes(index & 0xFF for index in range(length))
                    effective_hardware_aes_mode = hardware_aes_mode
                else:
                    aes_output = aes_input
                    effective_hardware_aes_mode = hardware_aes_mode
                for offset, byte in enumerate(aes_output):
                    evaluator.write_mem(output_backing + offset, byte, 1)
                event = {
                    "slot": slot,
                    "mode": effective_hardware_aes_mode,
                    "length": length,
                    "operation": hex(args[5]),
                    "iv": bytes(
                        evaluator.read_mem(args[4] + offset, 1)
                        for offset in range(16)
                    ).hex(),
                    "key_data": bytes(
                        evaluator.read_mem(args[6] + offset, 1)
                        for offset in range(32)
                    ).hex(),
                    "input": aes_input.hex(),
                    "output": aes_output.hex(),
                }
                hardware_aes_events.append(event)
                stages[-1]["hardware_aes_event"] = len(hardware_aes_events) - 1
            evaluator.regs["x0"] = 0
        elif target_name == "_read_random":
            # XNU's read_random(void *, u_int) fills the caller's buffer and
            # has no meaningful return value.  A deterministic byte stream
            # keeps offline runs reproducible while preserving the real data
            # dependency between selector 0x1a and the daemon's next request.
            for offset in range(args[1]):
                random_state = (
                    1664525 * random_state + 1013904223
                ) & 0x7FFFFFFF
                evaluator.write_mem(args[0] + offset, random_state >> 23, 1)
        elif target_name == "_random":
            random_state = (
                1664525 * random_state + 1013904223
            ) & 0x7FFFFFFF
            evaluator.regs["x0"] = random_state
        else:
            break

        evaluator.regs["x30"] = resume
        pc = resume
    else:
        raise RuntimeError("versioned-command trace exceeded its stage limit")

    output_length = evaluator.read_mem(SYNTHETIC_OUTPUT_LENGTH, 4)
    if output_length > 0x200:
        raise RuntimeError(f"invalid output length {output_length:#x}")
    output_auxiliary = bytes(
        evaluator.read_mem(SYNTHETIC_OUTPUT_AUX + offset, 1)
        for offset in range(20)
    )
    output_data = bytes(
        evaluator.read_mem(SYNTHETIC_OUTPUT_DATA + offset, 1)
        for offset in range(output_length)
    )
    completed = bool(
        stages
        and stages[-1]["reason"] == "return"
        and stages[-1]["target"] in (None, "0x0")
    )
    result = {
        "input": {
            "command": hex(command),
            "token0": hex(token0),
            "token1": hex(token1),
            "auxiliary": auxiliary.hex(),
            "data": input_data.hex(),
        },
        "completed": completed,
        "status": hex(evaluator.regs["x0"] & 0xFFFFFFFF),
        "output_auxiliary": output_auxiliary.hex(),
        "output_length": output_length,
        "output_data": output_data.hex(),
        "stages": stages,
    }
    if probe_events:
        result["probe_events"] = probe_events
    if hardware_aes_events:
        result["hardware_aes_events"] = hardware_aes_events
    if trace_dataflow:
        state = bytearray(input_data)
        state_snapshots = [
            {
                "index": 0,
                "state": bytes(state).hex(),
                "write_pcs": [],
            }
        ]
        touched_offsets: set[int] = set()
        write_pcs: list[str] = []
        for access in evaluator.memory_accesses:
            if access["operation"] != "write":
                continue
            access_start = access["address"]
            access_end = access_start + access["size"]
            state_start = SYNTHETIC_INPUT + 0x20
            state_end = state_start + len(input_data)
            overlap_start = max(access_start, state_start)
            overlap_end = min(access_end, state_end)
            if overlap_start >= overlap_end:
                continue
            for address in range(overlap_start, overlap_end):
                value_offset = address - access_start
                state_offset = address - state_start
                state[state_offset] = (access["value"] >> (8 * value_offset)) & 0xFF
                touched_offsets.add(state_offset)
            write_pcs.append(hex(access["pc"]))
            if len(touched_offsets) == len(input_data):
                state_snapshots.append(
                    {
                        "index": len(state_snapshots),
                        "state": bytes(state).hex(),
                        "write_pcs": sorted(set(write_pcs)),
                    }
                )
                touched_offsets.clear()
                write_pcs.clear()
        result["input_state_snapshots"] = state_snapshots
    if trace_dataflow or trace_static_reads or extra_memory_watch_ranges:
        result["memory_accesses"] = [
            {
                **access,
                "pc": hex(access["pc"]),
                "address": hex(access["address"]),
                "value": hex(access["value"]),
            }
            for access in evaluator.memory_accesses
        ]
    if return_evaluator:
        # Programmatic chained-operation drivers can reuse the kernel-global
        # and allocation overlay established by command 2.  CLI callers leave
        # this disabled because an Evaluator is intentionally not JSON data.
        result["_evaluator"] = evaluator
        result["_next_allocation"] = next_allocation
    if register_watch_names:
        result["register_accesses"] = [
            {
                **access,
                "pc": hex(access["pc"]),
                "value": hex(access["value"]),
            }
            for access in evaluator.register_accesses
        ]
    return result


def run_fp_client_init(
    db: Any,
    *,
    state: bytes = bytes(0x2000),
    client_type: int = 0,
    task: int = SYNTHETIC_TASK,
    fp_client_init_impl: int = IOS_23E246_FP_CLIENT_INIT_IMPL,
    kernel_collection_base: int = IOS_23E246_KERNEL_COLLECTION_BASE,
    return_evaluator: bool = False,
    initial_memory: dict[int, int] | None = None,
    allocation_base: int = SYNTHETIC_ALLOCATION_BASE,
) -> dict[str, Any]:
    """Replay the provider's per-user-client initialization core.

    The ``IOUserClient::start`` path clears its embedded state pointer and then
    calls this implementation with ``state``, a client-type flag, and the
    owning task.  The allocation and its task binding are persistent inputs to
    the later selector-0x1a and selector-0x15 provider methods.
    """

    evaluator = Evaluator(
        db,
        args=(SYNTHETIC_FP_STATE, client_type, task),
        sp=SYNTHETIC_SP,
        chained_pointer_base=kernel_collection_base,
        recent_pc_limit=32,
    )
    if initial_memory is not None:
        evaluator.memory.update(initial_memory)
    for offset, byte in enumerate(state):
        evaluator.write_mem(SYNTHETIC_FP_STATE + offset, byte, 1)

    pc = fp_client_init_impl
    next_allocation = allocation_base
    stages: list[dict[str, Any]] = []
    for index in range(500):
        stop = evaluator.run(
            pc,
            max_instructions=100_000_000,
            follow_internal_transfers=True,
        )
        target_name = _target_name(db, stop.target)
        args = [evaluator.regs[f"x{register}"] for register in range(8)]
        stages.append(
            {
                "index": index,
                "reason": stop.reason,
                "site": hex(stop.address),
                "mnemonic": stop.mnemonic,
                "target": hex(stop.target) if stop.target is not None else None,
                "target_name": target_name,
                "instructions": stop.instructions,
                "args": [hex(value) for value in args],
            }
        )
        if stop.reason == "return" and stop.target in (None, 0):
            break

        call_like = stop.mnemonic.startswith(("bl", "blr"))
        resume = stop.address + 4 if call_like else evaluator.regs["x30"]
        if target_name in ALLOCATION_NAMES:
            evaluator.regs["x0"] = next_allocation
            next_allocation += SYNTHETIC_ALLOCATION_STRIDE
        elif target_name in FREE_NAMES:
            pass
        else:
            break
        evaluator.regs["x30"] = resume
        pc = resume
    else:
        raise RuntimeError("FP-client initialization exceeded its stage limit")

    completed = bool(
        stages
        and stages[-1]["reason"] == "return"
        and stages[-1]["target"] in (None, "0x0")
    )
    result = {
        "completed": completed,
        "status": hex(evaluator.regs["x0"] & 0xFFFFFFFF),
        "state": bytes(
            evaluator.read_mem(SYNTHETIC_FP_STATE + offset, 1)
            for offset in range(len(state))
        ).hex(),
        "stages": stages,
    }
    if return_evaluator:
        result["_evaluator"] = evaluator
        result["_next_allocation"] = next_allocation
    return result


def run_fp_provider_init(
    db: Any,
    *,
    init_impls: tuple[int, ...],
    monotonic_clock: bytes,
    calendar_seconds: int,
    calendar_microseconds: int,
    random_seed: int = 0x12345678,
    kernel_collection_base: int = IOS_18_22G100_KERNEL_COLLECTION_BASE,
    return_evaluator: bool = False,
    initial_memory: dict[int, int] | None = None,
    allocation_base: int = SYNTHETIC_ALLOCATION_BASE,
) -> dict[str, Any]:
    """Replay the kext-wide startup routines run before user-client creation."""

    if not 0 < len(monotonic_clock) <= 0x100:
        raise ValueError("kern.monotonicclock must contain 1..256 bytes")
    evaluator = Evaluator(
        db,
        sp=SYNTHETIC_SP,
        chained_pointer_base=kernel_collection_base,
        recent_pc_limit=32,
    )
    if initial_memory is not None:
        evaluator.memory.update(initial_memory)

    next_allocation = allocation_base
    random_state = random_seed & 0x7FFFFFFF
    stages: list[dict[str, Any]] = []
    initializer_results: list[dict[str, Any]] = []
    completed = True

    for init_impl in init_impls:
        evaluator.regs["sp"] = SYNTHETIC_SP
        evaluator.regs["x30"] = 0
        pc = init_impl
        returned = False
        first_stage = len(stages)
        for _ in range(10_000):
            stop = evaluator.run(
                pc,
                max_instructions=100_000_000,
                follow_internal_transfers=True,
            )
            target_name = _target_name(db, stop.target)
            args = [evaluator.regs[f"x{register}"] for register in range(8)]
            stages.append(
                {
                    "index": len(stages),
                    "initializer": hex(init_impl),
                    "reason": stop.reason,
                    "site": hex(stop.address),
                    "mnemonic": stop.mnemonic,
                    "target": (
                        hex(stop.target) if stop.target is not None else None
                    ),
                    "target_name": target_name,
                    "instructions": stop.instructions,
                    "args": [hex(value) for value in args],
                }
            )
            if stop.reason == "return" and stop.target in (None, 0):
                returned = True
                initializer_results.append(
                    {
                        "implementation": hex(init_impl),
                        "status": hex(evaluator.regs["x0"] & 0xFFFFFFFF),
                        "stages": len(stages) - first_stage,
                    }
                )
                break

            call_like = stop.mnemonic.startswith(("bl", "blr"))
            resume = stop.address + 4 if call_like else evaluator.regs["x30"]
            if target_name in ALLOCATION_NAMES or target_name in {
                "_IOLockAlloc",
                "_IORWLockAlloc",
            }:
                evaluator.regs["x0"] = next_allocation
                next_allocation += SYNTHETIC_ALLOCATION_STRIDE
            elif target_name in FREE_NAMES or target_name in {
                "_IOLog",
                "_IORWLockWrite",
                "_IORWLockUnlock",
            }:
                pass
            elif target_name == "_memset":
                if args[2] > 0x1000000:
                    raise RuntimeError(f"unreasonable memset size {args[2]:#x}")
                for offset in range(args[2]):
                    evaluator.write_mem(args[0] + offset, args[1] & 0xFF, 1)
                evaluator.regs["x0"] = args[0]
            elif target_name == "_read_random":
                if args[1] > 0x1000000:
                    raise RuntimeError(
                        f"unreasonable read_random size {args[1]:#x}"
                    )
                for offset in range(args[1]):
                    random_state = (
                        1664525 * random_state + 1013904223
                    ) & 0x7FFFFFFF
                    evaluator.write_mem(
                        args[0] + offset,
                        random_state >> 23,
                        1,
                    )
            elif target_name == "_random":
                random_state = (
                    1664525 * random_state + 1013904223
                ) & 0x7FFFFFFF
                evaluator.regs["x0"] = random_state
            elif target_name == "_sysctlbyname":
                sysctl_name = read_cbytes(evaluator, args[0]).decode(
                    "ascii", "replace"
                )
                if sysctl_name != "kern.monotonicclock":
                    raise RuntimeError(f"unexpected sysctl {sysctl_name!r}")
                capacity = evaluator.read_mem(args[2], 8)
                if capacity < len(monotonic_clock):
                    raise RuntimeError(
                        "kern.monotonicclock output buffer is too small: "
                        f"capacity={capacity:#x}, args="
                        + ",".join(hex(value) for value in args[:5])
                    )
                for offset, byte in enumerate(monotonic_clock):
                    evaluator.write_mem(args[1] + offset, byte, 1)
                evaluator.write_mem(args[2], len(monotonic_clock), 8)
                evaluator.regs["x0"] = 0
            elif target_name == "_clock_get_calendar_microtime":
                evaluator.write_mem(args[0], calendar_seconds, 8)
                evaluator.write_mem(args[1], calendar_microseconds, 4)
            else:
                completed = False
                break

            evaluator.regs["x30"] = resume
            pc = resume
        else:
            raise RuntimeError("FP-provider initialization exceeded its stage limit")

        if not returned:
            completed = False
            break

    result = {
        "completed": completed,
        "initializers": initializer_results,
        "random_state": hex(random_state),
        "stages": stages,
    }
    if return_evaluator:
        result["_evaluator"] = evaluator
        result["_next_allocation"] = next_allocation
    return result


def run_fp_message(
    db: Any,
    *,
    message: bytes,
    state: bytes = bytes(0x2000),
    random_seed: int = 0x12345678,
    fp_message_impl: int = IOS_23E246_FP_MESSAGE_IMPL,
    kernel_collection_base: int = IOS_23E246_KERNEL_COLLECTION_BASE,
    return_evaluator: bool = False,
    initial_memory: dict[int, int] | None = None,
    allocation_base: int = SYNTHETIC_ALLOCATION_BASE,
    fp3000_known_output: bytes | None = None,
) -> dict[str, Any]:
    """Replay the provider core behind selector ``0x1a``/SendFPMessage.

    The user-client wrapper maps the pointed userspace message into the kernel
    and calls this three-argument implementation with ``message``, its length,
    and a persistent per-client state block.  This interpreter models only the
    allocation/free family and ``read_random``; the FairPlay transform itself
    remains target code evaluated from the exact kext.
    """

    synthetic_message = SYNTHETIC_FP_MESSAGE
    synthetic_state = SYNTHETIC_FP_STATE
    if len(state) < 8:
        raise ValueError("the FP client-state field must contain at least 8 bytes")
    if fp3000_known_output is not None and len(fp3000_known_output) != 16:
        raise ValueError("the known FP3000 output must contain exactly 16 bytes")
    if (
        fp3000_known_output is not None
        and hashlib.sha256(fp3000_known_output).hexdigest()
        != FP3000_KNOWN_OUTPUT_SHA256
    ):
        raise ValueError("the known FP3000 output does not match the verified vector")
    provider_state = int.from_bytes(state[:8], "little")
    evaluator = Evaluator(
        db,
        args=(synthetic_message, len(message), provider_state),
        sp=SYNTHETIC_SP,
        chained_pointer_base=kernel_collection_base,
        recent_pc_limit=32,
    )
    if initial_memory is not None:
        evaluator.memory.update(initial_memory)
    for offset, byte in enumerate(message):
        evaluator.write_mem(synthetic_message + offset, byte, 1)
    for offset, byte in enumerate(state):
        evaluator.write_mem(synthetic_state + offset, byte, 1)

    pc = fp_message_impl
    next_allocation = allocation_base
    random_state = random_seed & 0x7FFFFFFF
    stages: list[dict[str, Any]] = []
    io_descriptors: dict[int, tuple[int, int]] = {}
    hardware_aes_events: list[dict[str, Any]] = []

    for slot in range(512):
        evaluator.write_mem(
            SYNTHETIC_AES_VTABLE + slot * 8,
            SYNTHETIC_AES_SENTINEL + slot,
            8,
        )
        evaluator.write_mem(
            SYNTHETIC_IO_BUFFER_VTABLE + slot * 8,
            SYNTHETIC_IO_BUFFER_SENTINEL + slot,
            8,
        )
    evaluator.write_mem(SYNTHETIC_AES_SERVICE, SYNTHETIC_AES_VTABLE, 8)

    def allocate_sparse(size: int) -> int:
        nonlocal next_allocation
        address = next_allocation
        next_allocation += max(
            SYNTHETIC_ALLOCATION_STRIDE,
            (size + SYNTHETIC_ALLOCATION_STRIDE - 1)
            & ~(SYNTHETIC_ALLOCATION_STRIDE - 1),
        )
        return address

    def make_io_descriptor(backing: int, size: int) -> int:
        descriptor = allocate_sparse(0x1000)
        evaluator.write_mem(descriptor, SYNTHETIC_IO_BUFFER_VTABLE, 8)
        io_descriptors[descriptor] = (backing, size)
        return descriptor

    for index in range(500):
        stop = evaluator.run(
            pc,
            max_instructions=100_000_000,
            follow_internal_transfers=True,
        )
        target_name = _target_name(db, stop.target)
        args = [evaluator.regs[f"x{register}"] for register in range(8)]
        stages.append(
            {
                "index": index,
                "reason": stop.reason,
                "site": hex(stop.address),
                "mnemonic": stop.mnemonic,
                "target": hex(stop.target) if stop.target is not None else None,
                "target_name": target_name,
                "instructions": stop.instructions,
                "args": [hex(value) for value in args],
            }
        )
        if stop.reason == "return" and stop.target in (None, 0):
            break

        call_like = stop.mnemonic.startswith(("bl", "blr"))
        resume = stop.address + 4 if call_like else evaluator.regs["x30"]
        if target_name in ALLOCATION_NAMES:
            evaluator.regs["x0"] = next_allocation
            next_allocation += SYNTHETIC_ALLOCATION_STRIDE
        elif target_name in FREE_NAMES:
            pass
        elif target_name == "_read_random":
            for offset in range(args[1]):
                random_state = (
                    1664525 * random_state + 1013904223
                ) & 0x7FFFFFFF
                evaluator.write_mem(args[0] + offset, random_state >> 23, 1)
        elif target_name == "_random":
            random_state = (
                1664525 * random_state + 1013904223
            ) & 0x7FFFFFFF
            evaluator.regs["x0"] = random_state
        elif target_name == "_memmove":
            if args[2] > 0x1000000:
                raise RuntimeError(f"unreasonable memmove size {args[2]:#x}")
            moved = bytes(
                evaluator.read_mem(args[1] + offset, 1)
                for offset in range(args[2])
            )
            for offset, byte in enumerate(moved):
                evaluator.write_mem(args[0] + offset, byte, 1)
            evaluator.regs["x0"] = args[0]
        elif target_name == "_memset":
            if args[2] > 0x1000000:
                raise RuntimeError(f"unreasonable memset size {args[2]:#x}")
            for offset in range(args[2]):
                evaluator.write_mem(args[0] + offset, args[1] & 0xFF, 1)
            evaluator.regs["x0"] = args[0]
        elif target_name == "_IOLog":
            stages[-1]["modeled_diagnostic_log"] = True
        elif target_name and "serviceMatching" in target_name:
            stages[-1]["service_name"] = read_cbytes(
                evaluator, args[0]
            ).decode("ascii", "replace")
            evaluator.regs["x0"] = SYNTHETIC_IO_MATCHING
        elif target_name and "waitForService" in target_name:
            evaluator.regs["x0"] = SYNTHETIC_AES_SERVICE
        elif target_name and "IOBufferMemoryDescriptor17inTaskWithOptions" in target_name:
            backing = allocate_sparse(args[2])
            evaluator.regs["x0"] = make_io_descriptor(backing, args[2])
            stages[-1]["modeled_backing"] = hex(backing)
            stages[-1]["modeled_size"] = args[2]
        elif target_name and "IOBufferMemoryDescriptor9withBytes" in target_name:
            evaluator.regs["x0"] = make_io_descriptor(args[0], args[1])
            stages[-1]["modeled_backing"] = hex(args[0])
            stages[-1]["modeled_size"] = args[1]
        elif (
            SYNTHETIC_IO_BUFFER_SENTINEL
            <= (stop.target or 0)
            < SYNTHETIC_IO_BUFFER_SENTINEL + 512
        ):
            slot = (stop.target or 0) - SYNTHETIC_IO_BUFFER_SENTINEL
            descriptor = io_descriptors.get(args[0])
            if descriptor is None:
                raise RuntimeError(
                    "IOBufferMemoryDescriptor vcall used an unknown object: "
                    f"{args[0]:#x}"
                )
            backing, size = descriptor
            evaluator.regs["x0"] = backing if slot == 41 else 0
            stages[-1]["io_buffer_vcall_slot"] = slot
            stages[-1]["modeled_backing"] = hex(backing)
            stages[-1]["modeled_size"] = size
        elif (
            SYNTHETIC_AES_SENTINEL
            <= (stop.target or 0)
            < SYNTHETIC_AES_SENTINEL + 512
        ):
            slot = (stop.target or 0) - SYNTHETIC_AES_SENTINEL
            input_descriptor = io_descriptors.get(args[1])
            output_descriptor = io_descriptors.get(args[2])
            event: dict[str, Any] = {
                "site": hex(stop.address),
                "slot": slot,
                "length": args[3],
                "arguments_0_7": [hex(value) for value in args],
                "arguments_3_7": [hex(value) for value in args[3:8]],
                "input_descriptor_known": input_descriptor is not None,
                "output_descriptor_known": output_descriptor is not None,
            }
            if args[4] != 0:
                iv_data = bytes(
                    evaluator.read_mem(args[4] + offset, 1)
                    for offset in range(16)
                )
                event["iv_sha256"] = hashlib.sha256(iv_data).hexdigest()
            if args[6] != 0:
                key_data = bytes(
                    evaluator.read_mem(args[6] + offset, 1)
                    for offset in range(44)
                )
                event["key_data_sha256"] = hashlib.sha256(key_data).hexdigest()
                event["key_selector"] = evaluator.read_mem(args[6] + 36, 4)
            if input_descriptor is not None and output_descriptor is not None:
                input_backing, input_capacity = input_descriptor
                output_backing, output_capacity = output_descriptor
                length = args[3]
                if length > input_capacity or length > output_capacity:
                    raise RuntimeError(
                        "IOAESAccelerator request exceeds descriptor capacity"
                    )
                aes_input = bytes(
                    evaluator.read_mem(input_backing + offset, 1)
                    for offset in range(length)
                )
                key_selector = event.get("key_selector")
                if (
                    fp3000_known_output is not None
                    and key_selector == 3000
                    and args[5] == 1
                    and length == 16
                ):
                    if (
                        hashlib.sha256(aes_input).hexdigest()
                        != FP3000_KNOWN_INPUT_SHA256
                        or event.get("iv_sha256") != FP3000_KNOWN_IV_SHA256
                    ):
                        raise RuntimeError(
                            "selector-3000 call does not match the verified input/IV vector"
                        )
                    aes_output = fp3000_known_output
                    event["model"] = "known-fp3000-vector"
                else:
                    aes_output = aes_input
                    event["model"] = "passthrough"
                for offset in range(length):
                    evaluator.write_mem(
                        output_backing + offset,
                        aes_output[offset],
                        1,
                    )
                written_output = bytes(
                    evaluator.read_mem(output_backing + offset, 1)
                    for offset in range(length)
                )
                event.update(
                    {
                        "input_capacity": input_capacity,
                        "output_capacity": output_capacity,
                        "input_sha256": hashlib.sha256(aes_input).hexdigest(),
                        "output_sha256": hashlib.sha256(written_output).hexdigest(),
                    }
                )
            hardware_aes_events.append(event)
            evaluator.regs["x0"] = 0
            stages[-1]["aes_service_vcall_slot"] = slot
            stages[-1]["hardware_aes_event"] = len(hardware_aes_events) - 1
        else:
            break
        evaluator.regs["x30"] = resume
        pc = resume
    else:
        raise RuntimeError("FP-message trace exceeded its stage limit")

    completed = bool(
        stages
        and stages[-1]["reason"] == "return"
        and stages[-1]["target"] in (None, "0x0")
    )
    result = {
        "completed": completed,
        "status": hex(evaluator.regs["x0"] & 0xFFFFFFFF),
        "output_message": bytes(
            evaluator.read_mem(synthetic_message + offset, 1)
            for offset in range(len(message))
        ).hex(),
        "state": bytes(
            evaluator.read_mem(synthetic_state + offset, 1)
            for offset in range(len(state))
        ).hex(),
        "random_state": hex(random_state),
        "stages": stages,
    }
    if hardware_aes_events:
        result["hardware_aes_events"] = hardware_aes_events
    if return_evaluator:
        result["_evaluator"] = evaluator
        result["_next_allocation"] = next_allocation
    return result


def parse_fixed_hex(value: str, size: int, label: str) -> bytes:
    data = bytes.fromhex(value)
    if len(data) != size:
        raise argparse.ArgumentTypeError(
            f"{label} must contain exactly {size} bytes, got {len(data)}"
        )
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--profile",
        choices=sorted(BUILD_PROFILES),
        default="macos-25G83",
        help="known FairPlayIOKit build/address profile",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        help="override the profile's FairPlayIOKit Mach-O",
    )
    parser.add_argument(
        "--run-versioned-impl",
        type=lambda value: int(value, 0),
        help="override the profile's selector-0x15 implementation address",
    )
    parser.add_argument(
        "--kernel-collection-base",
        type=lambda value: int(value, 0),
        help="override the profile's chained-pointer base",
    )
    parser.add_argument("--command", type=lambda value: int(value, 0), default=2)
    parser.add_argument(
        "--token0", type=lambda value: int(value, 0), default=0x2070D6B0
    )
    parser.add_argument(
        "--token1", type=lambda value: int(value, 0), default=0x59AB65F9
    )
    parser.add_argument("--aux-hex", default=DEFAULT_AUX.hex())
    parser.add_argument("--input-hex", default=DEFAULT_INPUT.hex())
    parser.add_argument(
        "--paired-input-hex",
        help="run a second input under identical modeled state and report XOR",
    )
    parser.add_argument(
        "--monotonic-clock-hex",
        default=(1).to_bytes(8, "little").hex() + bytes(8).hex(),
    )
    parser.add_argument("--calendar-seconds", type=int, default=1_700_000_000)
    parser.add_argument("--calendar-microseconds", type=int, default=0)
    parser.add_argument(
        "--trace-dataflow",
        action="store_true",
        help="record accesses to input, output, and synthetic allocation ranges",
    )
    parser.add_argument(
        "--trace-static-reads",
        action="store_true",
        help="also record reads from file-backed FairPlayIOKit static data",
    )
    parser.add_argument(
        "--probe-address",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="record all general registers before executing this address",
    )
    parser.add_argument(
        "--probe-register-write",
        action="append",
        default=[],
        metavar="ADDRESS:REGISTER:VALUE",
        help="write a register before executing the instruction at ADDRESS",
    )
    args = parser.parse_args()

    profile = BUILD_PROFILES[args.profile]
    binary = args.binary or profile["binary"]
    run_versioned_impl = (
        args.run_versioned_impl
        if args.run_versioned_impl is not None
        else profile["run_versioned_impl"]
    )
    kernel_collection_base = (
        args.kernel_collection_base
        if args.kernel_collection_base is not None
        else profile["kernel_collection_base"]
    )

    auxiliary = parse_fixed_hex(args.aux_hex, 20, "--aux-hex")
    input_data = bytes.fromhex(args.input_hex)
    monotonic_clock = parse_fixed_hex(
        args.monotonic_clock_hex,
        16,
        "--monotonic-clock-hex",
    )
    names = nm_names(binary)
    names.update(profile["external_names"])
    db = RawMachODatabase(binary, names=names)
    probe_register_overrides: dict[int, dict[str, int]] = {}
    for specification in args.probe_register_write:
        address_text, register_name, value_text = specification.split(":", 2)
        probe_register_overrides.setdefault(int(address_text, 0), {})[
            register_name.lower()
        ] = int(value_text, 0)
    common = {
        "command": args.command,
        "token0": args.token0,
        "token1": args.token1,
        "auxiliary": auxiliary,
        "monotonic_clock": monotonic_clock,
        "calendar_seconds": args.calendar_seconds,
        "calendar_microseconds": args.calendar_microseconds,
        "trace_dataflow": args.trace_dataflow,
        "trace_static_reads": args.trace_static_reads,
        "probe_addresses": tuple(args.probe_address),
        "probe_register_overrides": probe_register_overrides,
        "run_versioned_impl": run_versioned_impl,
        "kernel_collection_base": kernel_collection_base,
    }
    first = run_versioned(db, input_data=input_data, **common)
    report: dict[str, Any] = {"first": first}

    if args.paired_input_hex is not None:
        paired_input = bytes.fromhex(args.paired_input_hex)
        second = run_versioned(db, input_data=paired_input, **common)
        first_output = bytes.fromhex(first["output_data"])
        second_output = bytes.fromhex(second["output_data"])
        common_length = min(len(first_output), len(second_output))
        report["second"] = second
        report["differential"] = {
            "input_xor": bytes(
                left ^ right for left, right in zip(input_data, paired_input)
            ).hex(),
            "output_xor": bytes(
                first_output[index] ^ second_output[index]
                for index in range(common_length)
            ).hex(),
            "first_output_length": len(first_output),
            "second_output_length": len(second_output),
            "common_output_length": common_length,
            "nonzero_output_bytes": sum(
                first_output[index] != second_output[index]
                for index in range(common_length)
            ),
        }
        first_snapshots = first.get("input_state_snapshots", [])
        second_snapshots = second.get("input_state_snapshots", [])
        if first_snapshots and len(first_snapshots) == len(second_snapshots):
            first_states = [
                bytes.fromhex(snapshot["state"]) for snapshot in first_snapshots
            ]
            second_states = [
                bytes.fromhex(snapshot["state"]) for snapshot in second_snapshots
            ]
            transitions = []
            for index in range(len(first_states) - 1):
                first_mask = bytes(
                    left ^ right
                    for left, right in zip(first_states[index], first_states[index + 1])
                )
                second_mask = bytes(
                    left ^ right
                    for left, right in zip(
                        second_states[index], second_states[index + 1]
                    )
                )
                transitions.append(
                    {
                        "from": index,
                        "to": index + 1,
                        "first_xor": first_mask.hex(),
                        "second_xor": second_mask.hex(),
                        "shared_xor_layer": first_mask == second_mask,
                    }
                )
            report["state_differential"] = {
                "snapshot_xors": [
                    bytes(left ^ right for left, right in zip(first_state, second_state)).hex()
                    for first_state, second_state in zip(first_states, second_states)
                ],
                "transitions": transitions,
            }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
