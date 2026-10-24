"""Seeded static trace for fairplayd request 502.

Load in the fairplayd IDB after ``ida_static_arm64.py`` is importable, then call
``trace_fairplay_setup(db)``.  The trace never executes analyzed code and keeps
all synthetic writes in the evaluator overlay.

The import hooks model only deterministic plumbing needed to reach the path and
CoreKE boundaries.  They are not substitutes for live kernel, filesystem, or
cryptographic behavior.  Unknown imports terminate the trace.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any, Callable

_SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if _SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, _SCRIPT_DIRECTORY)

from ida_static_arm64 import Evaluator, _target_name


SETUP_IMPL = 0x100BFE0BC

SYNTHETIC_SP = 0x700000100000
SYNTHETIC_PATH = 0x700000200000
SYNTHETIC_AUDIT = 0x700000210000
SYNTHETIC_OUT_136 = 0x700000220000
SYNTHETIC_OUT_172 = 0x700000230000
SYNTHETIC_ALLOC_BASE = 0x700010000000
SYNTHETIC_THREAD = 0x700020000000
SYNTHETIC_ERRNO = 0x700020001000
SYNTHETIC_DLOPEN_HANDLE = 0x700030000000
SYNTHETIC_DLSYM_BASE = 0x700040000000
SYNTHETIC_IO_MATCHING = 0x700050000000
SYNTHETIC_IO_ITERATOR_BASE = 0x100
SYNTHETIC_IO_SERVICE_BASE = 0x200
SYNTHETIC_IO_CONNECTION_BASE = 0x300
SYNTHETIC_CF_BOOLEAN_TYPE = 0x424F4F4C
SYNTHETIC_CF_DATA_TYPE = 0x44415441
PTHREAD_ONCE_RETURN_BASE = 0xF200000000000000
IOS26_SEAN_CODEC_ENTRY = 0x1006B34FC
IOS26_SEAN_CODEC_PREPARED_DISPATCH = 0x1008FBA00
IOS26_SEAN_GRAFT_FREE_CALL = 0x1003D51E0
IOS26_SEAN_SENTINEL_FREE_CALL = 0x1008D8DCC
IOS26_SEAN_USER_COPY_POINTER = 0x1006B3360
IOS26_SEAN_USER_COPY_LOOP = 0x1008C3EA8
MASK32 = (1 << 32) - 1

DEFAULT_PATH = (
    b"/private/var/containers/Bundle/Application/"
    b"00000000-0000-0000-0000-000000000000/WhatsApp.app/WhatsApp\0"
)

ZERO_RETURN_IMPORTS = {
    "bootpolicy_get_security_mode",
    "csr_get_active_config",
    "notify_cancel",
    "notify_post",
    "os_log_type_enabled",
    "pthread_getspecific",
    "pthread_mutex_destroy",
    "pthread_mutex_init",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
    "pthread_rwlock_destroy",
    "pthread_rwlock_init",
    "pthread_rwlock_rdlock",
    "pthread_rwlock_unlock",
    "pthread_rwlock_wrlock",
    "pthread_set_qos_class_self_np",
    "pthread_setspecific",
    "puts",
    "vm_deallocate",
}


def _u32(value: int) -> int:
    return value & MASK32


def _ios26_sean_codec_context(evaluator: Evaluator) -> dict[str, int]:
    """Read the exact 23E246 address-bound SEAN codec state."""

    sp = evaluator.regs["sp"]
    sparse_seed_pointer = evaluator.read_mem(sp + 0x9E0, 8)
    sparse_holder = evaluator.read_mem(sp + 0x9D8, 8)
    if sparse_seed_pointer == 0 or sparse_holder == 0:
        raise RuntimeError("SEAN codec has a null sparse-state pointer")
    sparse_seed = evaluator.read_mem(sparse_seed_pointer, 4)
    sparse_base = evaluator.read_mem(sparse_holder, 8)
    if sparse_base == 0:
        raise RuntimeError("SEAN codec has a null sparse table")
    context = {
        "sparse_word": evaluator.read_mem(
            sparse_base + (sparse_seed & 0x26E1D168), 4
        ),
        "multiplier": _u32(evaluator.regs["x23"]),
        "index_multiplier": _u32(evaluator.regs["x28"]),
        "xor30": _u32(evaluator.regs["x30"]),
        "mask4": _u32(evaluator.regs["x4"]),
        "xor12": _u32(evaluator.regs["x12"]),
        "output_xor": _u32(evaluator.regs["x20"]),
        "encoded_zero": evaluator.read_mem(sp + 0xC10, 4),
        "table_x5": evaluator.regs["x5"],
        "table_x14": evaluator.regs["x14"],
        "table_sp948": evaluator.read_mem(sp + 0x948, 8),
    }
    if not context["table_x5"] or not context["table_x14"] or not context["table_sp948"]:
        raise RuntimeError("SEAN codec has a null byte table")
    return context


def _ios26_sean_decode_four(
    evaluator: Evaluator,
    codec: dict[str, int],
    address: int,
    encoded: bytes,
) -> int:
    if len(encoded) != 4:
        raise ValueError("SEAN codec word must contain four bytes")
    lanes: list[int] = []
    for lane in range(4):
        mixed = (codec["sparse_word"] ^ _u32(address + lane)) & 0x7FFFFFFF
        mixed = _u32(mixed * codec["multiplier"])
        mixed ^= mixed >> 16
        mixed = _u32(mixed * codec["multiplier"])
        index = (mixed >> 24) & 0xFF
        table_byte = (
            evaluator.read_mem(codec["table_x5"] + index, 1)
            ^ evaluator.read_mem(codec["table_x14"] + index + 3, 1)
            ^ evaluator.read_mem(codec["table_sp948"] + index + 1, 1)
        )
        value = _u32(
            encoded[lane]
            ^ table_byte
            ^ mixed
            ^ _u32(index * codec["index_multiplier"])
        )
        if lane < 3:
            value ^= codec["xor30"]
        lanes.append(_u32(value))
    high = _u32(
        ((lanes[0] & 0xFF) << 24)
        | ((lanes[1] & 0xFF) << 16)
        | ((lanes[2] & 0xFF) << 8)
    )
    high = _u32(high - ((high << 1) & 0xE22C3200))
    high = _u32(high + 0xF1161906)
    high ^= 0xBB466831
    low = lanes[3]
    selected = ((low & 0xFF) ^ codec["xor12"]) & high
    low &= codec["mask4"]
    return _u32(selected ^ low ^ codec["output_xor"] ^ codec["encoded_zero"])


def _ios26_sean_encode_four(
    evaluator: Evaluator,
    codec: dict[str, int],
    address: int,
    clear: bytes,
) -> bytes:
    if len(clear) != 4:
        raise ValueError("SEAN clear word must contain four bytes")
    encoded = bytearray(4)
    for lane in range(4):
        shift = 24 - lane * 8
        matches: list[int] = []
        for candidate in range(256):
            encoded[lane] = candidate
            output = _ios26_sean_decode_four(
                evaluator, codec, address, bytes(encoded)
            )
            if ((output >> shift) & 0xFF) == clear[lane]:
                matches.append(candidate)
        if len(matches) != 1:
            raise RuntimeError(
                f"SEAN codec lane {lane} at {address:#x} has "
                f"{len(matches)} inverse bytes"
            )
        encoded[lane] = matches[0]
    if _ios26_sean_decode_four(evaluator, codec, address, bytes(encoded)) != int.from_bytes(clear, "big"):
        raise RuntimeError(f"SEAN codec round trip failed at {address:#x}")
    return bytes(encoded)


def _ios26_sean_encode_range(
    evaluator: Evaluator,
    codec: dict[str, int],
    target_base: int,
    clear: bytes,
    encoded: bytearray,
    offset: int,
    size: int,
) -> None:
    cursor = 0
    while size - cursor >= 4:
        encoded[offset + cursor : offset + cursor + 4] = _ios26_sean_encode_four(
            evaluator,
            codec,
            target_base + offset + cursor,
            clear[offset + cursor : offset + cursor + 4],
        )
        cursor += 4
    if cursor != size:
        remaining = size - cursor
        tail = clear[offset + cursor : offset + size] + bytes(4 - remaining)
        encoded_tail = _ios26_sean_encode_four(
            evaluator, codec, target_base + offset + cursor, tail
        )
        encoded[offset + cursor : offset + size] = encoded_tail[:remaining]


def _ios26_sean_encode_atom(
    evaluator: Evaluator,
    codec: dict[str, int],
    target_base: int,
    clear: bytes,
    encoded: bytearray,
    offset: int,
    limit: int,
    depth: int = 0,
) -> None:
    if depth > 16 or offset > limit or limit - offset < 20:
        raise ValueError("invalid SEAN atom bounds")
    size = int.from_bytes(clear[offset : offset + 4], "big")
    if size < 20 or size > limit - offset:
        raise ValueError("invalid SEAN atom size")
    _ios26_sean_encode_range(
        evaluator, codec, target_base, clear, encoded, offset, 20
    )
    containers = {b"sean", b"grup", b"head", b"tail", b"user", b"key "}
    if clear[offset + 4 : offset + 8] in containers:
        cursor = offset + 20
        while cursor < offset + size:
            child_size = int.from_bytes(clear[cursor : cursor + 4], "big")
            _ios26_sean_encode_atom(
                evaluator,
                codec,
                target_base,
                clear,
                encoded,
                cursor,
                offset + size,
                depth + 1,
            )
            cursor += child_size
        if cursor != offset + size:
            raise ValueError("SEAN container does not end on a child boundary")
    else:
        _ios26_sean_encode_range(
            evaluator,
            codec,
            target_base,
            clear,
            encoded,
            offset + 20,
            size - 20,
        )


def _ios26_sean_encode_registry(
    evaluator: Evaluator,
    codec: dict[str, int],
    target_base: int,
    clear: bytes,
) -> bytes:
    if (
        len(clear) < 32
        or clear[16:20] != b"sean"
        or int.from_bytes(clear[12:16], "big") != len(clear) - 12
    ):
        raise ValueError("SEAN graft is not a complete clear registry")
    encoded = bytearray(len(clear))
    _ios26_sean_encode_range(
        evaluator, codec, target_base, clear, encoded, 0, 12
    )
    _ios26_sean_encode_atom(
        evaluator, codec, target_base, clear, encoded, 12, len(clear)
    )
    return bytes(encoded)


def _read_cbytes(evaluator: Evaluator, pointer: int, limit: int = 0x10000) -> bytes:
    data = bytearray()
    for offset in range(limit):
        byte = evaluator.read_mem(pointer + offset, 1)
        if byte == 0:
            break
        data.append(byte)
    return bytes(data)


def _read_cstring(evaluator: Evaluator, pointer: int, limit: int = 0x10000) -> str:
    return _read_cbytes(evaluator, pointer, limit).decode("utf-8", "replace")


def _read_constant_cf_string(evaluator: Evaluator, pointer: int) -> str:
    string_pointer = evaluator.read_mem(pointer + 16, 8)
    string_length = evaluator.read_mem(pointer + 24, 8)
    if string_length > 0x1000:
        raise RuntimeError(
            f"constant CFString at {pointer:#x} is too long: {string_length:#x}"
        )
    return bytes(
        evaluator.read_mem(string_pointer + offset, 1)
        for offset in range(string_length)
    ).decode("utf-8", "replace")


def _matching_file_payload(
    file_payloads: dict[str, bytes] | None, path: str
) -> bytes | None:
    """Return the most-specific configured suffix match for a modeled path."""

    if file_payloads is None:
        return None
    for suffix in sorted(file_payloads, key=len, reverse=True):
        if path.endswith(suffix):
            return file_payloads[suffix]
    return None


def _matching_file_stat(
    file_stat_metadata: dict[str, dict[str, int]] | None, path: str
) -> dict[str, int]:
    if file_stat_metadata is None:
        return {}
    for suffix in sorted(file_stat_metadata, key=len, reverse=True):
        if path.endswith(suffix):
            return file_stat_metadata[suffix]
    return {}


def _write_darwin_stat(
    evaluator: Evaluator,
    address: int,
    size: int,
    metadata: dict[str, int],
) -> None:
    """Write the arm64 Darwin ``struct stat`` fields used by this path."""

    for offset in range(144):
        evaluator.write_mem(address + offset, 0, 1)
    evaluator.write_mem(address, metadata.get("dev", 0), 4)
    permissions = metadata.get("mode", 0o644) & 0o7777
    evaluator.write_mem(address + 4, 0o100000 | permissions, 2)
    evaluator.write_mem(address + 6, metadata.get("nlink", 1), 2)
    evaluator.write_mem(address + 8, metadata.get("ino", 0), 8)
    evaluator.write_mem(address + 16, metadata.get("uid", 0), 4)
    evaluator.write_mem(address + 20, metadata.get("gid", 0), 4)
    evaluator.write_mem(address + 24, metadata.get("rdev", 0), 4)
    for prefix, offset in (
        ("atime", 32),
        ("mtime", 48),
        ("ctime", 64),
        ("birthtime", 80),
    ):
        evaluator.write_mem(address + offset, metadata.get(prefix, 0), 8)
        evaluator.write_mem(
            address + offset + 8, metadata.get(prefix + "_nsec", 0), 8
        )
    evaluator.write_mem(address + 96, size, 8)
    evaluator.write_mem(address + 104, metadata.get("blocks", 0), 8)
    evaluator.write_mem(address + 112, metadata.get("blksize", 0), 4)
    evaluator.write_mem(address + 116, metadata.get("flags", 0), 4)
    evaluator.write_mem(address + 120, metadata.get("gen", 0), 4)


def _seed_evaluator(
    db: Any,
    path: bytes,
    extra_memory_watch_ranges: tuple[tuple[int, int], ...] = (),
    register_watch_names: tuple[str, ...] = (),
    watch_allocations: bool = True,
    chained_pointer_base: int | None = None,
    chained_pointer_format: str | None = None,
    request_token: int = 0x123,
    origin: int = 0,
    audit_token: bytes = bytes(32),
    initial_memory: dict[int, int] | None = None,
    initial_registers: dict[str, int] | None = None,
    initial_nzcv: dict[str, int] | None = None,
    profile_instructions: bool = False,
    recent_pc_limit: int = 0,
) -> Evaluator:
    if len(audit_token) != 32:
        raise ValueError("request-502 audit token must contain exactly 32 bytes")
    memory_watch_ranges = list(extra_memory_watch_ranges)
    if watch_allocations:
        memory_watch_ranges.insert(
            0,
            (SYNTHETIC_ALLOC_BASE, SYNTHETIC_ALLOC_BASE + 0x10000000),
        )
    evaluator = Evaluator(
        db,
        args=(
            request_token,
            SYNTHETIC_PATH,
            len(path),
            0x0100000C,
            0,
            origin,
            SYNTHETIC_AUDIT,
            SYNTHETIC_OUT_136,
        ),
        sp=SYNTHETIC_SP,
        chained_pointer_base=chained_pointer_base,
        chained_pointer_format=chained_pointer_format,
        memory_watch_ranges=tuple(memory_watch_ranges),
        register_watch_names=register_watch_names,
        profile_instructions=profile_instructions,
        recent_pc_limit=recent_pc_limit,
    )

    if initial_memory is not None:
        evaluator.memory.update(initial_memory)
    if initial_registers is not None:
        for name, value in initial_registers.items():
            is_vector = (
                name.startswith("v")
                and name[1:].isdigit()
                and 0 <= int(name[1:]) < 32
            )
            if name not in evaluator.regs and not is_vector:
                raise ValueError(f"unknown initial register {name!r}")
            register_bits = 128 if is_vector else 64
            evaluator.regs[name] = value & ((1 << register_bits) - 1)
    if initial_nzcv is not None:
        if set(initial_nzcv) != {"n", "z", "c", "v"}:
            raise ValueError("initial NZCV must contain n/z/c/v")
        evaluator.nzcv.update(
            {name: int(bool(value)) for name, value in initial_nzcv.items()}
        )

    for offset, byte in enumerate(path):
        evaluator.write_mem(SYNTHETIC_PATH + offset, byte, 1)
    for offset, byte in enumerate(audit_token):
        evaluator.write_mem(SYNTHETIC_AUDIT + offset, byte, 1)

    # Arguments 9..13: fixed 172-byte output, two OOL pointers, and lengths.
    stack_arguments = (
        SYNTHETIC_OUT_172,
        0x700000240000,
        0x700000250000,
        0x700000260000,
        0x700000270000,
    )
    for index, value in enumerate(stack_arguments):
        evaluator.write_mem(SYNTHETIC_SP + index * 8, value, 8)
    return evaluator


def trace_fairplay_setup(
    db: Any,
    *,
    path: bytes = DEFAULT_PATH,
    max_stages: int = 10000,
    coreke_return: int | None = 0,
    coreke_buffer_updates: dict[int, tuple[int, bytes]] | None = None,
    file_payloads: dict[str, bytes] | None = None,
    file_stat_metadata: dict[str, dict[str, int]] | None = None,
    extra_memory_watch_ranges: tuple[tuple[int, int], ...] = (),
    initial_memory_break_ranges: tuple[tuple[int, int], ...] = (),
    audit_pid: int = 0,
    register_watch_names: tuple[str, ...] = (),
    force_post_sinf_status: int | None = None,
    force_post_supf_status: int | None = None,
    force_post_certificate_predicate: bool | None = None,
    force_post_certificate_state_match: bool | None = None,
    force_certificate_state_byte: int | None = None,
    watch_allocations: bool = True,
    setup_impl: int = SETUP_IMPL,
    chained_pointer_base: int | None = None,
    chained_pointer_format: str | None = None,
    request_token: int = 0x123,
    origin: int = 0,
    audit_token: bytes = bytes(32),
    initial_memory: dict[int, int] | None = None,
    initial_registers: dict[str, int] | None = None,
    initial_nzcv: dict[str, int] | None = None,
    initialized_once_tokens: set[int] | None = None,
    registry_property_values: dict[tuple[str, str], bytes] | None = None,
    mobile_gestalt_answers: dict[str, bytes] | None = None,
    io_mac_address: bytes = b"\x02\x00\x00\x00\x00\x01",
    hypervisor_present: bool = True,
    follow_internal_transfers: bool = False,
    max_instructions_per_stage: int = 200000,
    file_read_break_offsets: dict[str, int] | None = None,
    stage_register_names: tuple[str, ...] = (),
    stage_sp_memory_offsets: tuple[int, ...] = (),
    accelerate_ios_supf_reverse_copy: bool = False,
    post_acceleration_instruction_limit: int | None = None,
    stop_addresses: frozenset[int] = frozenset(),
    stop_address_hit: int = 1,
    profile_instructions: bool = False,
    accelerate_ios_udid_byte_scan: bool = False,
    capture_ios_udid_simd_generator: bool = False,
    recent_pc_limit: int = 0,
    missing_files_are_enoent: bool = False,
    iokit_struct_method_outputs: dict[int, bytes] | None = None,
    iokit_struct_method_handlers: dict[
        int, Callable[[bytes, int, Evaluator], tuple[int, bytes]]
    ]
    | None = None,
    iokit_struct_method_input_overrides: dict[int, bytes] | None = None,
    register_overrides: dict[int, dict[str, int]] | None = None,
    register_override_hits: dict[int, int] | None = None,
    address_redirects: dict[int, int] | None = None,
    memory_copies: dict[int, list[tuple[int, int, int]]] | None = None,
    redirect_instruction_limit: int | None = None,
    trace_addresses: frozenset[int] = frozenset(),
    repeated_trace_addresses: frozenset[int] = frozenset(),
    continue_instruction_limit_stages: int = 0,
    reverse_memcpy_hits: dict[int, frozenset[int]] | None = None,
    malloc_adapter_hits: dict[int, frozenset[int]] | None = None,
    ios26_sean_graft_clear: bytes | None = None,
    ios26_sean_graft_source_ordinal: int = 2,
    ios26_sean_graft_source_size: int = 0x14,
    ios26_sean_graft_rebase_aliases: bool = False,
    ios26_sean_graft_in_place: bool = False,
    ios26_sean_graft_enable_repairs: bool = True,
    ios26_sean_graft_adjust_owner_bounds: bool = False,
) -> dict[str, Any]:
    """Trace request 502 until an unmodeled boundary or the stage limit.

    ``coreke_return=None`` stops at the first resolved CoreKE call.  An integer
    supplies a synthetic return value and permits tracing the caller's next
    branch. ``coreke_buffer_updates`` can separately model only buffer writes
    that were established by an independent CoreKE trace.
    """

    if len(io_mac_address) != 6:
        raise ValueError("IOKit MAC address fixture must contain exactly six bytes")

    evaluator = _seed_evaluator(
        db,
        path,
        extra_memory_watch_ranges=extra_memory_watch_ranges,
        register_watch_names=register_watch_names,
        watch_allocations=watch_allocations,
        chained_pointer_base=chained_pointer_base,
        chained_pointer_format=chained_pointer_format,
        request_token=request_token,
        origin=origin,
        audit_token=audit_token,
        initial_memory=initial_memory,
        initial_registers=initial_registers,
        initial_nzcv=initial_nzcv,
        profile_instructions=profile_instructions,
        recent_pc_limit=recent_pc_limit,
    )
    evaluator.memory_break_ranges += initial_memory_break_ranges
    pc = setup_impl
    next_allocation = SYNTHETIC_ALLOC_BASE
    if initial_memory:
        prior_allocations = [
            address
            for address in initial_memory
            if SYNTHETIC_ALLOC_BASE <= address < SYNTHETIC_THREAD
        ]
        if prior_allocations:
            next_allocation = (max(prior_allocations) + 0x100000) & ~0xFFFFF
    next_fake_symbol = SYNTHETIC_DLSYM_BASE
    once_tokens: set[int] = set(initialized_once_tokens or ())
    fake_symbols: dict[int, str] = {}
    fake_cf_strings: dict[int, bytes] = {}
    fake_cf_values: dict[int, tuple[str, bytes | bool]] = {}
    open_files: dict[int, dict[str, Any]] = {}
    next_fd = 10
    next_io_iterator = SYNTHETIC_IO_ITERATOR_BASE
    next_io_service = SYNTHETIC_IO_SERVICE_BASE
    next_io_connection = SYNTHETIC_IO_CONNECTION_BASE
    random_state = 0x12345678
    io_iterator_services: dict[int, int] = {}
    sha1_contexts: dict[int, Any] = {}
    pending_once_returns: dict[int, int] = {}
    stages: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    current_instruction_limit = max_instructions_per_stage
    stop_address_hits: dict[int, int] = {}
    applied_register_overrides: set[int] = set()
    encountered_register_override_hits: dict[int, int] = {}
    applied_address_redirects: set[int] = set()
    applied_memory_copies: set[int] = set()
    recorded_trace_addresses: set[int] = set()
    repeated_trace_hits: dict[int, int] = {}
    adapter_hit_counts: dict[int, int] = {}
    continued_instruction_limits = 0
    simd_generator_capture: dict[str, Any] | None = None
    simd_premix_registers: dict[str, int] | None = None
    simd_premix_stack_window: bytes | None = None
    simd_premix_stack_initialized: bytes | None = None
    ios26_sean_source_cells: list[int] = []
    ios26_sean_graft_installed = False
    ios26_sean_graft_address: int | None = None
    ios26_sean_graft_owned = False
    ios26_sean_graft_free_skipped = False
    ios26_sean_sentinel_free_fixed = False
    ios26_sean_user_copy_pointer_fixed = False
    ios26_sean_user_copy_loop_fixed = False
    ios26_sean_private_scratch: int | None = None
    ios26_sean_codec_hits = 0

    def install_ios26_sean_graft(
        codec: dict[str, int],
        source_cell: int,
        source_base: int,
        site: int,
        codec_hit: int | None,
    ) -> None:
        nonlocal next_allocation
        nonlocal ios26_sean_graft_installed
        nonlocal ios26_sean_graft_address
        nonlocal ios26_sean_graft_owned
        nonlocal ios26_sean_private_scratch
        if ios26_sean_graft_clear is None:
            raise AssertionError("SEAN graft installer has no clear registry")
        graft_address = source_base if ios26_sean_graft_in_place else next_allocation
        if not ios26_sean_graft_in_place:
            allocation_size = max(
                0x100000,
                (len(ios26_sean_graft_clear) + 0xFFFFF) & ~0xFFFFF,
            )
            next_allocation += allocation_size
        encoded = _ios26_sean_encode_registry(
            evaluator,
            codec,
            graft_address,
            ios26_sean_graft_clear,
        )
        for byte_offset, byte in enumerate(encoded):
            evaluator.write_mem(graft_address + byte_offset, byte, 1)
        owner_bound_delta = 0
        if ios26_sean_graft_adjust_owner_bounds:
            original_total = ios26_sean_graft_source_size + 0x0C
            owner_bound_delta = len(ios26_sean_graft_clear) - original_total
            for offset in (0x10, 0x14):
                previous = evaluator.read_mem(source_cell + offset, 4)
                evaluator.write_mem(
                    source_cell + offset,
                    _u32(previous + owner_bound_delta),
                    4,
                )
        rebased_memory: list[int] = []
        rebased_registers: list[str] = []
        if ios26_sean_graft_rebase_aliases:
            for address in sorted(evaluator.memory):
                if address & 7:
                    continue
                value = sum(
                    evaluator.memory.get(address + offset, 0) << (8 * offset)
                    for offset in range(8)
                )
                if source_base <= value < source_base + len(ios26_sean_graft_clear):
                    rebased_memory.append(address)
            for address in rebased_memory:
                value = evaluator.read_mem(address, 8)
                evaluator.write_mem(
                    address, graft_address + (value - source_base), 8
                )
            for name, value in evaluator.regs.items():
                if source_base <= value < source_base + len(ios26_sean_graft_clear):
                    evaluator.regs[name] = graft_address + (value - source_base)
                    rebased_registers.append(name)
        evaluator.write_mem(source_cell, graft_address, 8)
        scratch: int | None = None
        if not ios26_sean_graft_in_place and ios26_sean_graft_enable_repairs:
            scratch = evaluator.regs["sp"] + 0xCB00
            ios26_sean_private_scratch = scratch
            evaluator.write_mem(evaluator.regs["sp"] + 0xF58, scratch, 8)
            evaluator.write_mem(evaluator.regs["sp"] + 0x7400, scratch, 8)
        ios26_sean_graft_installed = True
        ios26_sean_graft_address = graft_address
        ios26_sean_graft_owned = not ios26_sean_graft_in_place
        events.append(
            {
                "kind": "ios26-sean-graft-installed",
                "site": hex(site),
                "codec_hit": codec_hit,
                "source_cell": hex(source_cell),
                "replaced_source": hex(source_base),
                "graft_address": hex(graft_address),
                "graft_bytes": len(encoded),
                "graft_sha256": hashlib.sha256(
                    ios26_sean_graft_clear
                ).hexdigest(),
                "encoded_sha256": hashlib.sha256(encoded).hexdigest(),
                "private_scratch": hex(scratch) if scratch is not None else None,
                "in_place": ios26_sean_graft_in_place,
                "rebased_memory_aliases": len(rebased_memory),
                "rebased_register_aliases": sorted(rebased_registers),
                "owner_bound_delta": owner_bound_delta,
            }
        )

    for index in range(max_stages):
        adapter_sites = set(reverse_memcpy_hits or ()) | set(malloc_adapter_hits or ())
        adapter_passthrough_site: int | None = None
        if pc in adapter_sites:
            hit = adapter_hit_counts.get(pc, 0) + 1
            adapter_hit_counts[pc] = hit
            if (
                reverse_memcpy_hits is not None
                and hit in reverse_memcpy_hits.get(pc, frozenset())
            ):
                source = evaluator.regs["x0"]
                destination = evaluator.regs["x1"]
                size = min(evaluator.regs["x2"], 0x100000)
                data = [
                    evaluator.read_mem(source + offset, 1)
                    for offset in range(size)
                ]
                for offset, byte in enumerate(data):
                    evaluator.write_mem(destination + offset, byte, 1)
                resume = evaluator.regs["x30"]
                evaluator.regs["x0"] = destination
                events.append(
                    {
                        "kind": "modeled-reverse-memcpy",
                        "site": hex(pc),
                        "hit": hit,
                        "source": hex(source),
                        "destination": hex(destination),
                        "size": size,
                        "resume": hex(resume),
                    }
                )
                pc = resume
                continue
            if (
                malloc_adapter_hits is not None
                and hit in malloc_adapter_hits.get(pc, frozenset())
            ):
                size = max(evaluator.regs["x0"], 1)
                address = next_allocation
                allocation_size = max(0x100000, (size + 0xFFFFF) & ~0xFFFFF)
                next_allocation += allocation_size
                evaluator.regs["x0"] = address
                resume = evaluator.regs["x30"]
                events.append(
                    {
                        "kind": "modeled-malloc-adapter",
                        "site": hex(pc),
                        "hit": hit,
                        "size": size,
                        "address": hex(address),
                        "resume": hex(resume),
                    }
                )
                pc = resume
                continue
            adapter_passthrough_site = pc
        ios26_sean_predispatch_passthrough = False
        if (
            ios26_sean_graft_clear is not None
            and not ios26_sean_graft_installed
            and pc == IOS26_SEAN_CODEC_PREPARED_DISPATCH
        ):
            codec = _ios26_sean_codec_context(evaluator)
            source_cell = evaluator.read_mem(evaluator.regs["sp"] + 0xC20, 8)
            source_base = evaluator.read_mem(source_cell, 8) if source_cell else 0
            source_offset = 0x0C
            decoded = (
                _ios26_sean_decode_four(
                    evaluator,
                    codec,
                    source_base + source_offset,
                    bytes(
                        evaluator.read_mem(source_base + source_offset + lane, 1)
                        for lane in range(4)
                    ),
                )
                if source_base
                else 0
            )
            root_tag = (
                _ios26_sean_decode_four(
                    evaluator,
                    codec,
                    source_base + 0x10,
                    bytes(
                        evaluator.read_mem(source_base + 0x10 + lane, 1)
                        for lane in range(4)
                    ),
                )
                if source_base
                else 0
            )
            events.append(
                {
                    "kind": "ios26-sean-predispatch-probe",
                    "site": hex(pc),
                    "source_cell": hex(source_cell),
                    "source_base": hex(source_base),
                    "source_offset": hex(source_offset),
                    "decoded_word": hex(decoded),
                    "root_tag": root_tag.to_bytes(4, "big").decode("latin-1"),
                    "source_owner_words": [
                        {
                            "offset": hex(offset),
                            "value": hex(evaluator.read_mem(source_cell + offset, 4)),
                        }
                        for offset in range(-0x40, 0x64, 4)
                    ]
                    if source_cell
                    else [],
                }
            )
            if (
                source_cell
                and source_offset == 0x0C
                and decoded == ios26_sean_graft_source_size
                and root_tag == int.from_bytes(b"sean", "big")
            ):
                if source_cell not in ios26_sean_source_cells:
                    ios26_sean_source_cells.append(source_cell)
                if (
                    len(ios26_sean_source_cells)
                    == ios26_sean_graft_source_ordinal
                ):
                    install_ios26_sean_graft(
                        codec, source_cell, source_base, pc, None
                    )
            ios26_sean_predispatch_passthrough = True
        ios26_sean_graft_free_passthrough = False
        if (
            ios26_sean_graft_installed
            and ios26_sean_graft_owned
            and pc == IOS26_SEAN_GRAFT_FREE_CALL
            and not ios26_sean_graft_free_skipped
        ):
            if evaluator.regs["x0"] == ios26_sean_graft_address:
                ios26_sean_graft_free_skipped = True
                events.append(
                    {
                        "kind": "ios26-sean-graft-free-skipped",
                        "site": hex(pc),
                        "graft_address": hex(ios26_sean_graft_address),
                    }
                )
                pc += 4
                continue
            ios26_sean_graft_free_passthrough = True
        ios26_sean_sentinel_free_passthrough = False
        if (
            ios26_sean_graft_installed
            and ios26_sean_graft_owned
            and ios26_sean_graft_enable_repairs
            and pc == IOS26_SEAN_SENTINEL_FREE_CALL
            and not ios26_sean_sentinel_free_fixed
        ):
            candidate = evaluator.regs["x0"]
            if not (
                SYNTHETIC_ALLOC_BASE
                <= candidate
                < SYNTHETIC_ALLOC_BASE + 0x10000000
            ):
                evaluator.regs["x0"] = 0
                ios26_sean_sentinel_free_fixed = True
                events.append(
                    {
                        "kind": "ios26-sean-invalid-free-normalized",
                        "site": hex(pc),
                        "previous": hex(candidate),
                        "replacement": "0x0",
                    }
                )
            ios26_sean_sentinel_free_passthrough = True
        if (
            ios26_sean_graft_installed
            and ios26_sean_graft_owned
            and ios26_sean_graft_enable_repairs
            and pc == IOS26_SEAN_USER_COPY_POINTER
            and not ios26_sean_user_copy_pointer_fixed
        ):
            scratch = evaluator.regs["sp"] + 0xCB00
            evaluator.regs["x8"] = scratch
            evaluator.regs["x10"] = 0x132E
            ios26_sean_user_copy_pointer_fixed = True
            events.append(
                {
                    "kind": "ios26-sean-user-copy-pointer-fixed",
                    "site": hex(pc),
                    "scratch": hex(scratch),
                }
            )
            pc += 4
            continue
        if (
            ios26_sean_graft_installed
            and ios26_sean_graft_owned
            and ios26_sean_graft_enable_repairs
            and pc == IOS26_SEAN_USER_COPY_LOOP
            and not ios26_sean_user_copy_loop_fixed
        ):
            scratch = evaluator.regs["sp"] + 0xCB00
            evaluator.regs["x10"] = scratch
            evaluator.regs["x12"] = _u32(
                evaluator.regs["x9"] + evaluator.regs["x23"]
            )
            ios26_sean_user_copy_loop_fixed = True
            events.append(
                {
                    "kind": "ios26-sean-user-copy-loop-fixed",
                    "site": hex(pc),
                    "scratch": hex(scratch),
                }
            )
            pc += 4
            continue
        ios26_sean_codec_passthrough = False
        if ios26_sean_graft_clear is not None and pc == IOS26_SEAN_CODEC_ENTRY:
            ios26_sean_codec_hits += 1
            if not ios26_sean_graft_installed:
                codec = _ios26_sean_codec_context(evaluator)
                source_cell = evaluator.regs["x16"]
                source_base = evaluator.read_mem(source_cell, 8)
                source_offset = _u32(evaluator.regs["x27"] + 0xA4B8F051)
                decoded = _ios26_sean_decode_four(
                    evaluator,
                    codec,
                    source_base + source_offset,
                    bytes(
                        evaluator.read_mem(source_base + source_offset + lane, 1)
                        for lane in range(4)
                    ),
                )
                root_tag = _ios26_sean_decode_four(
                    evaluator,
                    codec,
                    source_base + 0x10,
                    bytes(
                        evaluator.read_mem(source_base + 0x10 + lane, 1)
                        for lane in range(4)
                    ),
                )
                events.append(
                    {
                        "kind": "ios26-sean-codec-probe",
                        "site": hex(pc),
                        "codec_hit": ios26_sean_codec_hits,
                        "source_cell": hex(source_cell),
                        "source_base": hex(source_base),
                        "source_offset": hex(source_offset),
                        "decoded_word": hex(decoded),
                        "root_tag": root_tag.to_bytes(4, "big").decode(
                            "latin-1"
                        ),
                    }
                )
                if (
                    source_offset == 0x0C
                    and decoded == ios26_sean_graft_source_size
                    and root_tag == int.from_bytes(b"sean", "big")
                ):
                    if source_cell not in ios26_sean_source_cells:
                        ios26_sean_source_cells.append(source_cell)
                    if (
                        len(ios26_sean_source_cells)
                        == ios26_sean_graft_source_ordinal
                    ):
                        install_ios26_sean_graft(
                            codec,
                            source_cell,
                            source_base,
                            pc,
                            ios26_sean_codec_hits,
                        )
            ios26_sean_codec_passthrough = True
        if pc in trace_addresses and pc not in recorded_trace_addresses:
            recorded_trace_addresses.add(pc)
            events.append(
                {
                    "kind": "trace-address",
                    "site": hex(pc),
                    "registers": {
                        name: hex(value) for name, value in evaluator.snapshot().items()
                    },
                }
            )
        if pc in repeated_trace_addresses:
            hit = repeated_trace_hits.get(pc, 0) + 1
            repeated_trace_hits[pc] = hit
            events.append(
                {
                    "kind": "repeated-trace-address",
                    "site": hex(pc),
                    "hit": hit,
                    "stage": index,
                    "registers": {
                        name: hex(value)
                        for name, value in evaluator.snapshot().items()
                    },
                }
            )
            step = evaluator.run(
                pc,
                max_instructions=1,
                follow_internal_transfers=follow_internal_transfers,
            )
            if step.reason != "instruction-limit":
                raise RuntimeError(
                    "repeated trace address did not advance by one instruction: "
                    f"{pc:#x} -> {step.reason} at {step.address:#x}"
                )
            pc = step.address
            continue
        if (
            register_overrides is not None
            and pc in register_overrides
            and pc not in applied_register_overrides
        ):
            hit = encountered_register_override_hits.get(pc, 0) + 1
            encountered_register_override_hits[pc] = hit
            requested_hit = (register_override_hits or {}).get(pc, 1)
            if requested_hit == 0 or hit == requested_hit:
                writes = register_overrides[pc]
                for register, value in writes.items():
                    if register not in evaluator.regs:
                        raise ValueError(f"unknown override register {register!r}")
                    evaluator.regs[register] = value & ((1 << 64) - 1)
                if requested_hit != 0:
                    applied_register_overrides.add(pc)
                if requested_hit != 0 or hit == 1:
                    events.append(
                        {
                            "kind": "forced-register-override",
                            "site": hex(pc),
                            "hit": "every" if requested_hit == 0 else hit,
                            "registers": {
                                register: hex(value & ((1 << 64) - 1))
                                for register, value in writes.items()
                            },
                        }
                    )
        if (
            memory_copies is not None
            and pc in memory_copies
            and pc not in applied_memory_copies
        ):
            copies = memory_copies[pc]
            for source, destination, size in copies:
                data = [evaluator.read_mem(source + offset, 1) for offset in range(size)]
                for offset, byte in enumerate(data):
                    evaluator.write_mem(destination + offset, byte, 1)
            applied_memory_copies.add(pc)
            events.append(
                {
                    "kind": "forced-memory-copy",
                    "site": hex(pc),
                    "copies": [
                        {
                            "source": hex(source),
                            "destination": hex(destination),
                            "size": size,
                        }
                        for source, destination, size in copies
                    ],
                }
            )
        if (
            address_redirects is not None
            and pc in address_redirects
            and pc not in applied_address_redirects
        ):
            target = address_redirects[pc]
            applied_address_redirects.add(pc)
            events.append(
                {
                    "kind": "forced-address-redirect",
                    "site": hex(pc),
                    "target": hex(target),
                }
            )
            if redirect_instruction_limit is not None:
                current_instruction_limit = redirect_instruction_limit
            pc = target
            continue
        if pc == 0x1006758E8 and capture_ios_udid_simd_generator:
            simd_premix_registers = {
                **evaluator.snapshot(),
                **{
                    f"v{register}": evaluator.regs.get(f"v{register}", 0)
                    for register in range(32)
                },
            }
            window = evaluator.regs["sp"] + 0xC600
            simd_premix_stack_window = bytes(
                evaluator.read_mem(window + offset, 1)
                for offset in range(0x100)
            )
            simd_premix_stack_initialized = bytes(
                int(window + offset in evaluator.memory)
                for offset in range(0x100)
            )
        if pc == 0x100675B50 and capture_ios_udid_simd_generator:
            pointer = evaluator.regs["x12"]
            simd_generator_capture = {
                "pointer": pointer,
                "seed": evaluator.regs["x9"] & 0xFFFFFFFF,
                "input": bytes(
                    evaluator.read_mem(pointer + offset, 1)
                    for offset in range(0x248)
                ),
            }
        if pc == 0x100675C74 and capture_ios_udid_simd_generator:
            if simd_generator_capture is None:
                raise RuntimeError("reached SIMD generator end without its start")
            pointer = simd_generator_capture["pointer"]
            events.append(
                {
                    "kind": "ios-udid-simd-generator-capture",
                    "start": "0x100675b50",
                    "end": hex(pc),
                    "pointer": hex(pointer),
                    "seed": hex(simd_generator_capture["seed"]),
                    "premix_registers": {
                        name: hex(value)
                        for name, value in (simd_premix_registers or {}).items()
                    },
                    "premix_stack_base": hex(
                        (simd_premix_registers or {}).get("sp", 0) + 0xC600
                    ),
                    "premix_stack": (simd_premix_stack_window or b"").hex(),
                    "premix_stack_initialized": (
                        simd_premix_stack_initialized or b""
                    ).hex(),
                    "input": simd_generator_capture["input"].hex(),
                    "output": bytes(
                        evaluator.read_mem(pointer + offset, 1)
                        for offset in range(0x248)
                    ).hex(),
                }
            )
            events.append(
                {
                    "kind": "stop",
                    "reason": "simd-generator-captured",
                    "site": hex(pc),
                    "target": None,
                    "target_name": None,
                }
            )
            break
        if pc == 0x10075BA88 and accelerate_ios_udid_byte_scan:
            initial_index = evaluator.regs["x0"] & 0xFFFFFFFF
            table = evaluator.regs["x25"]
            increment = (
                (evaluator.regs["x26"] & 0xFFFFFFFF)
                - 0xD92
                + (evaluator.regs["x7"] & 0xFFFFFFFF)
            ) & 0xFFFFFFFF
            if initial_index != 0 or increment != 1:
                raise RuntimeError(
                    "unexpected UDID table-scan induction state: "
                    f"index={initial_index:#x}, increment={increment:#x}"
                )
            candidates = [
                address - table
                for address, value in evaluator.memory.items()
                if table <= address < table + 0x1000000 and value == 0x8E
            ]
            if not candidates:
                raise RuntimeError("UDID table scan has no initialized 0x8e byte")
            match_index = min(candidates)
            evaluator.regs["x0"] = match_index
            events.append(
                {
                    "kind": "accelerated-udid-byte-scan",
                    "loop_head": hex(pc),
                    "table": hex(table),
                    "initial_index": initial_index,
                    "match_index": match_index,
                    "skipped_iterations": match_index,
                    "final_native_iterations": 1,
                }
            )
        if (
            pc == 0x1001625BC
            and accelerate_ios_supf_reverse_copy
            and not evaluator.memory_break_ranges
        ):
            evaluator.stage = index
            source = evaluator.regs["x12"]
            destination = evaluator.read_mem(evaluator.regs["sp"] + 0x190, 8)
            initial_count = evaluator.regs["x10"]
            masks: dict[int, int] = {}
            for iteration in range(32):
                byte_index = evaluator.regs["x10"] - 1
                iteration_stop = evaluator.run(
                    pc,
                    max_instructions=10000,
                    follow_internal_transfers=True,
                    breakpoints=frozenset({pc}),
                )
                if (
                    iteration_stop.reason != "breakpoint"
                    or iteration_stop.address != pc
                ):
                    raise RuntimeError(
                        "SUPF reverse-copy loop did not return to its head: "
                        f"{iteration_stop.reason} at {iteration_stop.address:#x}"
                    )
                source_byte = evaluator.memory[source + byte_index]
                output_byte = evaluator.memory[destination + byte_index]
                mask = source_byte ^ output_byte
                phase = byte_index & 0xF
                previous = masks.get(phase)
                if previous is not None and previous != mask:
                    raise RuntimeError(
                        "SUPF reverse-copy mask is not 16-byte periodic: "
                        f"phase {phase}, {previous:#x} != {mask:#x}"
                    )
                masks[phase] = mask
            if len(masks) != 16:
                raise RuntimeError("SUPF reverse-copy did not cover all 16 mask phases")

            remaining_count = evaluator.regs["x10"]
            evaluator.current_pc = 0x1001625C8
            for byte_index in range(remaining_count - 1, 0, -1):
                source_byte = evaluator.read_mem(source + byte_index, 1)
                evaluator.memory[destination + byte_index] = (
                    source_byte ^ masks[byte_index & 0xF]
                )
            evaluator.regs["x10"] = 1
            events.append(
                {
                    "kind": "accelerated-supf-reverse-copy",
                    "loop_head": hex(pc),
                    "load_site": "0x1001625c8",
                    "store_site": "0x1001626b4",
                    "source": hex(source),
                    "destination": hex(destination),
                    "byte_count": initial_count,
                    "native_iterations": 32,
                    "bulk_iterations": remaining_count - 1,
                    "final_native_iterations": 1,
                    "xor_mask": bytes(masks[phase] for phase in range(16)).hex(),
                }
            )
            if post_acceleration_instruction_limit is not None:
                current_instruction_limit = post_acceleration_instruction_limit
        if (
            pc == 0x10093FFD0
            and accelerate_ios_supf_reverse_copy
            and not evaluator.memory_break_ranges
        ):
            evaluator.stage = index
            source = evaluator.regs["x23"]
            destination = evaluator.regs["x20"]
            initial_count = evaluator.regs["x9"]
            masks: dict[int, int] = {}
            for iteration in range(32):
                byte_index = evaluator.regs["x9"] - 1
                iteration_stop = evaluator.run(
                    pc,
                    max_instructions=10000,
                    follow_internal_transfers=True,
                    breakpoints=frozenset({pc}),
                )
                if (
                    iteration_stop.reason != "breakpoint"
                    or iteration_stop.address != pc
                ):
                    raise RuntimeError(
                        "26A428 SUPF reverse-copy loop did not return to its head: "
                        f"{iteration_stop.reason} at {iteration_stop.address:#x}"
                    )
                source_byte = evaluator.memory[source + byte_index]
                output_byte = evaluator.memory[destination + byte_index]
                mask = source_byte ^ output_byte
                phase = byte_index & 0xF
                previous = masks.get(phase)
                if previous is not None and previous != mask:
                    raise RuntimeError(
                        "26A428 SUPF reverse-copy mask is not 16-byte periodic: "
                        f"phase {phase}, {previous:#x} != {mask:#x}"
                    )
                masks[phase] = mask
            if len(masks) != 16:
                raise RuntimeError(
                    "26A428 SUPF reverse-copy did not cover all 16 mask phases"
                )

            remaining_count = evaluator.regs["x9"]
            evaluator.current_pc = 0x100940078
            for byte_index in range(remaining_count - 1, 0, -1):
                source_byte = evaluator.read_mem(source + byte_index, 1)
                evaluator.memory[destination + byte_index] = (
                    source_byte ^ masks[byte_index & 0xF]
                )
            evaluator.regs["x9"] = 1
            events.append(
                {
                    "kind": "accelerated-supf-reverse-copy-26A428",
                    "loop_head": hex(pc),
                    "load_site": "0x100940078",
                    "store_site": "0x1009400b8",
                    "source": hex(source),
                    "destination": hex(destination),
                    "byte_count": initial_count,
                    "native_iterations": 32,
                    "bulk_iterations": remaining_count - 1,
                    "final_native_iterations": 1,
                    "xor_mask": bytes(masks[phase] for phase in range(16)).hex(),
                }
            )
            if post_acceleration_instruction_limit is not None:
                current_instruction_limit = post_acceleration_instruction_limit
        if (
            pc == 0x100647AD4
            and accelerate_ios_supf_reverse_copy
            and not evaluator.memory_break_ranges
        ):
            evaluator.stage = index
            source = evaluator.regs["x23"]
            destination = evaluator.regs["x25"]
            initial_count = evaluator.regs["x10"]
            masks: dict[int, int] = {}
            for iteration in range(32):
                byte_index = evaluator.regs["x10"] - 1
                iteration_stop = evaluator.run(
                    pc,
                    max_instructions=10000,
                    follow_internal_transfers=True,
                    breakpoints=frozenset({pc}),
                )
                if (
                    iteration_stop.reason != "breakpoint"
                    or iteration_stop.address != pc
                ):
                    raise RuntimeError(
                        "26B118 SUPF reverse-copy loop did not return to its head: "
                        f"{iteration_stop.reason} at {iteration_stop.address:#x}"
                    )
                source_byte = evaluator.memory[source + byte_index]
                output_byte = evaluator.memory[destination + byte_index]
                mask = source_byte ^ output_byte
                phase = byte_index & 0xF
                previous = masks.get(phase)
                if previous is not None and previous != mask:
                    raise RuntimeError(
                        "26B118 SUPF reverse-copy mask is not 16-byte periodic: "
                        f"phase {phase}, {previous:#x} != {mask:#x}"
                    )
                masks[phase] = mask
            if len(masks) != 16:
                raise RuntimeError(
                    "26B118 SUPF reverse-copy did not cover all 16 mask phases"
                )

            remaining_count = evaluator.regs["x10"]
            evaluator.current_pc = 0x100647AD8
            for byte_index in range(remaining_count - 1, 0, -1):
                source_byte = evaluator.read_mem(source + byte_index, 1)
                evaluator.memory[destination + byte_index] = (
                    source_byte ^ masks[byte_index & 0xF]
                )
            evaluator.regs["x10"] = 1
            events.append(
                {
                    "kind": "accelerated-supf-reverse-copy-26B118",
                    "loop_head": hex(pc),
                    "load_site": "0x100647ad8",
                    "store_site": "0x100647ba4",
                    "source": hex(source),
                    "destination": hex(destination),
                    "byte_count": initial_count,
                    "native_iterations": 32,
                    "bulk_iterations": remaining_count - 1,
                    "final_native_iterations": 1,
                    "xor_mask": bytes(masks[phase] for phase in range(16)).hex(),
                }
            )
            if post_acceleration_instruction_limit is not None:
                current_instruction_limit = post_acceleration_instruction_limit
        if pc in (0x100001E84, 0x100001DDC):
            registry_path = _read_cstring(evaluator, evaluator.regs["x0"])
            property_name = _read_cstring(evaluator, evaluator.regs["x1"])
            capacity = evaluator.read_mem(evaluator.regs["x3"], 4)
            event = {
                "kind": "registry-property-request",
                "path": registry_path,
                "property": property_name,
                "capacity": capacity,
                "destination": hex(evaluator.regs["x2"]),
                "length_pointer": hex(evaluator.regs["x3"]),
            }
            events.append(event)
            payload = None
            if registry_property_values is not None:
                payload = registry_property_values.get((registry_path, property_name))
            if payload is not None:
                if len(payload) > capacity:
                    evaluator.regs["x0"] = 0xFFFF5BD9  # -42023
                else:
                    for byte_offset, byte in enumerate(payload):
                        evaluator.write_mem(
                            evaluator.regs["x2"] + byte_offset,
                            byte,
                            1,
                        )
                    evaluator.write_mem(evaluator.regs["x3"], len(payload), 4)
                    evaluator.regs["x0"] = 0
                    event["modeled_size"] = len(payload)
                pc = evaluator.regs["x30"]
                continue
        if pc == 0x100A6B31C and force_post_sinf_status is not None:
            status_address = evaluator.regs["x24"] + 0x20
            previous_status = evaluator.read_mem(status_address, 4)
            evaluator.write_mem(status_address, force_post_sinf_status, 4)
            events.append(
                {
                    "kind": "forced-post-sinf-status",
                    "address": hex(status_address),
                    "previous": hex(previous_status),
                    "value": hex(force_post_sinf_status & 0xFFFFFFFF),
                }
            )
        if pc == 0x100942930 and force_post_supf_status is not None:
            status_address = evaluator.regs["x23"]
            previous_status = evaluator.read_mem(status_address, 4)
            evaluator.write_mem(status_address, force_post_supf_status, 4)
            events.append(
                {
                    "kind": "forced-post-supf-status",
                    "address": hex(status_address),
                    "previous": hex(previous_status),
                    "value": hex(force_post_supf_status & 0xFFFFFFFF),
                }
            )
        if pc == 0x1008DE8A4:
            table = evaluator.read_mem(evaluator.regs["sp"] + 0xA38, 8)
            state = evaluator.regs["x19"] & 0xFFFFFFFF
            branch_targets: dict[bool, int] = {}
            for predicate in (False, True):
                table_index = ((498 * int(predicate)) ^ state) & 0xFFFFFFFF
                signed_index = (
                    table_index - (1 << 32)
                    if table_index & (1 << 31)
                    else table_index
                )
                branch_targets[predicate] = evaluator.read_mem(
                    table + signed_index * 8,
                    8,
                )
            events.append(
                {
                    "kind": "post-certificate-dispatch",
                    "state": hex(state),
                    "stack_2234": hex(evaluator.read_mem(evaluator.regs["sp"] + 0x2234, 4)),
                    "stack_3a54": hex(evaluator.read_mem(evaluator.regs["sp"] + 0x3A54, 4)),
                    "false_target": hex(branch_targets[False]),
                    "true_target": hex(branch_targets[True]),
                }
            )
            if force_post_certificate_predicate is not None:
                evaluator.regs["x24"] = 0xB2AC8746
                forced_target = branch_targets[force_post_certificate_predicate]
                events.append(
                    {
                        "kind": "forced-post-certificate-predicate",
                        "predicate": force_post_certificate_predicate,
                        "target": hex(forced_target),
                    }
                )
                pc = forced_target
                continue
        if pc == 0x100A2A3E0:
            table = evaluator.read_mem(evaluator.regs["sp"] + 0xA38, 8)
            base_index = ((evaluator.regs["x20"] & 0xFFFFFFFF) + 0x61F6) & 0xFFFFFFFF
            branch_targets: dict[bool, int] = {}
            for matches in (False, True):
                table_index = base_index ^ (12 if matches else 0)
                signed_index = (
                    table_index - (1 << 32)
                    if table_index & (1 << 31)
                    else table_index
                )
                branch_targets[matches] = evaluator.read_mem(
                    table + signed_index * 8,
                    8,
                )
            events.append(
                {
                    "kind": "post-certificate-state-dispatch",
                    "base_index": hex(base_index),
                    "false_target": hex(branch_targets[False]),
                    "true_target": hex(branch_targets[True]),
                }
            )
            if force_post_certificate_state_match is not None:
                evaluator.regs["x24"] = 0xB2AC8741
                forced_target = branch_targets[force_post_certificate_state_match]
                events.append(
                    {
                        "kind": "forced-post-certificate-state-match",
                        "matches": force_post_certificate_state_match,
                        "target": hex(forced_target),
                    }
                )
                pc = forced_target
                continue
        if pc == 0x1007AABB0:
            byte_address = evaluator.regs["x1"] + 0xD43
            previous_byte = evaluator.read_mem(byte_address, 1)
            table = evaluator.read_mem(evaluator.regs["sp"] + 0xA38, 8)
            state = evaluator.regs["x11"] & 0xFFFFFFFF
            masked = ((state + 0x0360B3B8) & 0xFC9EF67A) ^ 0x7042
            candidates = []
            for candidate_byte in range(256):
                table_index = ((masked * candidate_byte) ^ state) & 0xFFFFFFFF
                signed_index = (
                    table_index - (1 << 32)
                    if table_index & (1 << 31)
                    else table_index
                )
                target = evaluator.read_mem(table + signed_index * 8, 8)
                if target and db.is_valid_ea(target):
                    candidates.append((candidate_byte, target))
            events.append(
                {
                    "kind": "certificate-state-byte-dispatch",
                    "address": hex(byte_address),
                    "previous": hex(previous_byte),
                    "candidates": [
                        {"byte": candidate, "target": hex(target)}
                        for candidate, target in candidates[:32]
                    ],
                    "candidate_count": len(candidates),
                }
            )
            if force_certificate_state_byte is not None:
                evaluator.write_mem(
                    byte_address,
                    force_certificate_state_byte & 0xFF,
                    1,
                )
                events.append(
                    {
                        "kind": "forced-certificate-state-byte",
                        "value": hex(force_certificate_state_byte & 0xFF),
                    }
                )
        evaluator.stage = index
        if profile_instructions:
            evaluator.instruction_counts.clear()
        stop = evaluator.run(
            pc,
            max_instructions=current_instruction_limit,
            follow_internal_transfers=follow_internal_transfers,
            breakpoints=frozenset(
                {
                    0x100001E84,
                    0x100001DDC,
                    0x1007AABB0,
                    0x1008DE8A4,
                    0x100942930,
                    0x100A2A3E0,
                    0x100A6B31C,
                }
                | (
                    {0x1001625BC, 0x10093FFD0, 0x100647AD4}
                    if accelerate_ios_supf_reverse_copy
                    else set()
                )
                | ({0x10075BA88} if accelerate_ios_udid_byte_scan else set())
                | (
                    {0x1006758E8, 0x100675B50, 0x100675C74}
                    if capture_ios_udid_simd_generator
                    else set()
                )
                | set(stop_addresses)
                | (
                    set(register_overrides or {}) - applied_register_overrides
                )
                | (set(address_redirects or {}) - applied_address_redirects)
                | (set(memory_copies or {}) - applied_memory_copies)
                | (set(trace_addresses) - recorded_trace_addresses)
                | set(repeated_trace_addresses)
                | (adapter_sites - (
                    {adapter_passthrough_site}
                    if adapter_passthrough_site is not None else set()
                ))
                | (
                    {IOS26_SEAN_CODEC_PREPARED_DISPATCH}
                    if ios26_sean_graft_clear is not None
                    and not ios26_sean_graft_installed
                    and not ios26_sean_predispatch_passthrough
                    else set()
                )
                | (
                    {IOS26_SEAN_CODEC_ENTRY}
                    if ios26_sean_graft_clear is not None
                    and not ios26_sean_graft_installed
                    and not ios26_sean_codec_passthrough
                    else set()
                )
                | (
                    {IOS26_SEAN_GRAFT_FREE_CALL}
                    if ios26_sean_graft_installed
                    and ios26_sean_graft_owned
                    and not ios26_sean_graft_free_skipped
                    and not ios26_sean_graft_free_passthrough
                    else set()
                )
                | (
                    {IOS26_SEAN_SENTINEL_FREE_CALL}
                    if ios26_sean_graft_installed
                    and ios26_sean_graft_owned
                    and ios26_sean_graft_enable_repairs
                    and not ios26_sean_sentinel_free_fixed
                    and not ios26_sean_sentinel_free_passthrough
                    else set()
                )
                | (
                    {IOS26_SEAN_USER_COPY_POINTER}
                    if ios26_sean_graft_installed
                    and ios26_sean_graft_owned
                    and ios26_sean_graft_enable_repairs
                    and not ios26_sean_user_copy_pointer_fixed
                    else set()
                )
                | (
                    {IOS26_SEAN_USER_COPY_LOOP}
                    if ios26_sean_graft_installed
                    and ios26_sean_graft_owned
                    and ios26_sean_graft_enable_repairs
                    and not ios26_sean_user_copy_loop_fixed
                    else set()
                )
            ),
        )
        if stop.reason == "return" and stop.target in pending_once_returns:
            resume = pending_once_returns.pop(stop.target)
            evaluator.regs["x0"] = 0
            evaluator.regs["x30"] = resume
            pc = resume
            continue
        target_name = _target_name(db, stop.target)
        normalized_name = (target_name or "").lstrip("_")
        row = {
            "index": index,
            "start": hex(pc),
            "reason": stop.reason,
            "site": hex(stop.address),
            "mnemonic": stop.mnemonic,
            "target": hex(stop.target) if stop.target is not None else None,
            "target_name": target_name,
            "args": [hex(stop.registers[f"x{arg}"]) for arg in range(8)],
            "sp": hex(stop.registers["sp"]),
            "instructions": stop.instructions,
        }
        if stage_register_names:
            row["registers"] = {
                name: hex(stop.registers.get(name, 0))
                for name in stage_register_names
            }
        if stage_sp_memory_offsets:
            row["sp_memory"] = {
                hex(offset): hex(
                    evaluator.read_mem(stop.registers.get("sp", 0) + offset, 8)
                )
                for offset in stage_sp_memory_offsets
            }
        if profile_instructions:
            row["top_instruction_pcs"] = [
                {"pc": hex(address), "count": count}
                for address, count in sorted(
                    evaluator.instruction_counts.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:40]
            ]
        if evaluator.recent_pcs is not None:
            row["recent_pcs"] = [hex(address) for address in evaluator.recent_pcs]
        if stop.reason == "memory-breakpoint":
            row["memory_break_hit"] = dict(evaluator.memory_break_hit or {})
        stages.append(row)

        if (
            stop.reason == "instruction-limit"
            and continued_instruction_limits < continue_instruction_limit_stages
        ):
            continued_instruction_limits += 1
            events.append(
                {
                    "kind": "continued-instruction-limit",
                    "site": hex(stop.address),
                    "slice": continued_instruction_limits,
                    "instructions": stop.instructions,
                }
            )
            pc = stop.address
            continue

        if stop.reason == "breakpoint" and stop.address in adapter_sites:
            pc = stop.address
            continue

        if stop.reason == "breakpoint" and stop.address in stop_addresses:
            hit = stop_address_hits.get(stop.address, 0) + 1
            stop_address_hits[stop.address] = hit
            if hit < stop_address_hit:
                pc = stop.address
                continue
            events.append(
                {
                    "kind": "stop",
                    "reason": "breakpoint",
                    "site": hex(stop.address),
                    "hit": hit,
                    "target": None,
                    "target_name": None,
                }
            )
            break
        if stop.reason == "breakpoint":
            pc = stop.address
            continue

        call_like = stop.reason in ("direct-call", "indirect") and stop.mnemonic.startswith(
            ("bl", "blr")
        )
        tail_like = stop.reason == "direct-branch" or (
            stop.reason == "indirect" and stop.mnemonic.startswith(("b", "bra", "br"))
        )
        resume = stop.address + 4 if call_like else evaluator.regs["x30"]

        if stop.target in fake_symbols:
            symbol = fake_symbols[stop.target]
            events.append(
                {
                    "kind": "coreke-call",
                    "symbol": symbol,
                    "site": hex(stop.address),
                    "args": row["args"],
                    "sp": row["sp"],
                    "descriptor16": bytes(
                        evaluator.read_mem(evaluator.regs["x2"] + offset, 1)
                        for offset in range(16)
                    ).hex(),
                }
            )
            operation = evaluator.regs["x0"] & 0xFFFFFFFF
            if coreke_buffer_updates is not None and operation in coreke_buffer_updates:
                offset, data = coreke_buffer_updates[operation]
                destination = evaluator.regs["x2"] + offset
                for byte_offset, byte in enumerate(data):
                    evaluator.write_mem(destination + byte_offset, byte, 1)
                events.append(
                    {
                        "kind": "modeled-coreke-buffer-update",
                        "symbol": symbol,
                        "operation": operation,
                        "offset": offset,
                        "size": len(data),
                    }
                )
            if coreke_return is None:
                break
            evaluator.regs["x0"] = coreke_return
            evaluator.regs["x30"] = resume
            pc = resume
            continue

        handled = False
        if call_like or tail_like:
            if normalized_name == "IORegistryEntryFromPath":
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "master_port": evaluator.regs["x0"],
                        "path": _read_cstring(evaluator, evaluator.regs["x1"]),
                        "args": row["args"],
                        "site": hex(stop.address),
                    }
                )
                break
            if normalized_name in ("open", "open_dprotected_np"):
                file_path = _read_cstring(evaluator, evaluator.regs["x0"])
                events.append(
                    {
                        "kind": "file-call",
                        "function": normalized_name,
                        "path": file_path,
                        "args": row["args"],
                        "site": hex(stop.address),
                    }
                )
                payload = _matching_file_payload(file_payloads, file_path)
                if payload is None:
                    if not missing_files_are_enoent:
                        break
                    evaluator.write_mem(SYNTHETIC_ERRNO, 2, 4)
                    evaluator.regs["x0"] = 0xFFFFFFFF
                    events[-1]["modeled_missing_errno"] = 2
                    evaluator.regs["x30"] = resume
                    pc = resume
                    continue
                fd = next_fd
                next_fd += 1
                open_files[fd] = {
                    "data": payload,
                    "offset": 0,
                    "path": file_path,
                    "stat": _matching_file_stat(file_stat_metadata, file_path),
                }
                evaluator.regs["x0"] = fd
                evaluator.regs["x30"] = resume
                pc = resume
                continue
            if normalized_name in ("stat", "lstat"):
                file_path = _read_cstring(evaluator, evaluator.regs["x0"])
                payload = _matching_file_payload(file_payloads, file_path)
                events.append(
                    {
                        "kind": "file-call",
                        "function": normalized_name,
                        "path": file_path,
                        "args": row["args"],
                        "site": hex(stop.address),
                    }
                )
                if payload is None:
                    if not missing_files_are_enoent:
                        break
                    evaluator.write_mem(SYNTHETIC_ERRNO, 2, 4)
                    evaluator.regs["x0"] = 0xFFFFFFFF
                    events[-1]["modeled_missing_errno"] = 2
                    evaluator.regs["x30"] = resume
                    pc = resume
                    continue
                stat_buffer = evaluator.regs["x1"]
                _write_darwin_stat(
                    evaluator,
                    stat_buffer,
                    len(payload),
                    _matching_file_stat(file_stat_metadata, file_path),
                )
                evaluator.regs["x0"] = 0
                evaluator.regs["x30"] = resume
                pc = resume
                continue
            if normalized_name == "unlink":
                file_path = _read_cstring(evaluator, evaluator.regs["x0"])
                payload = _matching_file_payload(file_payloads, file_path)
                events.append(
                    {
                        "kind": "file-call",
                        "function": normalized_name,
                        "path": file_path,
                        "args": row["args"],
                        "site": hex(stop.address),
                    }
                )
                if payload is None:
                    if not missing_files_are_enoent:
                        break
                    evaluator.write_mem(SYNTHETIC_ERRNO, 2, 4)
                    evaluator.regs["x0"] = 0xFFFFFFFF
                    events[-1]["modeled_missing_errno"] = 2
                else:
                    # The replay never mutates a supplied host artifact.  A
                    # successful return models only the target process view.
                    evaluator.regs["x0"] = 0
                    events[-1]["modeled_removed"] = True
                evaluator.regs["x30"] = resume
                pc = resume
                continue
            handled = True
            if normalized_name == "chkstk_darwin":
                pass
            elif normalized_name == "arc4random":
                random_state = (
                    1664525 * random_state + 1013904223
                ) & 0xFFFFFFFF
                evaluator.regs["x0"] = random_state
            elif normalized_name in ZERO_RETURN_IMPORTS:
                evaluator.regs["x0"] = 0
            elif normalized_name == "audit_token_to_au32":
                # The reached call requests only the pid output in x6; all
                # other au32 output pointers are null on this path.
                if evaluator.regs["x6"]:
                    evaluator.write_mem(evaluator.regs["x6"], audit_pid, 4)
                evaluator.regs["x0"] = 0
            elif normalized_name == "pthread_self":
                evaluator.regs["x0"] = SYNTHETIC_THREAD
            elif normalized_name == "error":
                evaluator.write_mem(SYNTHETIC_ERRNO, 0, 4)
                evaluator.regs["x0"] = SYNTHETIC_ERRNO
            elif normalized_name == "pthread_get_qos_class_np":
                evaluator.write_mem(evaluator.regs["x1"], 0x15, 4)
                evaluator.write_mem(evaluator.regs["x2"], 0, 4)
                evaluator.regs["x0"] = 0
            elif normalized_name == "CC_SHA1_Init":
                context = evaluator.regs["x0"]
                sha1_contexts[context] = hashlib.sha1()
                evaluator.regs["x0"] = 1
            elif normalized_name == "CC_SHA1_Update":
                context = evaluator.regs["x0"]
                source = evaluator.regs["x1"]
                length = evaluator.regs["x2"]
                if length > 0x1000000:
                    raise RuntimeError(
                        f"CC_SHA1_Update input is too large: {length:#x}"
                    )
                digest = sha1_contexts.get(context)
                if digest is None:
                    raise RuntimeError(
                        f"CC_SHA1_Update used unknown context {context:#x}"
                    )
                digest.update(
                    bytes(
                        evaluator.read_mem(source + offset, 1)
                        for offset in range(length)
                    )
                )
                evaluator.regs["x0"] = 1
            elif normalized_name == "CC_SHA1_Final":
                destination = evaluator.regs["x0"]
                context = evaluator.regs["x1"]
                digest = sha1_contexts.pop(context, None)
                if digest is None:
                    raise RuntimeError(
                        f"CC_SHA1_Final used unknown context {context:#x}"
                    )
                for offset, byte in enumerate(digest.digest()):
                    evaluator.write_mem(destination + offset, byte, 1)
                evaluator.regs["x0"] = 1
            elif normalized_name == "notify_register_check":
                if evaluator.regs["x1"]:
                    evaluator.write_mem(evaluator.regs["x1"], 1, 4)
                evaluator.regs["x0"] = 0
            elif normalized_name == "notify_check":
                if evaluator.regs["x1"]:
                    evaluator.write_mem(evaluator.regs["x1"], 0, 4)
                evaluator.regs["x0"] = 0
            elif normalized_name == "IOMainPort":
                # IOMainPort(bootstrap_port, &main_port) is process plumbing;
                # the reached caller checks only the kern_return_t before
                # passing the resulting handle to an IOKit query.
                destination = evaluator.regs["x1"]
                if destination:
                    evaluator.write_mem(destination, 1, 4)
                evaluator.regs["x0"] = 0
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "destination": hex(destination),
                        "modeled_port": 1,
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOBSDNameMatching":
                # IOBSDNameMatching(main_port, options, bsd_name) returns the
                # same kind of retained matching dictionary consumed by
                # IOServiceGetMatchingServices as IOServiceMatching does.
                # Keep the argument geometry distinct: the BSD name is x2,
                # not x0.
                master_port = evaluator.regs["x0"] & 0xFFFFFFFF
                bsd_name = _read_cstring(evaluator, evaluator.regs["x2"])
                evaluator.regs["x0"] = SYNTHETIC_IO_MATCHING
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "master_port": master_port,
                        "options": evaluator.regs["x1"] & 0xFFFFFFFF,
                        "bsd_name": bsd_name,
                        "modeled_matching": hex(SYNTHETIC_IO_MATCHING),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOServiceMatching":
                service_name = _read_cstring(evaluator, evaluator.regs["x0"])
                evaluator.regs["x0"] = SYNTHETIC_IO_MATCHING
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "service_name": service_name,
                        "modeled_matching": hex(SYNTHETIC_IO_MATCHING),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOServiceGetMatchingServices":
                destination = evaluator.regs["x2"]
                iterator = next_io_iterator
                next_io_iterator += 1
                service = next_io_service
                next_io_service += 1
                io_iterator_services[iterator] = service
                evaluator.write_mem(destination, iterator, 4)
                evaluator.regs["x0"] = 0
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "matching": hex(evaluator.regs["x1"]),
                        "modeled_iterator": hex(iterator),
                        "modeled_service": hex(service),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOIteratorNext":
                iterator = evaluator.regs["x0"] & 0xFFFFFFFF
                service = io_iterator_services.pop(iterator, 0)
                evaluator.regs["x0"] = service
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "iterator": hex(iterator),
                        "modeled_service": hex(service),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOServiceOpen":
                service = evaluator.regs["x0"] & 0xFFFFFFFF
                destination = evaluator.regs["x3"]
                connection = next_io_connection
                next_io_connection += 1
                evaluator.write_mem(destination, connection, 4)
                evaluator.regs["x0"] = 0
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "service": hex(service),
                        "type": evaluator.regs["x2"] & 0xFFFFFFFF,
                        "modeled_connection": hex(connection),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOObjectRelease":
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "object": hex(evaluator.regs["x0"] & 0xFFFFFFFF),
                        "site": hex(stop.address),
                    }
                )
                evaluator.regs["x0"] = 0
            elif normalized_name == "IORegistryEntryCreateCFProperty":
                registry_object = evaluator.regs["x0"] & 0xFFFFFFFF
                key = _read_constant_cf_string(evaluator, evaluator.regs["x1"])
                if key == "IOBuiltin":
                    value: tuple[str, bytes | bool] = ("boolean", True)
                elif key == "IOMACAddress":
                    value = ("data", io_mac_address)
                else:
                    handled = False
                    value = ("data", b"")
                if handled:
                    address = next_allocation
                    next_allocation += 0x100000
                    fake_cf_values[address] = value
                    evaluator.regs["x0"] = address
                    events.append(
                        {
                            "kind": "iokit-call",
                            "function": normalized_name,
                            "object": hex(registry_object),
                            "property": key,
                            "value_type": value[0],
                            "value_size": (
                                len(value[1]) if isinstance(value[1], bytes) else None
                            ),
                            "site": hex(stop.address),
                        }
                    )
            elif normalized_name == "IORegistryEntryGetParentEntry":
                destination = evaluator.regs["x2"]
                service = next_io_service
                next_io_service += 1
                evaluator.write_mem(destination, service, 4)
                evaluator.regs["x0"] = 0
                events.append(
                    {
                        "kind": "iokit-call",
                        "function": normalized_name,
                        "modeled_parent": hex(service),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "IOConnectCallStructMethod":
                selector = evaluator.regs["x1"] & 0xFFFFFFFF
                output_size_pointer = evaluator.regs["x5"]
                output_capacity = (
                    evaluator.read_mem(output_size_pointer, 8)
                    if output_size_pointer
                    else 0
                )
                modeled_output = (
                    iokit_struct_method_outputs.get(selector)
                    if iokit_struct_method_outputs is not None
                    else None
                )
                modeled_return = 0
                handler = (
                    iokit_struct_method_handlers.get(selector)
                    if iokit_struct_method_handlers is not None
                    else None
                )
                if handler is not None:
                    input_size = evaluator.regs["x3"]
                    if input_size > 0x100000:
                        raise RuntimeError(
                            f"IOKit selector {selector:#x} input is too large: "
                            f"{input_size:#x}"
                        )
                    override = (
                        iokit_struct_method_input_overrides.get(selector)
                        if iokit_struct_method_input_overrides is not None
                        else None
                    )
                    if override is not None:
                        if len(override) != input_size:
                            raise RuntimeError(
                                f"IOKit selector {selector:#x} input override "
                                f"is {len(override):#x} bytes, expected "
                                f"{input_size:#x}"
                            )
                        for offset, byte in enumerate(override):
                            evaluator.write_mem(
                                evaluator.regs["x2"] + offset, byte, 1
                            )
                        events.append(
                            {
                                "kind": "iokit-input-override",
                                "selector": hex(selector),
                                "bytes": len(override),
                                "sha256": hashlib.sha256(override).hexdigest(),
                            }
                        )
                    input_data = bytes(
                        evaluator.read_mem(evaluator.regs["x2"] + offset, 1)
                        for offset in range(input_size)
                    )
                    modeled_return, modeled_output = handler(
                        input_data,
                        output_capacity,
                        evaluator,
                    )
                event = {
                    "kind": "iokit-struct-method",
                    "connection": hex(evaluator.regs["x0"] & 0xFFFFFFFF),
                    "selector": hex(selector),
                    "input": hex(evaluator.regs["x2"]),
                    "input_size": evaluator.regs["x3"],
                    "output": hex(evaluator.regs["x4"]),
                    "output_capacity": output_capacity,
                    "site": hex(stop.address),
                }
                if evaluator.regs["x3"] <= 0x1000:
                    event["input_data"] = bytes(
                        evaluator.read_mem(evaluator.regs["x2"] + offset, 1)
                        for offset in range(evaluator.regs["x3"])
                    ).hex()
                    if evaluator.regs["x3"] >= 12:
                        pointed_address = evaluator.read_mem(
                            evaluator.regs["x2"], 8
                        )
                        pointed_length = evaluator.read_mem(
                            evaluator.regs["x2"] + 8, 4
                        )
                        if pointed_length <= 0x1000:
                            event["pointed_input"] = {
                                "address": hex(pointed_address),
                                "length": pointed_length,
                                "data": bytes(
                                    evaluator.read_mem(pointed_address + offset, 1)
                                    for offset in range(pointed_length)
                                ).hex(),
                            }
                events.append(event)
                if modeled_output is None:
                    handled = False
                elif len(modeled_output) > output_capacity:
                    raise RuntimeError(
                        f"modeled IOKit selector {selector:#x} output "
                        f"({len(modeled_output)} bytes) exceeds capacity "
                        f"{output_capacity}"
                    )
                else:
                    for offset, byte in enumerate(modeled_output):
                        evaluator.write_mem(evaluator.regs["x4"] + offset, byte, 1)
                    evaluator.write_mem(output_size_pointer, len(modeled_output), 8)
                    evaluator.regs["x0"] = modeled_return & 0xFFFFFFFF
                    event["modeled_return"] = hex(modeled_return & 0xFFFFFFFF)
                    event["modeled_output_size"] = len(modeled_output)
            elif normalized_name == "pthread_once":
                token = evaluator.regs["x0"]
                if token in once_tokens:
                    evaluator.regs["x0"] = 0
                    evaluator.regs["x30"] = resume
                    pc = resume
                else:
                    once_tokens.add(token)
                    sentinel = (
                        PTHREAD_ONCE_RETURN_BASE + len(once_tokens) * 0x1000
                    )
                    pending_once_returns[sentinel] = resume
                    evaluator.regs["x30"] = sentinel
                    pc = evaluator.regs["x1"]
                continue
            elif normalized_name == "dispatch_once":
                token = evaluator.regs["x0"]
                block = evaluator.regs["x1"]
                if token in once_tokens:
                    evaluator.regs["x0"] = 0
                    evaluator.regs["x30"] = resume
                    pc = resume
                else:
                    invoke = evaluator.read_mem(block + 0x10, 8)
                    if invoke == 0:
                        raise RuntimeError("dispatch_once block has a null invoke")
                    once_tokens.add(token)
                    sentinel = (
                        PTHREAD_ONCE_RETURN_BASE + len(once_tokens) * 0x1000
                    )
                    pending_once_returns[sentinel] = resume
                    evaluator.regs["x0"] = block
                    evaluator.regs["x30"] = sentinel
                    pc = invoke
                    events.append(
                        {
                            "kind": "dispatch-once",
                            "site": hex(stop.address),
                            "token": hex(token),
                            "block": hex(block),
                            "invoke": hex(invoke),
                        }
                    )
                continue
            elif normalized_name in ("getuid", "geteuid", "getgid", "getegid"):
                evaluator.regs["x0"] = 0
            elif normalized_name == "getpid":
                evaluator.regs["x0"] = 1234
            elif normalized_name == "gettimeofday":
                destination = evaluator.regs["x0"]
                if destination:
                    evaluator.write_mem(destination, 1_700_000_000, 8)
                    evaluator.write_mem(destination + 8, 0, 8)
                evaluator.regs["x0"] = 0
            elif normalized_name == "sysctlbyname":
                name = _read_cstring(evaluator, evaluator.regs["x0"])
                output = evaluator.regs["x1"]
                output_size_pointer = evaluator.regs["x2"]
                output_capacity = (
                    evaluator.read_mem(output_size_pointer, 8)
                    if output_size_pointer
                    else 0
                )
                event = {
                    "kind": "sysctlbyname",
                    "site": hex(stop.address),
                    "name": name,
                    "output_capacity": output_capacity,
                }
                if name == "kern.hv_vmm_present" and output and output_capacity >= 4:
                    modeled_hypervisor = int(hypervisor_present)
                    evaluator.write_mem(output, modeled_hypervisor, 4)
                    evaluator.write_mem(output_size_pointer, 4, 8)
                    evaluator.regs["x0"] = 0
                    event["modeled_value"] = modeled_hypervisor
                else:
                    evaluator.write_mem(SYNTHETIC_ERRNO, 2, 4)
                    evaluator.regs["x0"] = 0xFFFFFFFF
                    event["modeled_errno"] = 2
                events.append(event)
            elif normalized_name == "vm_allocate":
                destination = evaluator.regs["x1"]
                size = evaluator.regs["x2"]
                address = next_allocation
                allocation_size = max(0x4000, (size + 0x3FFF) & ~0x3FFF)
                next_allocation += allocation_size
                if destination:
                    evaluator.write_mem(destination, address, 8)
                for offset in range(size):
                    evaluator.memory[address + offset] = 0
                evaluator.regs["x0"] = 0
                events.append(
                    {
                        "kind": "vm-allocate",
                        "destination": hex(destination),
                        "address": hex(address),
                        "size": size,
                        "flags": evaluator.regs["x3"],
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "proc_pidpath":
                process_path = b"/usr/sbin/fairplayd.H2"
                destination = evaluator.regs["x1"]
                capacity = evaluator.regs["x2"]
                if len(process_path) + 1 > capacity:
                    evaluator.regs["x0"] = 0
                else:
                    for offset, byte in enumerate(process_path + b"\0"):
                        evaluator.write_mem(destination + offset, byte, 1)
                    evaluator.regs["x0"] = len(process_path)
            elif normalized_name in (
                "malloc",
                "malloc_type_malloc",
                "calloc",
                "malloc_type_calloc",
            ):
                allocation_bytes = (
                    evaluator.regs["x0"] * evaluator.regs["x1"]
                    if normalized_name in ("calloc", "malloc_type_calloc")
                    else evaluator.regs["x0"]
                )
                allocation_bytes = max(allocation_bytes, 1)
                address = next_allocation
                evaluator.regs["x0"] = address
                next_allocation += 0x100000
                events.append(
                    {
                        "kind": "heap-allocation",
                        "function": normalized_name,
                        "address": hex(address),
                        "length": allocation_bytes,
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "free":
                pass
            elif normalized_name == "CFStringGetSystemEncoding":
                # Darwin's system encoding is MacRoman (zero).  The reached
                # caller immediately uses it for an ASCII diagnostic string.
                evaluator.regs["x0"] = 0
            elif normalized_name in (
                "CFStringCreateWithCString",
                "CFStringCreateWithCStringNoCopy",
            ):
                value = _read_cstring(evaluator, evaluator.regs["x1"]).encode()
                address = next_allocation
                next_allocation += 0x100000
                fake_cf_strings[address] = value
                evaluator.regs["x0"] = address
                events.append(
                    {
                        "kind": "cf-string-create",
                        "function": normalized_name,
                        "address": hex(address),
                        "value": value.decode("utf-8", "replace"),
                        "site": hex(stop.address),
                    }
                )
            elif normalized_name == "CFStringGetLength":
                value = fake_cf_strings.get(evaluator.regs["x0"])
                if value is None:
                    handled = False
                else:
                    evaluator.regs["x0"] = len(value)
            elif normalized_name == "CFGetTypeID":
                if evaluator.regs["x0"] in fake_cf_strings:
                    evaluator.regs["x0"] = 0x535452
                elif evaluator.regs["x0"] in fake_cf_values:
                    value_type = fake_cf_values[evaluator.regs["x0"]][0]
                    evaluator.regs["x0"] = (
                        SYNTHETIC_CF_BOOLEAN_TYPE
                        if value_type == "boolean"
                        else SYNTHETIC_CF_DATA_TYPE
                    )
                else:
                    handled = False
            elif normalized_name == "CFStringGetTypeID":
                evaluator.regs["x0"] = 0x535452
            elif normalized_name == "CFBooleanGetTypeID":
                evaluator.regs["x0"] = SYNTHETIC_CF_BOOLEAN_TYPE
            elif normalized_name == "CFDataGetTypeID":
                evaluator.regs["x0"] = SYNTHETIC_CF_DATA_TYPE
            elif normalized_name == "CFBooleanGetValue":
                value = fake_cf_values.get(evaluator.regs["x0"])
                if value is None or value[0] != "boolean":
                    handled = False
                else:
                    evaluator.regs["x0"] = int(bool(value[1]))
            elif normalized_name == "CFDataCreate":
                source = evaluator.regs["x1"]
                length = evaluator.regs["x2"]
                if length > 0x100000:
                    raise RuntimeError(f"CFDataCreate input is too large: {length:#x}")
                value = bytes(
                    evaluator.read_mem(source + offset, 1)
                    for offset in range(length)
                )
                address = next_allocation
                next_allocation += 0x100000
                fake_cf_values[address] = ("data", value)
                evaluator.regs["x0"] = address
            elif normalized_name == "CFDataGetLength":
                value = fake_cf_values.get(evaluator.regs["x0"])
                if value is None or value[0] != "data" or not isinstance(value[1], bytes):
                    handled = False
                else:
                    evaluator.regs["x0"] = len(value[1])
            elif normalized_name == "CFDataGetBytePtr":
                value = fake_cf_values.get(evaluator.regs["x0"])
                if value is None or value[0] != "data" or not isinstance(value[1], bytes):
                    handled = False
                else:
                    address = next_allocation
                    next_allocation += 0x100000
                    for offset, byte in enumerate(value[1]):
                        evaluator.write_mem(address + offset, byte, 1)
                    evaluator.regs["x0"] = address
            elif normalized_name == "CFDataGetBytes":
                value = fake_cf_values.get(evaluator.regs["x0"])
                if value is None or value[0] != "data" or not isinstance(value[1], bytes):
                    handled = False
                else:
                    location = evaluator.regs["x1"]
                    length = evaluator.regs["x2"]
                    destination = evaluator.regs["x3"]
                    for offset, byte in enumerate(value[1][location : location + length]):
                        evaluator.write_mem(destination + offset, byte, 1)
            elif normalized_name == "CFStringGetMaximumSizeForEncoding":
                evaluator.regs["x0"] = evaluator.regs["x0"] * 4
            elif normalized_name == "CFStringGetCString":
                value = fake_cf_strings.get(evaluator.regs["x0"])
                capacity = evaluator.regs["x2"]
                if value is None or capacity <= len(value):
                    evaluator.regs["x0"] = 0
                else:
                    destination = evaluator.regs["x1"]
                    for offset, byte in enumerate(value + b"\0"):
                        evaluator.write_mem(destination + offset, byte, 1)
                    evaluator.regs["x0"] = 1
            elif normalized_name == "CFRelease":
                fake_cf_strings.pop(evaluator.regs["x0"], None)
                fake_cf_values.pop(evaluator.regs["x0"], None)
            elif normalized_name == "MGCopyAnswer":
                key_bytes = fake_cf_strings.get(evaluator.regs["x0"])
                key = (
                    key_bytes.decode("utf-8", "replace")
                    if key_bytes is not None
                    else None
                )
                answer = (
                    mobile_gestalt_answers.get(key)
                    if mobile_gestalt_answers is not None and key is not None
                    else None
                )
                events.append(
                    {
                        "kind": "mobile-gestalt-answer",
                        "key": key,
                        "modeled": answer is not None,
                        "value_size": len(answer) if answer is not None else None,
                        "site": hex(stop.address),
                    }
                )
                if answer is None:
                    handled = False
                else:
                    address = next_allocation
                    next_allocation += 0x100000
                    fake_cf_strings[address] = answer
                    evaluator.regs["x0"] = address
            elif normalized_name in ("memcpy", "memmove"):
                destination = evaluator.regs["x0"]
                source = evaluator.regs["x1"]
                count = min(evaluator.regs["x2"], 0x100000)
                data = [evaluator.read_mem(source + offset, 1) for offset in range(count)]
                for offset, byte in enumerate(data):
                    evaluator.write_mem(destination + offset, byte, 1)
                evaluator.regs["x0"] = destination
            elif normalized_name == "memset":
                destination = evaluator.regs["x0"]
                value = evaluator.regs["x1"] & 0xFF
                count = min(evaluator.regs["x2"], 0x100000)
                for offset in range(count):
                    evaluator.write_mem(destination + offset, value, 1)
                evaluator.regs["x0"] = destination
            elif normalized_name == "bzero":
                destination = evaluator.regs["x0"]
                count = min(evaluator.regs["x1"], 0x100000)
                for offset in range(count):
                    evaluator.write_mem(destination + offset, 0, 1)
            elif normalized_name == "strlen":
                string_address = evaluator.regs["x0"]
                string_data = _read_cbytes(evaluator, string_address)
                events.append(
                    {
                        "kind": "strlen",
                        "address": hex(string_address),
                        "length": len(string_data),
                        "bytes": string_data[:256].hex(),
                        "truncated": len(string_data) > 256,
                        "site": hex(stop.address),
                    }
                )
                evaluator.regs["x0"] = len(string_data)
            elif normalized_name == "strnlen":
                evaluator.regs["x0"] = len(
                    _read_cbytes(
                        evaluator,
                        evaluator.regs["x0"],
                        min(evaluator.regs["x1"], 0x100000),
                    )
                )
            elif normalized_name == "dlopen":
                events.append(
                    {
                        "kind": "dlopen",
                        "path": _read_cstring(evaluator, evaluator.regs["x0"]),
                        "mode": evaluator.regs["x1"],
                        "site": hex(stop.address),
                    }
                )
                evaluator.regs["x0"] = SYNTHETIC_DLOPEN_HANDLE
            elif normalized_name == "dlsym":
                symbol = _read_cstring(evaluator, evaluator.regs["x1"])
                address = next_fake_symbol
                next_fake_symbol += 0x1000
                fake_symbols[address] = symbol
                events.append(
                    {
                        "kind": "dlsym",
                        "symbol": symbol,
                        "fake_address": hex(address),
                        "site": hex(stop.address),
                    }
                )
                evaluator.regs["x0"] = address
            elif normalized_name in ("dlclose", "dlerror"):
                evaluator.regs["x0"] = 0
            elif normalized_name == "fstat":
                descriptor = evaluator.regs["x0"]
                entry = open_files.get(descriptor)
                if entry is None:
                    handled = False
                else:
                    stat_buffer = evaluator.regs["x1"]
                    _write_darwin_stat(
                        evaluator,
                        stat_buffer,
                        len(entry["data"]),
                        entry.get("stat", {}),
                    )
                    evaluator.regs["x0"] = 0
            elif normalized_name == "read":
                descriptor = evaluator.regs["x0"]
                entry = open_files.get(descriptor)
                if entry is None:
                    handled = False
                else:
                    destination = evaluator.regs["x1"]
                    count = evaluator.regs["x2"]
                    offset = entry["offset"]
                    data = entry["data"][offset : offset + count]
                    for index, byte in enumerate(data):
                        evaluator.write_mem(destination + index, byte, 1)
                    entry["offset"] += len(data)
                    evaluator.regs["x0"] = len(data)
            elif normalized_name == "close":
                open_files.pop(evaluator.regs["x0"], None)
                evaluator.regs["x0"] = 0
            elif normalized_name == "mmap":
                descriptor = evaluator.regs["x4"]
                entry = open_files.get(descriptor)
                if entry is not None:
                    mapped = next_allocation
                    next_allocation += 0x100000
                    length = evaluator.regs["x1"]
                    file_offset = evaluator.regs["x5"]
                    # Darwin maps whole VM pages even when the requested byte
                    # length ends in the middle of a page.  FairPlay's Mach-O
                    # scanner requests mach_header (28 bytes) + sizeofcmds for
                    # a 64-bit image; the final LC_CODE_SIGNATURE datasize is
                    # four bytes beyond that requested length but remains in
                    # the same mapped 16 KiB page on real iOS.  Populate the
                    # complete accessible page rather than leaving those bytes
                    # spuriously zero in the sparse evaluator overlay.
                    accessible_length = (length + 0x3FFF) & ~0x3FFF
                    data = entry["data"][
                        file_offset : file_offset + accessible_length
                    ]
                    for index, byte in enumerate(data):
                        # Populate the synthetic mapping as environment state,
                        # not as an instruction-side write. This keeps memory
                        # watch logs focused on analyzed-code accesses.
                        evaluator.memory[mapped + index] = byte
                    evaluator.regs["x0"] = mapped
                    events.append(
                        {
                            "kind": "mmap-file",
                            "path": entry["path"],
                            "address": hex(mapped),
                            "length": length,
                            "accessible_length": accessible_length,
                            "populated_length": len(data),
                            "file_offset": file_offset,
                            "site": hex(stop.address),
                        }
                    )
                    if file_read_break_offsets is not None:
                        for suffix, break_offset in file_read_break_offsets.items():
                            if entry["path"].endswith(suffix):
                                evaluator.memory_break_ranges += (
                                    (
                                        mapped + break_offset,
                                        mapped + break_offset + 1,
                                    ),
                                )
                                events.append(
                                    {
                                        "kind": "file-read-breakpoint-armed",
                                        "path": entry["path"],
                                        "offset": hex(break_offset),
                                        "address": hex(mapped + break_offset),
                                    }
                                )
                elif descriptor in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) and (
                    evaluator.regs["x3"] & 0x1000
                ):
                    mapped = next_allocation
                    length = evaluator.regs["x1"]
                    allocation_size = max(0x100000, (length + 0xFFFFF) & ~0xFFFFF)
                    next_allocation += allocation_size
                    evaluator.regs["x0"] = mapped
                    events.append(
                        {
                            "kind": "mmap-anonymous",
                            "address": hex(mapped),
                            "length": length,
                            "protection": evaluator.regs["x2"],
                            "flags": evaluator.regs["x3"],
                            "site": hex(stop.address),
                        }
                    )
                else:
                    handled = False
            elif normalized_name == "munmap":
                evaluator.regs["x0"] = 0
            else:
                handled = False

            if handled:
                evaluator.regs["x30"] = resume
                pc = resume
                continue

        target_is_internal = stop.target is not None and db.is_valid_ea(stop.target)
        if stop.reason in ("direct-call", "indirect") and target_is_internal:
            if call_like:
                evaluator.regs["x30"] = stop.address + 4
            pc = stop.target
            continue
        if stop.reason == "return" and target_is_internal:
            pc = stop.target
            continue

        events.append(
            {
                "kind": "stop",
                "reason": stop.reason,
                "site": hex(stop.address),
                "target": hex(stop.target) if stop.target is not None else None,
                "target_name": target_name,
            }
        )
        break

    if ios26_sean_private_scratch is not None:
        scratch = bytes(
            evaluator.read_mem(ios26_sean_private_scratch + offset, 1)
            for offset in range(0x280)
        )
        events.append(
            {
                "kind": "ios26-sean-user-copy-scratch-final",
                "address": hex(ios26_sean_private_scratch),
                "bytes": len(scratch),
                "sha256": hashlib.sha256(scratch).hexdigest(),
                "nonzero_bytes": sum(byte != 0 for byte in scratch),
            }
        )

    return {
        "stages": stages,
        "events": events,
        "fake_symbols": {hex(address): name for address, name in fake_symbols.items()},
        "memory_accesses": evaluator.memory_accesses,
        "register_accesses": evaluator.register_accesses,
        "final_registers": evaluator.snapshot(),
        "final_vector_registers": {
            name: value
            for name, value in evaluator.regs.items()
            if name.startswith("v") and name[1:].isdigit()
        },
        "final_nzcv": dict(evaluator.nzcv),
        # Kept out of the JSON-facing report by callers.  Exposing the final
        # sparse overlay lets exact-build drivers inspect dynamically located
        # scratch buffers at an internal breakpoint without modifying target
        # memory or teaching this generic tracer about their layout.
        "final_memory": evaluator.memory,
        "final_once_tokens": sorted(once_tokens),
    }
