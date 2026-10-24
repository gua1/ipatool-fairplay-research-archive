"""Exact-build seeded replay for iOS ``fairplayd.H2`` request 502.

This driver first executes the daemon's deterministic protected-table startup
using modeled process plumbing, then reuses the resulting global-memory overlay
for :func:`trace_fairplay_setup`.  It does not execute the target binary.

Build profiles keep daemon and FairPlayIOKit constants paired.  The D47AP
``product-id`` was verified directly in both supported iPhone17,3 IPSWs.
"""

from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import pickle
import re
import subprocess
from typing import Any, Callable
from zipfile import ZipFile

from ida_static_arm64 import Evaluator, _target_name
from raw_macho_db import RawMachODatabase, dyld_info_fixups, otool_indirect_names
from trace_fairplay_setup import (
    _matching_file_stat,
    _write_darwin_stat,
    trace_fairplay_setup,
)
from trace_fairplay_iokit_run_versioned import (
    BUILD_PROFILES as FAIRPLAY_IOKIT_BUILD_PROFILES,
    nm_names as fairplay_iokit_nm_names,
    run_fp_client_init as run_fairplay_iokit_client_init,
    run_fp_message as run_fairplay_iokit_fp_message,
    run_fp_provider_init as run_fairplay_iokit_provider_init,
    run_versioned as run_fairplay_iokit_versioned,
)


SETUP_IMPL = 0x100B912D8
MAIN = 0x100B763F4
IMAGE_BASE = 0x100000000
REQUEST_TOKEN = 0x01000101
STARTUP_SP = 0x700001000000
STARTUP_ALLOC_BASE = 0x710000000000
DEFAULT_PRODUCT_ID = bytes.fromhex(
    "1c2775a019ca5e2a44e6477a56ff010d8e6ef248"
)
# Independently evaluated from the matching 25G83 FairPlayIOKit provider
# methods.  Both values are protocol metadata, not keys or device secrets.
DEFAULT_IOKIT_VERSION = 0x4B130000
DEFAULT_IOKIT_PROTOCOL_CAPABILITIES = 0x1F8
STARTUP_CACHE_SCHEMA = 1
DEFAULT_STARTUP_CACHE = Path(
    "artifacts/fairplay/cache/fairplayd-ios23E246-startup-v1.json"
)
PTHREAD_ONCE_RETURN_BASE = 0xF200000000000000
XPC_LISTENER_RETURN = 0xF300000000000000
XPC_MESSAGE_RETURN = 0xF400000000000000
SYNTHETIC_XPC_PEER = 0x700090001000
SYNTHETIC_XPC_MESSAGE = 0x700090002000
DAEMON_BUILD_PROFILES: dict[str, dict[str, Any]] = {
    "macos-26A428": {
        "binary": Path(
            "artifacts/fairplay/fairplayd-arm64e-macos-26A428"
        ),
        "main": 0x100332040,
        "setup_impl": 0x100340A34,
        "request_token": 0x123,
        "product_id": b"",
        # FairPlayIOKit 72.19 uses the same packed major/minor convention as
        # the validated iOS profiles.
        "iokit_version": 0x48130000,
        "iokit_capabilities": 0x1F8,
        "startup_cache": Path(
            "artifacts/fairplay/cache/fairplayd-macos-26A428-startup-v1.json"
        ),
    },
    "ios-23E246": {
        "binary": Path("artifacts/fairplay/fairplayd-ios-23E246"),
        "main": MAIN,
        "setup_impl": SETUP_IMPL,
        "request_token": REQUEST_TOKEN,
        "product_id": DEFAULT_PRODUCT_ID,
        "iokit_version": DEFAULT_IOKIT_VERSION,
        "iokit_capabilities": DEFAULT_IOKIT_PROTOCOL_CAPABILITIES,
        "startup_cache": DEFAULT_STARTUP_CACHE,
    },
    "ios18-22G100": {
        "binary": Path("artifacts/fairplay/fairplayd-ios18-22G100"),
        "main": 0x100050170,
        "setup_impl": 0x1008B7924,
        "request_token": 0x01000101,
        "product_id": DEFAULT_PRODUCT_ID,
        "iokit_version": 0x4A1C0000,
        "iokit_capabilities": 0x1F8,
        # Runtime token reconstructed at the protected XPC dictionary-type
        # comparison (0x10081f040) under the sparse dyld binding model.
        "xpc_dictionary_type_token": 0xF0FFFFFFFACF6786,
        "startup_cache": Path(
            "artifacts/fairplay/cache/fairplayd-ios18-22G100-startup.json"
        ),
    },
}


def _read_evaluator_cstring(
    evaluator: Evaluator, pointer: int, limit: int = 0x1000
) -> str:
    data = bytearray()
    for offset in range(limit):
        byte = evaluator.read_mem(pointer + offset, 1)
        if byte == 0:
            break
        data.append(byte)
    return data.decode("utf-8", "replace")
FAIRPLAY_STATE_BASENAMES = frozenset(
    {
        "IC-Info.sidb",
        "IC-Info.sisb",
        "IC-Info.sidn",
        "IC-Info.sido",
        "IC-Info.sidd",
        "IC-Info.sidv",
        "IC-Info.sisv",
        "IC-Info.sids",
        "SC Info.sidb",
        "SC Info.sisb",
        "SC Info.sidn",
        "SC Info.sido",
        "SC Info.sidd",
        "SC Info.sidv",
        "SC Info.sisv",
        "SC Info.sids",
    }
)

ZERO_RETURN_IMPORTS = {
    "atexit",
    "munmap",
    "notify_cancel",
    "notify_post",
    "ptrace",
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
    "sched_yield",
    "signal",
    "umask",
}


def initialize_daemon(
    db: Any,
    *,
    main_address: int = MAIN,
    main_args: tuple[int, ...] = (0, 0, 0),
    initial_memory: dict[int, int] | None = None,
    ephemeral_multiuser: bool = False,
    memory_watch_ranges: tuple[tuple[int, int], ...] = (),
    recent_pc_limit: int = 0,
    stop_addresses: frozenset[int] = frozenset(),
    iokit_version: int = DEFAULT_IOKIT_VERSION,
    iokit_capabilities: int = DEFAULT_IOKIT_PROTOCOL_CAPABILITIES,
    iokit_struct_method_handlers: dict[
        int, Callable[[bytes, int, Evaluator], tuple[int, bytes]]
    ]
    | None = None,
    iokit_struct_method_input_overrides: dict[int, bytes] | None = None,
    unique_device_id: bytes = b"00000000-0000000000000000",
    probe_xpc_listener: bool = False,
    probe_xpc_message: bool = False,
    xpc_message_data: bytes | None = None,
    xpc_dictionary_type_token: int | None = None,
    file_payloads: dict[str, bytes] | None = None,
    file_stat_metadata: dict[str, dict[str, int]] | None = None,
    directory_paths: frozenset[str] = frozenset(),
    missing_files_are_enoent: bool = False,
) -> dict[str, Any]:
    """Build the process-startup overlay needed by protected import veneers."""

    evaluator = Evaluator(
        db,
        args=main_args,
        sp=STARTUP_SP,
        chained_pointer_base=IMAGE_BASE,
        chained_pointer_format="arm64e-userland",
        memory_watch_ranges=memory_watch_ranges,
        recent_pc_limit=recent_pc_limit,
    )
    if initial_memory is not None:
        evaluator.memory.update(initial_memory)
    pc = main_address
    once_tokens: set[int] = set()
    next_allocation = STARTUP_ALLOC_BASE
    random_state = 0x12345678
    total_instructions = 0
    external_calls: list[dict[str, Any]] = []
    pending_once_returns: dict[int, int] = {}
    objc_strings: dict[int, bytes] = {}
    objc_mc_profile = 0x700060001000
    objc_ak_device = 0x700060002000
    next_objc_object = 0x700060003000
    next_bootstrap_port = 0x500
    next_cf_object = 0x700070000000
    io_matching = 0x700080000000
    next_io_iterator = 0x600
    next_io_service = 0x700
    next_io_connection = 0x800
    io_iterator_services: dict[int, int] = {}
    next_xpc_connection = 0x700090000000
    next_fd = 0xA00
    open_files: dict[int, dict[str, Any]] = {}
    xpc_connections: dict[int, dict[str, Any]] = {}
    xpc_objects: dict[int, dict[str, Any]] = {}
    xpc_events: list[dict[str, Any]] = []
    xpc_listener_probe_active = False
    xpc_message_probe_active = False
    synthetic_sec_task = 0x7000A0000000
    synthetic_cf_boolean = 0x7000A0001000
    xpc_dictionary_type = (
        xpc_dictionary_type_token
        if xpc_dictionary_type_token is not None
        else next(
            (
                address
                for address, name in getattr(db.names, "names", {}).items()
                if name == "__xpc_type_dictionary"
            ),
            0xF10000000002A000,
        )
    )

    for index in range(1000):
        internal_xpc_probes = (
            frozenset({0x10081F040, 0x100DD0084})
            if xpc_message_probe_active
            else frozenset()
        )
        stop = evaluator.run(
            pc,
            max_instructions=100_000_000,
            follow_internal_transfers=True,
            breakpoints=stop_addresses | internal_xpc_probes,
        )
        total_instructions += stop.instructions
        if (
            stop.reason == "breakpoint"
            and stop.address in internal_xpc_probes
        ):
            xpc_events.append(
                {
                    "operation": "internal-register-probe",
                    "address": hex(stop.address),
                    "registers": {
                        name: hex(stop.registers[name])
                        for name in ("x0", "x8", "x19", "x20", "x23")
                    },
                }
            )
            pc = stop.address
            continue
        if stop.reason == "breakpoint" and stop.address in stop_addresses:
            startup_stop = {
                "reason": "breakpoint",
                "site": hex(stop.address),
                "target": None,
                "target_name": None,
                "x0": hex(evaluator.regs["x0"]),
            }
            break
        if stop.reason == "return" and stop.target in pending_once_returns:
            resume = pending_once_returns.pop(stop.target)
            evaluator.regs["x0"] = 0
            evaluator.regs["x30"] = resume
            pc = resume
            continue
        if (
            stop.reason == "return"
            and stop.target == XPC_LISTENER_RETURN
            and xpc_listener_probe_active
        ):
            if probe_xpc_message and not xpc_message_probe_active:
                peer = xpc_connections.get(SYNTHETIC_XPC_PEER, {})
                block_text = peer.get("event_handler_block")
                invoke_text = peer.get("event_handler_invoke")
                if block_text and invoke_text:
                    block = int(block_text, 16)
                    invoke = int(invoke_text, 16)
                    xpc_objects[SYNTHETIC_XPC_MESSAGE] = {
                        "address": hex(SYNTHETIC_XPC_MESSAGE),
                        "type": "dictionary",
                        "values": (
                            {"data": xpc_message_data}
                            if xpc_message_data is not None
                            else {}
                        ),
                        "explicitly_synthetic": True,
                    }
                    evaluator.regs["x0"] = block
                    evaluator.regs["x1"] = SYNTHETIC_XPC_MESSAGE
                    evaluator.regs["sp"] = STARTUP_SP - 0x40000
                    evaluator.regs["x30"] = XPC_MESSAGE_RETURN
                    pc = invoke
                    xpc_message_probe_active = True
                    continue
            startup_stop = {
                "reason": "xpc-listener-probe-return",
                "site": hex(stop.address),
                "target": hex(stop.target),
                "target_name": None,
                "x0": hex(evaluator.regs["x0"]),
                "explicitly_synthetic_peer": True,
            }
            break
        if (
            stop.reason == "return"
            and stop.target == XPC_MESSAGE_RETURN
            and xpc_message_probe_active
        ):
            startup_stop = {
                "reason": "xpc-message-probe-return",
                "site": hex(stop.address),
                "target": hex(stop.target),
                "target_name": None,
                "x0": hex(evaluator.regs["x0"]),
                "explicitly_synthetic_message": True,
            }
            break
        target_name = _target_name(db, stop.target)
        normalized_name = (target_name or "").lstrip("_")
        call_like = stop.reason in ("direct-call", "indirect") and stop.mnemonic.startswith(
            ("bl", "blr")
        )
        resume = stop.address + 4 if call_like else evaluator.regs["x30"]
        external_calls.append(
            {
                "index": index,
                "site": hex(stop.address),
                "target_name": target_name,
                "x0": hex(evaluator.regs["x0"]),
                "args": [hex(evaluator.regs[f"x{arg}"]) for arg in range(8)],
                "callee_saved": {
                    f"x{register}": hex(evaluator.regs[f"x{register}"])
                    for register in range(19, 29)
                },
                "sp": hex(evaluator.regs["sp"]),
                "instructions": total_instructions,
            }
        )

        handled = normalized_name in ZERO_RETURN_IMPORTS or normalized_name in {
            "arc4random",
            "bootstrap_check_in",
            "CFMachPortCreateRunLoopSource",
            "CFMachPortCreateWithPort",
            "CFFileDescriptorCreate",
            "CFFileDescriptorCreateRunLoopSource",
            "CFFileDescriptorEnableCallBacks",
            "CFBooleanGetTypeID",
            "CFBooleanGetValue",
            "CFGetTypeID",
            "CFRelease",
            "CFRunLoopAddSource",
            "CFRunLoopGetMain",
            "IOMainPort",
            "IOIteratorNext",
            "IOConnectCallStructMethod",
            "IOObjectRelease",
            "IOServiceGetMatchingServices",
            "IOServiceMatching",
            "IOServiceOpen",
            "chkstk_darwin",
            "container_system_path_for_identifier",
            "free",
            "getpid",
            "gettimeofday",
            "kevent",
            "kqueue",
            "malloc",
            "malloc_type_malloc",
            "memcpy",
            "memcpy_chk",
            "memset",
            "memset_chk",
            "memset_pattern16",
            "mmap",
            "open",
            "open_dprotected_np",
            "read",
            "close",
            "fstat",
            "stat",
            "lstat",
            "mkdir",
            "unlink",
            "write",
            "objc_autoreleasePoolPop",
            "objc_autoreleasePoolPush",
            "objc_msgSend",
            "proc_pidpath",
            "SecTaskCopyValueForEntitlement",
            "SecTaskCreateWithAuditToken",
            "strlen",
            "strnlen",
            "sysconf",
            "time",
            "xpc_connection_activate",
            "xpc_connection_cancel",
            "xpc_connection_create_mach_service",
            "xpc_connection_resume",
            "xpc_connection_send_message",
            "xpc_connection_set_event_handler",
            "xpc_connection_set_target_queue",
            "xpc_dictionary_create_empty",
            "xpc_dictionary_create_reply",
            "xpc_dictionary_get_audit_token",
            "xpc_dictionary_get_data",
            "xpc_dictionary_set_data",
            "xpc_dictionary_set_int64",
            "xpc_get_type",
            "xpc_release",
        }
        if handled:
            if normalized_name in ZERO_RETURN_IMPORTS:
                evaluator.regs["x0"] = 0
            elif normalized_name == "sysconf":
                # _SC_PAGESIZE on iOS arm64.
                evaluator.regs["x0"] = 0x4000
            elif normalized_name in ("mmap", "malloc", "malloc_type_malloc"):
                if normalized_name == "mmap":
                    descriptor = evaluator.regs["x4"]
                    entry = open_files.get(descriptor)
                    if entry is not None:
                        mapped = next_allocation
                        length = evaluator.regs["x1"]
                        file_offset = evaluator.regs["x5"]
                        data = entry["data"][file_offset : file_offset + length]
                        for offset, byte in enumerate(data):
                            evaluator.memory[mapped + offset] = byte
                        next_allocation += (max(length, 0x100) + 0xFFF) & ~0xFFF
                        evaluator.regs["x0"] = mapped
                        external_calls[-1]["file_path"] = entry["path"]
                        external_calls[-1]["mapped_size"] = len(data)
                    else:
                        size = evaluator.regs["x1"]
                        evaluator.regs["x0"] = next_allocation
                        next_allocation += (max(size, 0x100) + 0xFFF) & ~0xFFF
                else:
                    size = evaluator.regs["x0"]
                    evaluator.regs["x0"] = next_allocation
                    next_allocation += (max(size, 0x100) + 0xFFF) & ~0xFFF
            elif normalized_name in ("open", "open_dprotected_np"):
                file_path = _read_evaluator_cstring(evaluator, evaluator.regs["x0"])
                payload = next(
                    (
                        candidate
                        for suffix, candidate in (file_payloads or {}).items()
                        if file_path.endswith(suffix)
                    ),
                    None,
                )
                external_calls[-1]["file_path"] = file_path
                external_calls[-1]["file_present"] = payload is not None
                if payload is None:
                    if not missing_files_are_enoent:
                        handled = False
                    else:
                        evaluator.regs["x0"] = 0xFFFFFFFFFFFFFFFF
                else:
                    descriptor = next_fd
                    next_fd += 1
                    open_files[descriptor] = {
                        "data": payload,
                        "offset": 0,
                        "path": file_path,
                        "stat": _matching_file_stat(
                            file_stat_metadata, file_path
                        ),
                    }
                    evaluator.regs["x0"] = descriptor
            elif normalized_name in ("stat", "lstat"):
                file_path = _read_evaluator_cstring(evaluator, evaluator.regs["x0"])
                payload = next(
                    (
                        candidate
                        for suffix, candidate in (file_payloads or {}).items()
                        if file_path.endswith(suffix)
                    ),
                    None,
                )
                is_directory = file_path.rstrip("/") in {
                    path.rstrip("/") for path in directory_paths
                }
                external_calls[-1]["file_path"] = file_path
                external_calls[-1]["file_present"] = payload is not None or is_directory
                if payload is None and not is_directory:
                    if not missing_files_are_enoent:
                        handled = False
                    else:
                        evaluator.regs["x0"] = 0xFFFFFFFFFFFFFFFF
                else:
                    stat_buffer = evaluator.regs["x1"]
                    if is_directory:
                        for offset in range(144):
                            evaluator.write_mem(stat_buffer + offset, 0, 1)
                        evaluator.write_mem(stat_buffer + 4, 0o040700, 2)
                    else:
                        _write_darwin_stat(
                            evaluator,
                            stat_buffer,
                            len(payload) if payload is not None else 0,
                            _matching_file_stat(
                                file_stat_metadata, file_path
                            ),
                        )
                    evaluator.regs["x0"] = 0
            elif normalized_name == "fstat":
                entry = open_files.get(evaluator.regs["x0"])
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
                entry = open_files.get(evaluator.regs["x0"])
                if entry is None:
                    handled = False
                else:
                    count = evaluator.regs["x2"]
                    offset = entry["offset"]
                    data = entry["data"][offset : offset + count]
                    for byte_offset, byte in enumerate(data):
                        evaluator.write_mem(
                            evaluator.regs["x1"] + byte_offset, byte, 1
                        )
                    entry["offset"] += len(data)
                    evaluator.regs["x0"] = len(data)
                    external_calls[-1]["file_path"] = entry["path"]
                    external_calls[-1]["read_size"] = len(data)
            elif normalized_name == "close":
                open_files.pop(evaluator.regs["x0"], None)
                evaluator.regs["x0"] = 0
            elif normalized_name == "write":
                entry = open_files.get(evaluator.regs["x0"])
                if entry is None:
                    handled = False
                else:
                    # Startup replay is read-only with respect to host files.
                    # Report a successful in-process write without changing the
                    # supplied captured artifact.
                    evaluator.regs["x0"] = evaluator.regs["x2"]
                    external_calls[-1]["file_path"] = entry["path"]
                    external_calls[-1]["modeled_write_size"] = evaluator.regs["x2"]
            elif normalized_name == "mkdir":
                file_path = _read_evaluator_cstring(evaluator, evaluator.regs["x0"])
                external_calls[-1]["file_path"] = file_path
                evaluator.regs["x0"] = (
                    0
                    if file_path.rstrip("/") in {
                        path.rstrip("/") for path in directory_paths
                    }
                    else 0xFFFFFFFFFFFFFFFF
                )
            elif normalized_name == "unlink":
                file_path = _read_evaluator_cstring(evaluator, evaluator.regs["x0"])
                external_calls[-1]["file_path"] = file_path
                external_calls[-1]["modeled_read_only"] = True
                evaluator.regs["x0"] = 0
            elif normalized_name == "arc4random":
                random_state = (
                    1664525 * random_state + 1013904223
                ) & 0xFFFFFFFF
                evaluator.regs["x0"] = random_state
            elif normalized_name == "gettimeofday":
                if evaluator.regs["x0"]:
                    evaluator.write_mem(evaluator.regs["x0"], 1_700_000_000, 8)
                    evaluator.write_mem(evaluator.regs["x0"] + 8, 0, 8)
                evaluator.regs["x0"] = 0
            elif normalized_name == "getpid":
                evaluator.regs["x0"] = 1234
            elif normalized_name == "kqueue":
                evaluator.regs["x0"] = 0x900
            elif normalized_name == "kevent":
                # This startup call only registers one EVFILT_SIGNAL change;
                # it does not wait for events.  Preserve a real blocking
                # kevent boundary if the daemon later reaches one.
                if (
                    evaluator.regs["x1"]
                    and evaluator.regs["x2"]
                    and evaluator.regs["x3"] == 0
                    and evaluator.regs["x4"] == 0
                ):
                    evaluator.regs["x0"] = 0
                    external_calls[-1]["mode"] = "register-changelist"
                else:
                    handled = False
            elif normalized_name == "xpc_connection_create_mach_service":
                service_name = _read_evaluator_cstring(
                    evaluator, evaluator.regs["x0"]
                )
                connection = next_xpc_connection
                next_xpc_connection += 0x1000
                xpc_connections[connection] = {
                    "address": hex(connection),
                    "service_name": service_name,
                    "flags": hex(evaluator.regs["x2"]),
                }
                evaluator.regs["x0"] = connection
                external_calls[-1]["service_name"] = service_name
                external_calls[-1]["modeled_connection"] = hex(connection)
            elif normalized_name == "xpc_connection_set_event_handler":
                connection = evaluator.regs["x0"]
                block = evaluator.regs["x1"]
                metadata = xpc_connections.setdefault(
                    connection, {"address": hex(connection)}
                )
                metadata["event_handler_block"] = hex(block)
                metadata["event_handler_invoke"] = hex(
                    evaluator.read_mem(block + 0x10, 8)
                )
                external_calls[-1]["event_handler_block"] = hex(block)
                external_calls[-1]["event_handler_invoke"] = metadata[
                    "event_handler_invoke"
                ]
            elif normalized_name in {
                "xpc_connection_activate",
                "xpc_connection_cancel",
                "xpc_connection_resume",
                "xpc_connection_send_message",
                "xpc_connection_set_target_queue",
            }:
                connection = evaluator.regs["x0"]
                metadata = xpc_connections.setdefault(
                    connection, {"address": hex(connection)}
                )
                if normalized_name in {
                    "xpc_connection_activate",
                    "xpc_connection_resume",
                }:
                    metadata["activated"] = True
                elif normalized_name == "xpc_connection_cancel":
                    metadata["cancelled"] = True
                elif normalized_name == "xpc_connection_send_message":
                    xpc_events.append(
                        {
                            "operation": "connection-send-message",
                            "connection": hex(connection),
                            "message": hex(evaluator.regs["x1"]),
                        }
                    )
            elif normalized_name == "xpc_get_type":
                metadata = xpc_objects.get(evaluator.regs["x0"])
                if metadata is None:
                    handled = False
                else:
                    evaluator.regs["x0"] = (
                        xpc_dictionary_type
                        if metadata.get("type") == "dictionary"
                        else 0
                    )
            elif normalized_name == "xpc_dictionary_get_audit_token":
                destination = evaluator.regs["x1"]
                # audit_token_t is eight uint32_t words.  Use a plausible
                # mobile daemon identity with a live PID; all authorization
                # decisions still flow through the explicitly modeled
                # SecTask entitlement check below.
                audit_words = (501, 501, 20, 501, 20, 1234, 100000, 1)
                for word_index, value in enumerate(audit_words):
                    evaluator.write_mem(
                        destination + word_index * 4, value, 4
                    )
                xpc_events.append(
                    {
                        "operation": "dictionary-get-audit-token",
                        "dictionary": hex(evaluator.regs["x0"]),
                        "modeled_pid": 1234,
                    }
                )
            elif normalized_name == "xpc_dictionary_get_data":
                dictionary = evaluator.regs["x0"]
                key = _read_evaluator_cstring(
                    evaluator, evaluator.regs["x1"]
                )
                metadata = xpc_objects.get(dictionary)
                if metadata is None:
                    handled = False
                else:
                    value = metadata.get("values", {}).get(key)
                    if evaluator.regs["x2"]:
                        evaluator.write_mem(
                            evaluator.regs["x2"],
                            len(value) if isinstance(value, bytes) else 0,
                            8,
                        )
                    if isinstance(value, bytes):
                        value_address = next_allocation
                        next_allocation += (len(value) + 0xFFF) & ~0xFFF
                        for offset, byte in enumerate(value):
                            evaluator.write_mem(value_address + offset, byte, 1)
                        evaluator.regs["x0"] = value_address
                    else:
                        evaluator.regs["x0"] = 0
                    xpc_events.append(
                        {
                            "operation": "dictionary-get-data",
                            "dictionary": hex(dictionary),
                            "key": key,
                            "present": isinstance(value, bytes),
                            "size": len(value) if isinstance(value, bytes) else 0,
                        }
                    )
                    external_calls[-1]["xpc_key"] = key
            elif normalized_name in {
                "xpc_dictionary_create_empty",
                "xpc_dictionary_create_reply",
            }:
                dictionary = next_xpc_connection
                next_xpc_connection += 0x1000
                xpc_objects[dictionary] = {
                    "address": hex(dictionary),
                    "type": "dictionary",
                    "values": {},
                    "source": normalized_name,
                }
                evaluator.regs["x0"] = dictionary
            elif normalized_name in {
                "xpc_dictionary_set_data",
                "xpc_dictionary_set_int64",
            }:
                dictionary = evaluator.regs["x0"]
                key = _read_evaluator_cstring(
                    evaluator, evaluator.regs["x1"]
                )
                metadata = xpc_objects.setdefault(
                    dictionary,
                    {
                        "address": hex(dictionary),
                        "type": "dictionary",
                        "values": {},
                    },
                )
                if normalized_name == "xpc_dictionary_set_data":
                    modeled_value = {
                        "kind": "data",
                        "size": evaluator.regs["x3"],
                    }
                else:
                    modeled_value = {
                        "kind": "int64",
                        "value": evaluator.regs["x2"],
                    }
                metadata["values"][key] = modeled_value
                xpc_events.append(
                    {
                        "operation": normalized_name,
                        "dictionary": hex(dictionary),
                        "key": key,
                        "value": modeled_value,
                    }
                )
            elif normalized_name == "SecTaskCreateWithAuditToken":
                evaluator.regs["x0"] = synthetic_sec_task
                xpc_events.append({"operation": "sec-task-create"})
            elif normalized_name == "SecTaskCopyValueForEntitlement":
                entitlement = evaluator.regs["x1"]
                string_pointer = evaluator.read_mem(entitlement + 0x10, 8)
                string_length = evaluator.read_mem(entitlement + 0x18, 8)
                string_value = None
                if string_pointer and string_length <= 0x1000:
                    string_value = bytes(
                        evaluator.read_mem(string_pointer + offset, 1)
                        for offset in range(string_length)
                    ).decode("utf-8", "replace")
                evaluator.regs["x0"] = synthetic_cf_boolean
                xpc_events.append(
                    {
                        "operation": "copy-entitlement",
                        "entitlement_object": hex(entitlement),
                        "entitlement": string_value,
                        "modeled_value": True,
                    }
                )
            elif normalized_name == "xpc_release":
                pass
            elif normalized_name == "container_system_path_for_identifier":
                # Private libsystem ABI: returns an allocated path and stores
                # a container_error_t through x1 only on failure.  The daemon
                # seeds that slot with sentinel 1 and requires it to remain 1
                # when a non-null path is returned.  A NULL identifier asks
                # for the current daemon's system container.
                path = b"/private/var/mobile/Library/FairPlay\0"
                path_address = next_allocation
                next_allocation += 0x1000
                for offset, byte in enumerate(path):
                    evaluator.write_mem(path_address + offset, byte, 1)
                evaluator.regs["x0"] = path_address
                external_calls[-1]["modeled_path"] = path[:-1].decode()
            elif normalized_name == "bootstrap_check_in":
                service_name = _read_evaluator_cstring(
                    evaluator, evaluator.regs["x1"]
                )
                destination = evaluator.regs["x2"]
                if destination:
                    evaluator.write_mem(destination, next_bootstrap_port, 4)
                evaluator.regs["x0"] = 0
                external_calls[-1]["service_name"] = service_name
                external_calls[-1]["modeled_port"] = hex(next_bootstrap_port)
                next_bootstrap_port += 1
            elif normalized_name == "CFMachPortCreateWithPort":
                if evaluator.regs["x4"]:
                    evaluator.write_mem(evaluator.regs["x4"], 0, 1)
                evaluator.regs["x0"] = next_cf_object
                external_calls[-1]["mach_port"] = hex(
                    evaluator.regs["x1"] & 0xFFFFFFFF
                )
                external_calls[-1]["callback"] = hex(evaluator.regs["x2"])
                next_cf_object += 0x1000
            elif normalized_name == "CFMachPortCreateRunLoopSource":
                evaluator.regs["x0"] = next_cf_object
                next_cf_object += 0x1000
            elif normalized_name == "CFFileDescriptorCreate":
                evaluator.regs["x0"] = next_cf_object
                external_calls[-1]["file_descriptor"] = hex(
                    evaluator.regs["x1"] & 0xFFFFFFFF
                )
                external_calls[-1]["callback"] = hex(evaluator.regs["x3"])
                next_cf_object += 0x1000
            elif normalized_name == "CFFileDescriptorCreateRunLoopSource":
                evaluator.regs["x0"] = next_cf_object
                next_cf_object += 0x1000
            elif normalized_name == "CFFileDescriptorEnableCallBacks":
                pass
            elif normalized_name == "CFRunLoopGetMain":
                evaluator.regs["x0"] = 0x70007000F000
            elif normalized_name == "CFRunLoopAddSource":
                pass
            elif normalized_name == "CFRelease":
                pass
            elif normalized_name in {"CFBooleanGetTypeID", "CFGetTypeID"}:
                evaluator.regs["x0"] = 1
            elif normalized_name == "CFBooleanGetValue":
                evaluator.regs["x0"] = int(
                    evaluator.regs["x0"] == synthetic_cf_boolean
                )
            elif normalized_name == "IOMainPort":
                if evaluator.regs["x1"]:
                    evaluator.write_mem(evaluator.regs["x1"], 1, 4)
                evaluator.regs["x0"] = 0
            elif normalized_name == "IOServiceMatching":
                external_calls[-1]["service_name"] = _read_evaluator_cstring(
                    evaluator, evaluator.regs["x0"]
                )
                evaluator.regs["x0"] = io_matching
            elif normalized_name == "IOServiceGetMatchingServices":
                destination = evaluator.regs["x2"]
                iterator = next_io_iterator
                service = next_io_service
                next_io_iterator += 1
                next_io_service += 1
                io_iterator_services[iterator] = service
                evaluator.write_mem(destination, iterator, 4)
                evaluator.regs["x0"] = 0
                external_calls[-1]["modeled_iterator"] = hex(iterator)
                external_calls[-1]["modeled_service"] = hex(service)
            elif normalized_name == "IOIteratorNext":
                iterator = evaluator.regs["x0"] & 0xFFFFFFFF
                evaluator.regs["x0"] = io_iterator_services.pop(iterator, 0)
            elif normalized_name == "IOServiceOpen":
                destination = evaluator.regs["x3"]
                connection = next_io_connection
                next_io_connection += 1
                evaluator.write_mem(destination, connection, 4)
                evaluator.regs["x0"] = 0
                external_calls[-1]["modeled_connection"] = hex(connection)
            elif normalized_name == "IOObjectRelease":
                evaluator.regs["x0"] = 0
            elif normalized_name == "IOConnectCallStructMethod":
                selector = evaluator.regs["x1"] & 0xFFFFFFFF
                output = evaluator.regs["x4"]
                output_size_pointer = evaluator.regs["x5"]
                output_capacity = (
                    evaluator.read_mem(output_size_pointer, 8)
                    if output_size_pointer
                    else 0
                )
                external_calls[-1]["selector"] = hex(selector)
                external_calls[-1]["input_size"] = evaluator.regs["x3"]
                if selector == 0x16:
                    evaluator.write_mem(output, iokit_version, 4)
                    evaluator.write_mem(output_size_pointer, 4, 8)
                    evaluator.regs["x0"] = 0
                elif selector == 0x17:
                    evaluator.write_mem(output, iokit_capabilities, 4)
                    evaluator.write_mem(output_size_pointer, 4, 8)
                    evaluator.regs["x0"] = 0
                else:
                    handler = (
                        iokit_struct_method_handlers.get(selector)
                        if iokit_struct_method_handlers is not None
                        else None
                    )
                    if handler is None:
                        handled = False
                    else:
                        input_size = evaluator.regs["x3"]
                        override = (
                            iokit_struct_method_input_overrides.get(selector)
                            if iokit_struct_method_input_overrides is not None
                            else None
                        )
                        if override is not None:
                            if len(override) != input_size:
                                raise RuntimeError(
                                    f"startup selector {selector:#x} input "
                                    f"override is {len(override):#x} bytes, "
                                    f"expected {input_size:#x}"
                                )
                            for offset, byte in enumerate(override):
                                evaluator.write_mem(
                                    evaluator.regs["x2"] + offset, byte, 1
                                )
                            external_calls[-1]["input_override_sha256"] = (
                                hashlib.sha256(override).hexdigest()
                            )
                        input_data = bytes(
                            evaluator.read_mem(evaluator.regs["x2"] + offset, 1)
                            for offset in range(input_size)
                        )
                        modeled_return, modeled_output = handler(
                            input_data, output_capacity, evaluator
                        )
                        if len(modeled_output) > output_capacity:
                            raise RuntimeError(
                                f"startup selector {selector:#x} output "
                                f"exceeds capacity {output_capacity:#x}"
                            )
                        for offset, byte in enumerate(modeled_output):
                            evaluator.write_mem(output + offset, byte, 1)
                        evaluator.write_mem(
                            output_size_pointer, len(modeled_output), 8
                        )
                        evaluator.regs["x0"] = modeled_return & 0xFFFFFFFF
                        external_calls[-1]["modeled_return"] = hex(
                            modeled_return & 0xFFFFFFFF
                        )
                        external_calls[-1]["modeled_output_size"] = len(
                            modeled_output
                        )
            elif normalized_name == "objc_autoreleasePoolPush":
                evaluator.regs["x0"] = 0x700060000000
            elif normalized_name == "objc_autoreleasePoolPop":
                pass
            elif normalized_name == "objc_msgSend":
                selector = _read_evaluator_cstring(
                    evaluator, evaluator.regs["x1"]
                )
                external_calls[-1]["selector"] = selector
                if selector == "sharedConnection":
                    evaluator.regs["x0"] = objc_mc_profile
                elif selector == "isEphemeralMultiUser":
                    evaluator.regs["x0"] = int(ephemeral_multiuser)
                elif selector == "currentDevice":
                    evaluator.regs["x0"] = objc_ak_device
                elif selector == "uniqueDeviceIdentifier":
                    address = next_objc_object
                    next_objc_object += 0x1000
                    objc_strings[address] = unique_device_id
                    evaluator.regs["x0"] = address
                elif selector == "serverFriendlyDescription":
                    address = next_objc_object
                    next_objc_object += 0x1000
                    objc_strings[address] = b"iPhone"
                    evaluator.regs["x0"] = address
                elif selector == "UTF8String":
                    value = objc_strings.get(evaluator.regs["x0"])
                    if value is None:
                        handled = False
                    else:
                        address = next_allocation
                        next_allocation += 0x1000
                        for offset, byte in enumerate(value + b"\0"):
                            evaluator.write_mem(address + offset, byte, 1)
                        evaluator.regs["x0"] = address
                elif selector == "length":
                    value = objc_strings.get(evaluator.regs["x0"])
                    if value is None:
                        handled = False
                    else:
                        evaluator.regs["x0"] = len(value)
                else:
                    handled = False
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
            elif normalized_name in ("strlen", "strnlen"):
                limit = (
                    evaluator.regs["x1"]
                    if normalized_name == "strnlen"
                    else 0x100000
                )
                evaluator.regs["x0"] = len(
                    _read_evaluator_cstring(
                        evaluator, evaluator.regs["x0"], min(limit, 0x100000)
                    ).encode()
                )
            elif normalized_name in ("memcpy", "memcpy_chk"):
                destination = evaluator.regs["x0"]
                source = evaluator.regs["x1"]
                count = min(evaluator.regs["x2"], 0x100000)
                data = [evaluator.read_mem(source + offset, 1) for offset in range(count)]
                for offset, byte in enumerate(data):
                    evaluator.write_mem(destination + offset, byte, 1)
                evaluator.regs["x0"] = destination
            elif normalized_name in ("memset", "memset_chk"):
                destination = evaluator.regs["x0"]
                value = evaluator.regs["x1"] & 0xFF
                count = min(evaluator.regs["x2"], 0x100000)
                for offset in range(count):
                    evaluator.write_mem(destination + offset, value, 1)
                evaluator.regs["x0"] = destination
            elif normalized_name == "memset_pattern16":
                destination = evaluator.regs["x0"]
                pattern = bytes(
                    evaluator.read_mem(evaluator.regs["x1"] + offset, 1)
                    for offset in range(16)
                )
                for offset in range(evaluator.regs["x2"]):
                    evaluator.write_mem(
                        destination + offset, pattern[offset % 16], 1
                    )
            elif normalized_name == "time":
                if evaluator.regs["x0"]:
                    evaluator.write_mem(evaluator.regs["x0"], 1_700_000_000, 8)
                evaluator.regs["x0"] = 1_700_000_000
            # free and chkstk_darwin preserve the relevant state.
            if handled:
                evaluator.regs["x30"] = resume
                pc = resume
                continue

        if normalized_name == "pthread_once":
            token = evaluator.regs["x0"]
            if token in once_tokens:
                evaluator.regs["x0"] = 0
                evaluator.regs["x30"] = resume
                pc = resume
            else:
                once_tokens.add(token)
                sentinel = PTHREAD_ONCE_RETURN_BASE + len(once_tokens) * 0x1000
                pending_once_returns[sentinel] = resume
                evaluator.regs["x30"] = sentinel
                pc = evaluator.regs["x1"]
            continue

        if (
            normalized_name == "CFRunLoopRun"
            and probe_xpc_listener
            and not xpc_listener_probe_active
        ):
            listener = next(
                (
                    (address, metadata)
                    for address, metadata in xpc_connections.items()
                    if metadata.get("service_name")
                    == "com.apple.fairplayd.xpc"
                    and metadata.get("event_handler_block")
                    and metadata.get("event_handler_invoke")
                ),
                None,
            )
            if listener is not None:
                _, metadata = listener
                block = int(metadata["event_handler_block"], 16)
                invoke = int(metadata["event_handler_invoke"], 16)
                xpc_connections[SYNTHETIC_XPC_PEER] = {
                    "address": hex(SYNTHETIC_XPC_PEER),
                    "kind": "synthetic-inbound-peer-probe",
                    "explicitly_synthetic": True,
                }
                external_calls[-1]["listener_probe"] = {
                    "explicitly_synthetic": True,
                    "block": hex(block),
                    "invoke": hex(invoke),
                    "peer": hex(SYNTHETIC_XPC_PEER),
                }
                evaluator.regs["x0"] = block
                evaluator.regs["x1"] = SYNTHETIC_XPC_PEER
                evaluator.regs["sp"] = STARTUP_SP - 0x20000
                evaluator.regs["x30"] = XPC_LISTENER_RETURN
                pc = invoke
                xpc_listener_probe_active = True
                continue

        startup_stop = {
            "reason": stop.reason,
            "site": hex(stop.address),
            "target": hex(stop.target) if stop.target is not None else None,
            "target_name": target_name,
            "x0": hex(evaluator.regs["x0"]),
        }
        break
    else:
        startup_stop = {"reason": "stage-limit"}

    result = {
        "memory": evaluator.memory,
        "once_tokens": once_tokens,
        "stop": startup_stop,
        "main_status_address": STARTUP_SP - 0x9C,
        "main_status": evaluator.read_mem(STARTUP_SP - 0x9C, 4),
        "final_registers": evaluator.snapshot(),
        "final_vector_registers": {
            name: value
            for name, value in evaluator.regs.items()
            if name.startswith("v") and name[1:].isdigit()
        },
        "final_nzcv": dict(evaluator.nzcv),
        "instructions": total_instructions,
        "external_calls": external_calls,
        "xpc_connections": list(xpc_connections.values()),
        "xpc_objects": [
            {
                **metadata,
                "values": {
                    key: (
                        {
                            "kind": "data",
                            "size": len(value),
                            "sha256": hashlib.sha256(value).hexdigest(),
                        }
                        if isinstance(value, bytes)
                        else value
                    )
                    for key, value in metadata.get("values", {}).items()
                },
            }
            for metadata in xpc_objects.values()
        ],
        "xpc_events": xpc_events,
        "next_allocation": next_allocation,
    }
    if probe_xpc_listener:
        ascii_strings: list[dict[str, Any]] = []
        run_start: int | None = None
        run = bytearray()
        previous: int | None = None

        def finish_ascii_run() -> None:
            nonlocal run_start, run
            if run_start is not None and len(run) >= 5 and any(
                (65 <= byte <= 90) or (97 <= byte <= 122) for byte in run
            ):
                ascii_strings.append(
                    {
                        "address": hex(run_start),
                        "value": bytes(run).decode("ascii"),
                    }
                )
            run_start = None
            run = bytearray()

        for address in sorted(evaluator.memory):
            byte = evaluator.memory[address]
            contiguous = previous is not None and address == previous + 1
            if not contiguous:
                finish_ascii_run()
            if 0x20 <= byte <= 0x7E:
                if run_start is None:
                    run_start = address
                run.append(byte)
            else:
                finish_ascii_run()
            previous = address
        finish_ascii_run()
        result["ascii_strings"] = ascii_strings[:10000]
    if memory_watch_ranges:
        result["memory_accesses"] = evaluator.memory_accesses
    if evaluator.recent_pcs is not None:
        result["recent_pcs"] = list(evaluator.recent_pcs)
    return result


def startup_cache_fingerprint(binary: Path) -> dict[str, Any]:
    """Identify every local input that can change the startup overlay."""

    script_directory = Path(__file__).resolve().parent
    inputs = (
        binary,
        Path(__file__).resolve(),
        script_directory / "ida_static_arm64.py",
        script_directory / "raw_macho_db.py",
    )
    return {
        "schema": STARTUP_CACHE_SCHEMA,
        "inputs": {
            str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in inputs
        },
    }


def load_startup_cache(path: Path, fingerprint: dict[str, Any]) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    if path.name.endswith(".json.gz"):
        try:
            with gzip.open(path, "rt") as stream:
                cached = json.load(stream)
            if (
                cached.get("schema") != "ipatool-fairplay-startup-cache-v1"
                or cached.get("binary_sha256") not in fingerprint["inputs"].values()
            ):
                return None
            return {
                "memory": {
                    int(address, 16): value
                    for address, value in cached["memory"]
                },
                "once_tokens": {
                    int(value, 16) for value in cached["once_tokens"]
                },
                "stop": {
                    "reason": "packaged-build-startup-cache",
                    "site": None,
                    "target": None,
                    "target_name": "CFRunLoopRun",
                    "x0": "0x0",
                },
                "instructions": 0,
                "external_calls": [],
                "xpc_connections": [],
                "xpc_objects": [],
                "xpc_events": [],
                "ascii_strings": [],
                "recent_pcs": [],
            }
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None
    if path.name.endswith(".pkl.gz"):
        try:
            with gzip.open(path, "rb") as stream:
                checkpoint = pickle.load(stream)
            if checkpoint.get("schema") != 1:
                return None
            binary = Path(checkpoint["binary"])
            if hashlib.sha256(binary.read_bytes()).hexdigest() != checkpoint.get(
                "binary_sha256"
            ):
                return None
            return {
                "memory": dict(checkpoint["memory"]),
                "once_tokens": set(checkpoint.get("once_tokens", ())),
                "stop": {
                    "reason": "native-startup-checkpoint",
                    "site": checkpoint.get("pc"),
                    "target": None,
                    "target_name": "CFRunLoopRun",
                    "x0": "0x0",
                },
                "instructions": 0,
                "external_calls": [],
                "xpc_connections": [],
                "xpc_objects": [],
                "xpc_events": [],
                "ascii_strings": [],
                "recent_pcs": [],
            }
        except (KeyError, OSError, TypeError, ValueError, pickle.UnpicklingError):
            return None
    try:
        cached = json.loads(path.read_text())
        if cached.get("fingerprint") != fingerprint:
            return None
        startup = cached["startup"]
        return {
            **startup,
            "memory": {
                int(address, 16): value for address, value in startup["memory"]
            },
            "once_tokens": set(startup["once_tokens"]),
        }
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def save_startup_cache(
    path: Path,
    fingerprint: dict[str, Any],
    startup: dict[str, Any],
) -> None:
    serialized = {
        **startup,
        "memory": [[hex(address), value] for address, value in startup["memory"].items()],
        "once_tokens": sorted(startup["once_tokens"]),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(
            {"fingerprint": fingerprint, "startup": serialized},
            separators=(",", ":"),
        )
    )
    temporary.replace(path)


def contiguous_ranges(offsets: set[int]) -> list[tuple[int, int]]:
    ranges: list[list[int]] = []
    for offset in sorted(offsets):
        if not ranges or offset != ranges[-1][1]:
            ranges.append([offset, offset + 1])
        else:
            ranges[-1][1] += 1
    return [(start, end) for start, end in ranges]


def parse_address_range(value: str) -> tuple[int, int]:
    try:
        start_text, end_text = value.split(":", 1)
        start = int(start_text, 0)
        end = int(end_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected START:END") from error
    if end <= start:
        raise argparse.ArgumentTypeError("watch-range END must be greater than START")
    return start, end


def parse_state_probe(value: str) -> tuple[str, int]:
    name, separator, size_text = value.partition(":")
    if name not in FAIRPLAY_STATE_BASENAMES:
        raise argparse.ArgumentTypeError(
            "state probe name must be one of "
            + ", ".join(sorted(FAIRPLAY_STATE_BASENAMES))
        )
    try:
        size = int(size_text, 0) if separator else 0
    except ValueError as error:
        raise argparse.ArgumentTypeError("state probe size must be an integer") from error
    if not 0 <= size <= 0x100000:
        raise argparse.ArgumentTypeError("state probe size must be between 0 and 1 MiB")
    return name, size


def parse_register_override(value: str) -> tuple[int, str, int, int]:
    try:
        parts = value.split(":")
        if len(parts) not in (3, 4):
            raise ValueError
        address_text, register, value_text = parts[:3]
        address = int(address_text, 0)
        register_value = int(value_text, 0)
        hit = int(parts[3], 0) if len(parts) == 4 else 1
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected ADDRESS:REGISTER:VALUE[:HIT]"
        ) from error
    if register not in ({f"x{index}" for index in range(31)} | {"sp"}):
        raise argparse.ArgumentTypeError("REGISTER must be x0..x30 or sp")
    if hit < 0:
        raise argparse.ArgumentTypeError("HIT must be zero (every hit) or greater")
    return address, register, register_value, hit


def parse_memory_qword_override(value: str) -> tuple[int, int]:
    try:
        address_text, value_text = value.split(":", 1)
        address = int(address_text, 0)
        qword_value = int(value_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected ADDRESS:VALUE") from error
    if not 0 <= address < (1 << 64):
        raise argparse.ArgumentTypeError("ADDRESS must fit in an unsigned qword")
    if not 0 <= qword_value < (1 << 64):
        raise argparse.ArgumentTypeError("VALUE must fit in an unsigned qword")
    return address, qword_value


def parse_address_redirect(value: str) -> tuple[int, int]:
    try:
        source_text, target_text = value.split(":", 1)
        source = int(source_text, 0)
        target = int(target_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected FROM:TO") from error
    return source, target


def parse_memory_copy(value: str) -> tuple[int, int, int, int]:
    try:
        pc_text, source_text, destination_text, size_text = value.split(":", 3)
        pc = int(pc_text, 0)
        source = int(source_text, 0)
        destination = int(destination_text, 0)
        size = int(size_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected PC:SOURCE:DESTINATION:SIZE"
        ) from error
    if not 0 < size <= 0x100000:
        raise argparse.ArgumentTypeError("SIZE must be between 1 and 1 MiB")
    return pc, source, destination, size


def parse_file_payload(value: str) -> tuple[str, Path]:
    try:
        suffix, path_text = value.split("=", 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected SUFFIX=PATH") from error
    if not suffix:
        raise argparse.ArgumentTypeError("SUFFIX must not be empty")
    return suffix, Path(path_text)


FAIRPLAY_STAT_FIELDS = frozenset(
    {
        "dev", "nlink", "ino", "rdev", "atime", "atime_nsec",
        "mtime", "mtime_nsec", "ctime", "ctime_nsec", "birthtime",
        "birthtime_nsec", "blocks", "blksize", "flags", "gen",
    }
)


def parse_fairplay_stat_field(value: str) -> tuple[str, int]:
    try:
        name, raw_value = value.split("=", 1)
        parsed = int(raw_value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected NAME=VALUE") from error
    if name not in FAIRPLAY_STAT_FIELDS:
        raise argparse.ArgumentTypeError(
            "unknown stat field; expected one of "
            + ", ".join(sorted(FAIRPLAY_STAT_FIELDS))
        )
    return name, parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--daemon-profile",
        choices=sorted(DAEMON_BUILD_PROFILES),
        default="ios-23E246",
        help="exact fairplayd build/address profile",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        help="override the daemon profile's Mach-O",
    )
    parser.add_argument(
        "--startup-cache",
        type=Path,
        help=(
            "validated cache for the deterministic daemon-startup overlay; "
            "defaults to the daemon profile's build-specific path"
        ),
    )
    parser.add_argument(
        "--main-address",
        type=lambda value: int(value, 0),
        help="exact-build LC_MAIN address used to initialize protected globals",
    )
    parser.add_argument(
        "--setup-impl-address",
        type=lambda value: int(value, 0),
        help="exact-build implementation called by the request-502 MIG stub",
    )
    parser.add_argument(
        "--request-token",
        type=lambda value: int(value, 0),
        help="MIG request token passed as the first handler argument",
    )
    parser.add_argument(
        "--audit-token-hex",
        type=bytes.fromhex,
        help=(
            "exact 32-byte request-502 audit token; defaults to zeros and is "
            "never included verbatim in the report"
        ),
    )
    parser.add_argument(
        "--origin",
        type=lambda value: int(value, 0),
        default=1,
        help="request-502 origin word passed after the CPU subtype",
    )
    parser.add_argument(
        "--ipa",
        type=Path,
        default=Path("artifacts/WhatsApp_26.32.73_889564367.ipa"),
    )
    parser.add_argument(
        "--supf-member",
        default="Payload/WhatsApp.app/SC_Info/WhatsApp.v5.supf",
        help="IPA member supplied at the modeled .v5.supf path",
    )
    parser.add_argument(
        "--legacy-supf-member",
        default="Payload/WhatsApp.app/SC_Info/WhatsApp.supf",
        help="IPA member supplied at the modeled legacy .supf path",
    )
    parser.add_argument(
        "--supf-file",
        type=Path,
        help="override the IPA .v5.supf member with an installed-app file",
    )
    parser.add_argument(
        "--legacy-supf-file",
        type=Path,
        help="override the IPA legacy .supf member with an installed-app file",
    )
    parser.add_argument(
        "--executable-member",
        help="optional IPA member supplied when the handler opens its input executable",
    )
    parser.add_argument(
        "--executable-path",
        default=(
            "/private/var/containers/Bundle/Application/"
            "00000000-0000-0000-0000-000000000000/WhatsApp.app/WhatsApp"
        ),
        help="modeled on-device executable path passed to request 502",
    )
    parser.add_argument(
        "--sinf",
        type=Path,
        default=Path("artifacts/fairplay/WhatsApp-26.32.73.sinf"),
    )
    parser.add_argument(
        "--fairplay-state-dir",
        type=Path,
        default=Path("artifacts/fairplay"),
        help=(
            "directory containing optional IC-Info.* device-state files; "
            "matching files are supplied by basename without printing contents"
        ),
    )
    parser.add_argument(
        "--fairplay-state-mode",
        type=lambda value: int(value, 0),
        help="permission bits for captured FairPlay state files (for example 0o666)",
    )
    parser.add_argument(
        "--fairplay-state-uid",
        type=lambda value: int(value, 0),
        help="owner UID for captured FairPlay state files",
    )
    parser.add_argument(
        "--fairplay-state-gid",
        type=lambda value: int(value, 0),
        help="owner GID for captured FairPlay state files",
    )
    parser.add_argument(
        "--fairplay-state-stat-field",
        type=parse_fairplay_stat_field,
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="additional exact Darwin stat field for captured FairPlay state",
    )
    parser.add_argument(
        "--startup-file",
        action="append",
        type=parse_file_payload,
        default=[],
        metavar="SUFFIX=PATH",
        help=(
            "supply an exact file while building the daemon startup overlay; "
            "repeatable, with matching by requested-path suffix"
        ),
    )
    parser.add_argument(
        "--startup-directory",
        action="append",
        default=[],
        help="model an existing directory while building the startup overlay",
    )
    parser.add_argument(
        "--probe-fairplay-state",
        action="append",
        type=parse_state_probe,
        default=[],
        metavar="NAME[:SIZE]",
        help=(
            "supply a zero-filled synthetic IC-Info file for branch mapping; "
            "repeatable and reported explicitly as a probe"
        ),
    )
    parser.add_argument(
        "--sean-graft-clear",
        type=Path,
        help=(
            "offline-only: address-encode and install one clear 23E246 SEAN "
            "registry at the second main SEAN codec source"
        ),
    )
    parser.add_argument(
        "--sean-graft-source-ordinal",
        type=int,
        choices=(1, 2),
        default=2,
        help=(
            "offline-only: graft at the first or second distinct matching "
            "SEAN source (default: second)"
        ),
    )
    parser.add_argument(
        "--sean-graft-source-size",
        type=lambda value: int(value, 0),
        default=0x14,
        help=(
            "offline-only: decoded size at source+0x0c used to select the "
            "SEAN source (default: 0x14)"
        ),
    )
    parser.add_argument(
        "--sean-graft-rebase-aliases",
        action="store_true",
        help=(
            "offline-only: replace every exact in-memory/register alias of "
            "the selected SEAN source when publishing the graft"
        ),
    )
    parser.add_argument(
        "--sean-graft-in-place",
        action="store_true",
        help=(
            "offline-only: encode the graft over the selected source instead "
            "of relocating it; no synthetic ownership/scratch repairs apply"
        ),
    )
    parser.add_argument(
        "--sean-graft-repairs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "offline-only: apply synthetic ownership/scratch repairs for a "
            "relocated graft (default: enabled)"
        ),
    )
    parser.add_argument(
        "--sean-graft-adjust-owner-bounds",
        action="store_true",
        help=(
            "offline-only: advance the two source-owner cursors by the graft "
            "size delta"
        ),
    )
    parser.add_argument(
        "--product-id-hex",
        help=(
            "IODeviceTree /product/product-id; defaults to the exact daemon "
            "profile value, while an empty string leaves it unmodeled"
        ),
    )
    parser.add_argument(
        "--unique-device-id",
        help="model MGCopyAnswer(UniqueDeviceID); the value is not printed",
    )
    parser.add_argument(
        "--mac-address-from-interface",
        help=(
            "model IOMACAddress from the named local interface without "
            "printing or retaining its value"
        ),
    )
    parser.add_argument(
        "--mac-address-from-hardware-interface",
        help=(
            "model IOMACAddress from the named hardware port, avoiding the "
            "runtime/private Wi-Fi MAC, without printing or retaining it"
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
        "--model-physical-host",
        action="store_true",
        help="model kern.hv_vmm_present as zero for a physical source Mac",
    )
    parser.add_argument(
        "--model-coreke-operation-10",
        action="store_true",
        help=(
            "apply the statically proven CoreKE operation-10 descriptor "
            "mutation and return value"
        ),
    )
    parser.add_argument(
        "--probe-xpc-listener",
        action="store_true",
        help=(
            "invoke the registered fairplayd XPC listener once with an "
            "explicitly synthetic peer to recover its per-message handler"
        ),
    )
    parser.add_argument(
        "--probe-xpc-message",
        action="store_true",
        help=(
            "after --probe-xpc-listener, invoke the recovered per-peer "
            "handler once with an empty synthetic XPC dictionary"
        ),
    )
    parser.add_argument(
        "--probe-xpc-message-data-hex",
        help=(
            "populate the synthetic XPC dictionary's data field with the "
            "given hexadecimal bytes"
        ),
    )
    parser.add_argument(
        "--iokit-version",
        type=lambda value: int(value, 0),
        help=(
            "four-byte output for FairPlayIOKit selector 0x16; defaults to "
            "the selected kext profile's exact value"
        ),
    )
    parser.add_argument(
        "--iokit-protocol-capabilities",
        type=lambda value: int(value, 0),
        help=(
            "four-byte output for FairPlayIOKit selector 0x17; defaults to "
            "the selected kext profile's exact value"
        ),
    )
    parser.add_argument(
        "--iokit-monotonic-clock-hex",
        help=(
            "kern.monotonicclock bytes used by provider startup and selector "
            "0x15; defaults to the selected kext profile's exact width"
        ),
    )
    parser.add_argument(
        "--iokit-calendar-seconds",
        type=int,
        default=1_700_000_000,
        help="calendar seconds used by selector 0x15",
    )
    parser.add_argument(
        "--iokit-calendar-microseconds",
        type=int,
        default=0,
        help="calendar microseconds used by selector 0x15",
    )
    parser.add_argument(
        "--model-iokit-run-versioned",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="statically replay FairPlayIOKit selector 0x15",
    )
    parser.add_argument(
        "--model-iokit-fp-message",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "statically replay FairPlayIOKit selector 0x1a while allowing an "
            "explicit selector-0x15 fixture"
        ),
    )
    parser.add_argument(
        "--iokit-fp3000-output",
        type=Path,
        help=(
            "private exact 16-byte output for the known selector-3000 vector; "
            "used only by --model-iokit-fp-message"
        ),
    )
    parser.add_argument(
        "--iokit-run-versioned-output-hex",
        help=(
            "use a previously verified selector-0x15 output payload instead of "
            "replaying the provider; expects the returned data bytes only"
        ),
    )
    parser.add_argument(
        "--iokit-run-versioned-output-auxiliary-hex",
        help=(
            "20-byte auxiliary output paired with "
            "--iokit-run-versioned-output-hex"
        ),
    )
    parser.add_argument(
        "--iokit-run-versioned-output-structure",
        type=Path,
        help="exact private 0x228-byte selector-0x15 output structure",
    )
    parser.add_argument(
        "--iokit-run-versioned-output-structure-length",
        type=lambda value: int(value, 0),
        help=(
            "override the data length for a provider-boundary structure "
            "captured before the user-client wrapper stored it"
        ),
    )
    parser.add_argument(
        "--iokit-run-versioned-input-structure",
        type=Path,
        help=(
            "exact private 0x228-byte selector-0x15 input paired with an "
            "explicit output fixture"
        ),
    )
    parser.add_argument(
        "--fairplay-iokit-profile",
        choices=sorted(FAIRPLAY_IOKIT_BUILD_PROFILES),
        help=(
            "build/address profile used for the optional kernel replay; "
            "defaults to the matching daemon build"
        ),
    )
    parser.add_argument(
        "--fairplay-iokit-binary",
        type=Path,
        help="override the profile's FairPlayIOKit Mach-O",
    )
    parser.add_argument("--max-stages", type=int, default=30000)
    parser.add_argument(
        "--handler-instruction-limit",
        type=int,
        default=100_000_000,
        help="maximum target instructions between handler boundaries",
    )
    parser.add_argument(
        "--post-copy-instruction-limit",
        type=int,
        default=100_000_000,
        help="instruction guard used after the verified SUPF copy accelerator",
    )
    parser.add_argument(
        "--stop-supf-offset",
        type=lambda value: int(value, 0),
        help="stop on the first target-code read covering this SUPF offset",
    )
    parser.add_argument(
        "--stop-sinf-offset",
        type=lambda value: int(value, 0),
        help="stop on the first target-code read covering this SINF offset",
    )
    parser.add_argument(
        "--accelerate-supf-copy",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="verify and bulk-apply the 16-byte-periodic reverse copy loop",
    )
    parser.add_argument(
        "--accelerate-udid-byte-scan",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="skip the guarded linear scan to its first initialized 0x8e byte",
    )
    parser.add_argument(
        "--capture-udid-simd-generator",
        action="store_true",
        help="capture and stop after the 0x248-byte identity SIMD generator",
    )
    parser.add_argument(
        "--missing-files-enoent",
        action="store_true",
        help="model unknown open/stat/lstat paths as absent with errno ENOENT",
    )
    parser.add_argument(
        "--stop-address",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="stop before executing this internal address; repeatable",
    )
    parser.add_argument(
        "--force-post-sinf-status",
        type=lambda value: int(value, 0),
        help=(
            "explicit offline forced-path control: replace the protected "
            "post-SINF encoded status"
        ),
    )
    parser.add_argument(
        "--force-post-supf-status",
        type=lambda value: int(value, 0),
        help=(
            "explicit offline forced-path control: replace the protected "
            "post-SUPF encoded status"
        ),
    )
    parser.add_argument(
        "--trace-address",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="record registers at the first hit without stopping; repeatable",
    )
    parser.add_argument(
        "--trace-address-repeated",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="record registers at every hit without stopping; repeatable",
    )
    parser.add_argument(
        "--override-register",
        action="append",
        type=parse_register_override,
        default=[],
        metavar="ADDRESS:REGISTER:VALUE[:HIT]",
        help=(
            "override one register at an exact internal address and optional "
            "one-based hit (zero means every hit) for explicit forced-path "
            "analysis; repeatable"
        ),
    )
    parser.add_argument(
        "--override-memory-qword",
        action="append",
        type=parse_memory_qword_override,
        default=[],
        metavar="ADDRESS:VALUE",
        help=(
            "seed one little-endian qword in the evaluator overlay before the "
            "request; repeatable and reported explicitly"
        ),
    )
    parser.add_argument(
        "--redirect-address",
        action="append",
        type=parse_address_redirect,
        default=[],
        metavar="FROM:TO",
        help=(
            "redirect execution once before an exact internal address for "
            "explicit forced-path analysis; repeatable"
        ),
    )
    parser.add_argument(
        "--copy-memory-at",
        action="append",
        type=parse_memory_copy,
        default=[],
        metavar="PC:SOURCE:DESTINATION:SIZE",
        help=(
            "copy an overlay range once before an exact internal address for "
            "explicit frame-rebasing analysis; repeatable"
        ),
    )
    parser.add_argument(
        "--redirect-instruction-limit",
        type=int,
        help="instruction guard to apply after the first forced address redirect",
    )
    parser.add_argument(
        "--stop-address-hit",
        type=int,
        default=1,
        help="stop on this one-based hit of each --stop-address",
    )
    parser.add_argument(
        "--profile-instructions",
        action="store_true",
        help="include the hottest target PCs for each trace stage",
    )
    parser.add_argument(
        "--recent-pcs",
        type=int,
        default=0,
        help="include this many most recently executed target PCs",
    )
    parser.add_argument(
        "--stage-sp-memory-offset",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help=(
            "include an additional eight-byte SP-relative value in each stage "
            "snapshot; repeatable"
        ),
    )
    parser.add_argument(
        "--include-final-register-accesses",
        action="store_true",
        help="include recent watched-register writes from the final stage",
    )
    parser.add_argument(
        "--watch-register",
        action="append",
        default=[],
        help="record every write to this register with its private value; repeatable",
    )
    parser.add_argument(
        "--include-all-stages",
        action="store_true",
        help="include every trace stage instead of only the final twenty",
    )
    parser.add_argument(
        "--include-final-outputs",
        action="store_true",
        help="include the seeded request-502 output buffers at trace end",
    )
    parser.add_argument(
        "--watch-memory",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="record allocation reads/writes for dataflow reports",
    )
    parser.add_argument(
        "--watch-status",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="record the request status slots even when allocation tracing is off",
    )
    parser.add_argument(
        "--extra-watch-range",
        action="append",
        type=parse_address_range,
        default=[],
        help="record memory accesses in START:END; repeatable",
    )
    parser.add_argument(
        "--stop-memory-read-range",
        action="append",
        type=parse_address_range,
        default=[],
        help="stop on the first target-code read in START:END; repeatable",
    )
    parser.add_argument(
        "--dump-final-memory-register",
        action="append",
        default=[],
        help="dump bytes at this final-stage register; repeatable",
    )
    parser.add_argument(
        "--dump-final-memory-address",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="dump bytes at this absolute final overlay address; repeatable",
    )
    parser.add_argument(
        "--dump-final-memory-size",
        type=lambda value: int(value, 0),
        default=64,
        help="byte count used by --dump-final-memory-register",
    )
    parser.add_argument(
        "--checkpoint-file",
        type=Path,
        help=(
            "write the final sparse evaluator overlay and register state for "
            "offline continuation"
        ),
    )
    parser.add_argument(
        "--handler-initial-checkpoint",
        type=Path,
        help=(
            "seed a fresh request from a prior handler checkpoint's sparse "
            "memory and once-token state"
        ),
    )
    parser.add_argument(
        "--resume-handler-checkpoint",
        action="store_true",
        help=(
            "resume at the exact PC/register/NZCV state stored by "
            "--checkpoint-file instead of using it as a memory-only warmup"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the JSON report to this file instead of stdout",
    )
    args = parser.parse_args()

    io_mac_address = b"\x02\x00\x00\x00\x00\x01"
    io_mac_source = "deterministic-fixture"
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
        interface_output = subprocess.run(
            ["/sbin/ifconfig", args.mac_address_from_interface],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        interface_match = re.search(
            r"\bether\s+([0-9a-fA-F:]{17})\b", interface_output
        )
        if interface_match is None:
            parser.error(
                f"interface {args.mac_address_from_interface!r} has no Ethernet address"
            )
        io_mac_address = bytes.fromhex(interface_match.group(1).replace(":", ""))
        io_mac_source = f"host-interface:{args.mac_address_from_interface}"
    elif args.mac_address_from_hardware_interface is not None:
        hardware_output = subprocess.run(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        hardware_mac = None
        for block in re.split(r"\n\s*\n", hardware_output):
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
        io_mac_address = hardware_mac
        io_mac_source = (
            "hardware-port-interface:"
            f"{args.mac_address_from_hardware_interface}"
        )
    elif args.mac_address_file is not None:
        private_mac_data = args.mac_address_file.read_bytes()
        if len(private_mac_data) == 6:
            io_mac_address = private_mac_data
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
            io_mac_address = bytes.fromhex(normalized_mac)
        io_mac_source = "private-file"

    daemon_profile = DAEMON_BUILD_PROFILES[args.daemon_profile]
    if args.sean_graft_clear is not None and args.daemon_profile != "ios-23E246":
        parser.error("--sean-graft-clear currently requires ios-23E246")
    args.binary = args.binary or daemon_profile["binary"]
    args.startup_cache = (
        args.startup_cache or daemon_profile["startup_cache"]
    )
    args.main_address = (
        args.main_address
        if args.main_address is not None
        else daemon_profile["main"]
    )
    args.setup_impl_address = (
        args.setup_impl_address
        if args.setup_impl_address is not None
        else daemon_profile["setup_impl"]
    )
    args.request_token = (
        args.request_token
        if args.request_token is not None
        else daemon_profile["request_token"]
    )
    args.product_id_hex = (
        args.product_id_hex
        if args.product_id_hex is not None
        else daemon_profile["product_id"].hex()
    )
    if args.fairplay_iokit_profile is None:
        args.fairplay_iokit_profile = {
            "macos-26A428": "macos-26A428",
            "ios18-22G100": "ios18-22G100",
            "ios-23E246": "ios-23E246",
        }[args.daemon_profile]

    fixups, bind_names = dyld_info_fixups(args.binary)
    names = otool_indirect_names(args.binary)
    names.update(bind_names)
    db = RawMachODatabase(args.binary, names=names, fixups=fixups)

    with ZipFile(args.ipa) as archive:
        supf = archive.read(args.supf_member)
        legacy_supf = archive.read(args.legacy_supf_member)
        executable = (
            archive.read(args.executable_member)
            if args.executable_member is not None
            else None
        )
    if args.supf_file is not None:
        supf = args.supf_file.read_bytes()
    if args.legacy_supf_file is not None:
        legacy_supf = args.legacy_supf_file.read_bytes()
    registry_values = None
    if args.product_id_hex:
        registry_values = {
            ("IODeviceTree:/product", "product-id"): bytes.fromhex(
                args.product_id_hex
            )
        }
    mobile_gestalt_answers = None
    if args.unique_device_id is not None:
        mobile_gestalt_answers = {
            "UniqueDeviceID": args.unique_device_id.encode(),
        }

    file_payloads = {
        ".sinf": args.sinf.read_bytes(),
        ".supf": legacy_supf,
        ".v5.supf": supf,
    }
    file_stat_metadata: dict[str, dict[str, int]] = {}
    sean_graft_clear = (
        args.sean_graft_clear.read_bytes()
        if args.sean_graft_clear is not None
        else None
    )
    startup_file_reports = []
    for suffix, path in args.startup_file:
        payload = path.read_bytes()
        file_payloads[suffix] = payload
        startup_file_reports.append(
            {
                "suffix": suffix,
                "path": str(path),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if executable is not None:
        file_payloads["/" + Path(args.executable_path).name] = executable
    fairplay_state_files = []
    if args.fairplay_state_dir.is_dir():
        state_paths = {
            *args.fairplay_state_dir.rglob("IC-Info.*"),
            *args.fairplay_state_dir.rglob("SC Info.*"),
        }
        for state_path in sorted(state_paths):
            if not state_path.is_file():
                continue
            payload = state_path.read_bytes()
            relative_path = state_path.relative_to(args.fairplay_state_dir)
            parent_parts = {part.lower() for part in relative_path.parts[:-1]}
            if state_path.name.startswith("SC Info."):
                matched_suffixes = [
                    "/var/db/fpsd/SC Info/" + state_path.name,
                    "/Users/Shared/SC Info/" + state_path.name,
                ]
            elif "library" in parent_parts:
                matched_suffixes = [
                    "/Library/FairPlay/iTunes_Control/iTunes/" + state_path.name
                ]
            elif "media" in parent_parts:
                matched_suffixes = [
                    "/Media/iTunes_Control/iTunes/" + state_path.name
                ]
            else:
                matched_suffixes = ["/" + state_path.name]
            for matched_suffix in matched_suffixes:
                file_payloads[matched_suffix] = payload
                metadata = {
                    key: value
                    for key, value in {
                        "mode": args.fairplay_state_mode,
                        "uid": args.fairplay_state_uid,
                        "gid": args.fairplay_state_gid,
                    }.items()
                    if value is not None
                }
                for key, value in args.fairplay_state_stat_field:
                    metadata[key] = value
                if metadata:
                    file_stat_metadata[matched_suffix] = metadata
            fairplay_state_files.append(
                {
                    "name": state_path.name,
                    "source": str(relative_path),
                    "matched_suffix": matched_suffixes[0],
                    "matched_suffixes": matched_suffixes,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "stat": file_stat_metadata.get(matched_suffixes[0], {}),
                }
            )
    for state_name, state_size in args.probe_fairplay_state:
        matched_suffix = "/" + state_name
        file_payloads[matched_suffix] = bytes(state_size)
        fairplay_state_files.append(
            {
                "name": state_name,
                "source": "synthetic-zero-filled-branch-probe",
                "matched_suffix": matched_suffix,
                "size": state_size,
                "sha256": hashlib.sha256(bytes(state_size)).hexdigest(),
            }
        )

    if args.model_iokit_run_versioned and (
        args.iokit_run_versioned_output_hex
        or args.iokit_run_versioned_output_structure
    ):
        parser.error(
            "--model-iokit-run-versioned and "
            "explicit selector-0x15 output fixtures are mutually exclusive"
        )
    if (
        args.iokit_run_versioned_output_hex is not None
        and args.iokit_run_versioned_output_structure is not None
    ):
        parser.error(
            "--iokit-run-versioned-output-hex and "
            "--iokit-run-versioned-output-structure are mutually exclusive"
        )
    if (
        args.iokit_run_versioned_output_auxiliary_hex is not None
        and args.iokit_run_versioned_output_hex is None
    ):
        parser.error(
            "--iokit-run-versioned-output-auxiliary-hex requires "
            "--iokit-run-versioned-output-hex"
        )
    if (
        args.iokit_run_versioned_output_structure_length is not None
        and args.iokit_run_versioned_output_structure is None
    ):
        parser.error(
            "--iokit-run-versioned-output-structure-length requires "
            "--iokit-run-versioned-output-structure"
        )
    if (
        args.iokit_run_versioned_input_structure is not None
        and args.iokit_run_versioned_output_hex is None
        and args.iokit_run_versioned_output_structure is None
    ):
        parser.error(
            "--iokit-run-versioned-input-structure requires an explicit "
            "selector-0x15 output fixture"
        )

    modeled_iokit_runs: list[dict[str, Any]] = []
    fp3000_known_output = (
        args.iokit_fp3000_output.read_bytes()
        if args.iokit_fp3000_output is not None
        else None
    )
    if fp3000_known_output is not None and len(fp3000_known_output) != 16:
        parser.error("--iokit-fp3000-output must contain exactly 16 bytes")
    iokit_input_structure = (
        args.iokit_run_versioned_input_structure.read_bytes()
        if args.iokit_run_versioned_input_structure is not None
        else None
    )
    if iokit_input_structure is not None and len(iokit_input_structure) != 0x228:
        parser.error(
            "--iokit-run-versioned-input-structure must contain exactly "
            "0x228 bytes"
        )
    iokit_struct_method_input_overrides = (
        {0x15: iokit_input_structure}
        if iokit_input_structure is not None
        else None
    )
    iokit_profile = FAIRPLAY_IOKIT_BUILD_PROFILES[
        args.fairplay_iokit_profile
    ]
    effective_iokit_version = (
        args.iokit_version
        if args.iokit_version is not None
        else iokit_profile.get("version", DEFAULT_IOKIT_VERSION)
    )
    effective_iokit_protocol_capabilities = (
        args.iokit_protocol_capabilities
        if args.iokit_protocol_capabilities is not None
        else iokit_profile.get(
            "protocol_capabilities",
            DEFAULT_IOKIT_PROTOCOL_CAPABILITIES,
        )
    )
    monotonic_clock_size = iokit_profile.get("monotonic_clock_size", 16)
    effective_monotonic_clock_hex = (
        args.iokit_monotonic_clock_hex
        if args.iokit_monotonic_clock_hex is not None
        else (1).to_bytes(monotonic_clock_size, "little").hex()
    )
    fp_message_state = bytes(0x2000)
    fp_message_kernel_memory: dict[int, int] | None = None
    fp_message_next_allocation: int | None = None
    fp_message_random_state = 0x12345678
    iokit_struct_method_handlers = None
    iokit_struct_method_outputs = {
        0x16: effective_iokit_version.to_bytes(4, "little"),
        0x17: effective_iokit_protocol_capabilities.to_bytes(4, "little"),
    }
    if args.model_iokit_run_versioned or args.model_iokit_fp_message:
        iokit_monotonic_clock = bytes.fromhex(effective_monotonic_clock_hex)
        if len(iokit_monotonic_clock) != monotonic_clock_size:
            parser.error(
                "--iokit-monotonic-clock-hex must contain exactly "
                f"{monotonic_clock_size} bytes for profile "
                f"{args.fairplay_iokit_profile}"
            )
        iokit_binary = args.fairplay_iokit_binary or iokit_profile["binary"]
        iokit_names = fairplay_iokit_nm_names(iokit_binary)
        iokit_names.update(iokit_profile["external_names"])
        iokit_db = RawMachODatabase(
            iokit_binary,
            names=iokit_names,
        )
        if "provider_init_impls" in iokit_profile:
            provider_result = run_fairplay_iokit_provider_init(
                iokit_db,
                init_impls=iokit_profile["provider_init_impls"],
                monotonic_clock=iokit_monotonic_clock,
                calendar_seconds=args.iokit_calendar_seconds,
                calendar_microseconds=args.iokit_calendar_microseconds,
                kernel_collection_base=iokit_profile[
                    "kernel_collection_base"
                ],
                return_evaluator=True,
            )
            if not provider_result["completed"]:
                raise RuntimeError(
                    "FairPlayIOKit provider initialization did not complete: "
                    f"{provider_result['stages'][-1]}"
                )
            kernel_evaluator = provider_result.pop("_evaluator")
            fp_message_next_allocation = provider_result.pop(
                "_next_allocation"
            )
            fp_message_random_state = int(
                provider_result["random_state"], 16
            )
            fp_message_kernel_memory = {
                address: byte
                for address, byte in kernel_evaluator.memory.items()
                if not (
                    0xFFFFFE1000000000
                    <= address
                    < 0xFFFFFE1000200000
                )
            }
            modeled_iokit_runs.append(
                {
                    "operation": "provider-init",
                    "completed": True,
                    "initializers": provider_result["initializers"],
                    "stages": len(provider_result["stages"]),
                    "overlay_bytes": len(fp_message_kernel_memory),
                }
            )
        if "fp_client_init_impl" in iokit_profile:
            init_result = run_fairplay_iokit_client_init(
                iokit_db,
                state=fp_message_state,
                fp_client_init_impl=iokit_profile["fp_client_init_impl"],
                kernel_collection_base=iokit_profile[
                    "kernel_collection_base"
                ],
                return_evaluator=True,
                initial_memory=fp_message_kernel_memory,
                allocation_base=(
                    fp_message_next_allocation
                    if fp_message_next_allocation is not None
                    else 0xFFFFFE1001000000
                ),
            )
            if not init_result["completed"] or init_result["status"] != "0x0":
                raise RuntimeError(
                    "FairPlayIOKit client initialization did not complete: "
                    f"{init_result['stages'][-1]}"
                )
            fp_message_state = bytes.fromhex(init_result["state"])
            kernel_evaluator = init_result.pop("_evaluator")
            fp_message_next_allocation = init_result.pop("_next_allocation")
            fp_message_kernel_memory = {
                address: byte
                for address, byte in kernel_evaluator.memory.items()
                if not (
                    0xFFFFFE1000000000
                    <= address
                    < 0xFFFFFE1000200000
                )
            }
            modeled_iokit_runs.append(
                {
                    "operation": "client-init",
                    "provider_status": init_result["status"],
                    "persistent_state_nonzero_bytes": sum(
                        byte != 0 for byte in fp_message_state
                    ),
                    "stages": len(init_result["stages"]),
                }
            )

        def model_run_versioned(
            input_structure: bytes,
            output_capacity: int,
            _user_evaluator: Any,
        ) -> tuple[int, bytes]:
            nonlocal fp_message_kernel_memory
            nonlocal fp_message_next_allocation
            if len(input_structure) != 0x228 or output_capacity < 0x228:
                raise RuntimeError(
                    "selector 0x15 requires a 0x228-byte input/output structure"
                )
            command = int.from_bytes(input_structure[0:4], "little")
            token0 = int.from_bytes(input_structure[4:8], "little")
            token1 = int.from_bytes(input_structure[8:12], "little")
            input_length = int.from_bytes(input_structure[0x220:0x224], "little")
            if input_length > 0x200:
                raise RuntimeError(
                    f"selector 0x15 input length is invalid: {input_length:#x}"
                )
            chained_state: dict[str, Any] = {}
            if fp_message_kernel_memory is not None:
                chained_state["initial_memory"] = fp_message_kernel_memory
            if fp_message_next_allocation is not None:
                chained_state["allocation_base"] = fp_message_next_allocation
            result = run_fairplay_iokit_versioned(
                iokit_db,
                command=command,
                token0=token0,
                token1=token1,
                auxiliary=input_structure[0xC:0x20],
                input_data=input_structure[0x20 : 0x20 + input_length],
                monotonic_clock=iokit_monotonic_clock,
                calendar_seconds=args.iokit_calendar_seconds,
                calendar_microseconds=args.iokit_calendar_microseconds,
                run_versioned_impl=iokit_profile["run_versioned_impl"],
                kernel_collection_base=iokit_profile["kernel_collection_base"],
                return_evaluator=True,
                **chained_state,
            )
            if not result["completed"]:
                raise RuntimeError(
                    "selector 0x15 provider replay did not complete: "
                    f"{result['stages'][-1]}"
                )
            kernel_evaluator = result.pop("_evaluator")
            fp_message_next_allocation = result.pop("_next_allocation")
            fp_message_kernel_memory = {
                address: byte
                for address, byte in kernel_evaluator.memory.items()
                if not (
                    0xFFFFFE1000000000
                    <= address
                    < 0xFFFFFE1000200000
                )
            }
            output_data = bytes.fromhex(result["output_data"])
            output_auxiliary = bytes.fromhex(result["output_auxiliary"])
            provider_status = int(result["status"], 16)
            output_structure = bytearray(0x228)
            output_structure[0xC:0x20] = output_auxiliary
            output_structure[0x20 : 0x20 + len(output_data)] = output_data
            output_structure[0x220:0x224] = len(output_data).to_bytes(4, "little")
            output_structure[0x224:0x228] = provider_status.to_bytes(4, "little")
            modeled_iokit_runs.append(
                {
                    "command": hex(command),
                    "token0": hex(token0),
                    "token1": hex(token1),
                    "input_auxiliary": input_structure[0xC:0x20].hex(),
                    "input_data": input_structure[
                        0x20 : 0x20 + input_length
                    ].hex(),
                    "provider_status": hex(provider_status),
                    "output_auxiliary": output_auxiliary.hex(),
                    "output_data": output_data.hex(),
                    "completed": result["completed"],
                    "stages": len(result["stages"]),
                    "hardware_aes_model": "pwn0rz-loader-passthrough",
                    "hardware_aes_events": result.get(
                        "hardware_aes_events", []
                    ),
                }
            )
            return 0, bytes(output_structure)

        iokit_struct_method_handlers = {}
        if args.model_iokit_run_versioned:
            iokit_struct_method_handlers[0x15] = model_run_versioned
        if "fp_message_impl" in iokit_profile:

            def model_fp_message(
                input_structure: bytes,
                output_capacity: int,
                user_evaluator: Any,
            ) -> tuple[int, bytes]:
                nonlocal fp_message_state
                nonlocal fp_message_kernel_memory
                nonlocal fp_message_next_allocation
                nonlocal fp_message_random_state
                indirect_message = len(input_structure) == 16
                if indirect_message:
                    if output_capacity < 16:
                        raise RuntimeError(
                            "selector 0x1a descriptor output is too small"
                        )
                    message_address = int.from_bytes(
                        input_structure[0:8], "little"
                    )
                    message_length = int.from_bytes(
                        input_structure[8:12], "little"
                    )
                else:
                    message_address = 0
                    message_length = len(input_structure)
                if message_length > 0x100000:
                    raise RuntimeError(
                        "selector 0x1a message is too large: "
                        f"{message_length:#x}"
                    )
                message = (
                    bytes(
                        user_evaluator.read_mem(message_address + offset, 1)
                        for offset in range(message_length)
                    )
                    if indirect_message
                    else input_structure
                )
                result = run_fairplay_iokit_fp_message(
                    iokit_db,
                    message=message,
                    state=fp_message_state,
                    fp_message_impl=iokit_profile["fp_message_impl"],
                    kernel_collection_base=iokit_profile[
                        "kernel_collection_base"
                    ],
                    return_evaluator=True,
                    initial_memory=fp_message_kernel_memory,
                    random_seed=fp_message_random_state,
                    allocation_base=(
                        fp_message_next_allocation
                        if fp_message_next_allocation is not None
                        else 0xFFFFFE1001000000
                    ),
                    fp3000_known_output=fp3000_known_output,
                )
                if not result["completed"]:
                    raise RuntimeError(
                        "selector 0x1a provider replay did not complete: "
                        f"{result['stages'][-1]}"
                    )
                output_message = bytes.fromhex(result["output_message"])
                fp_message_state = bytes.fromhex(result["state"])
                fp_message_random_state = int(result["random_state"], 16)
                kernel_evaluator = result.pop("_evaluator")
                fp_message_next_allocation = result.pop("_next_allocation")
                fp_message_kernel_memory = {
                    address: byte
                    for address, byte in kernel_evaluator.memory.items()
                    if not (
                        0xFFFFFE1000000000
                        <= address
                        < 0xFFFFFE1000200000
                    )
                }
                if indirect_message:
                    for offset, byte in enumerate(output_message):
                        user_evaluator.write_mem(
                            message_address + offset,
                            byte,
                            1,
                        )
                    method_output = input_structure
                else:
                    if len(output_message) > output_capacity:
                        raise RuntimeError(
                            "selector 0x1a direct output exceeds capacity"
                        )
                    method_output = output_message
                provider_status = int(result["status"], 16)
                modeled_iokit_runs.append(
                    {
                        "selector": "0x1a",
                        "message_length": message_length,
                        "provider_status": hex(provider_status),
                        "input_sha256": hashlib.sha256(message).hexdigest(),
                        "output_sha256": hashlib.sha256(
                            output_message
                        ).hexdigest(),
                        "changed_bytes": sum(
                            left != right
                            for left, right in zip(message, output_message)
                        ),
                        "random_state": result["random_state"],
                        "hardware_aes_model": "passthrough",
                        "hardware_aes_events": result.get(
                            "hardware_aes_events", []
                        ),
                    }
                )
                return provider_status, method_output

            iokit_struct_method_handlers[0x1A] = model_fp_message
    if (
        args.iokit_run_versioned_output_hex is not None
        or args.iokit_run_versioned_output_structure is not None
    ):
        if args.iokit_run_versioned_output_structure is not None:
            output_structure = bytearray(
                args.iokit_run_versioned_output_structure.read_bytes()
            )
            if len(output_structure) != 0x228:
                parser.error(
                    "--iokit-run-versioned-output-structure must contain "
                    "exactly 0x228 bytes"
                )
            if args.iokit_run_versioned_output_structure_length is not None:
                if not 0 <= args.iokit_run_versioned_output_structure_length <= 0x200:
                    parser.error(
                        "--iokit-run-versioned-output-structure-length must "
                        "be between zero and 0x200"
                    )
                output_structure[0x220:0x224] = (
                    args.iokit_run_versioned_output_structure_length.to_bytes(
                        4, "little"
                    )
                )
                output_structure[0x224:0x228] = bytes(4)
            output_length = int.from_bytes(
                output_structure[0x220:0x224], "little"
            )
            provider_status = int.from_bytes(
                output_structure[0x224:0x228], "little"
            )
            if output_length > 0x200 or provider_status != 0:
                parser.error(
                    "selector-0x15 output structure has invalid length or status"
                )
            output_data = bytes(output_structure[0x20 : 0x20 + output_length])
            output_auxiliary = bytes(output_structure[0xC:0x20])
            fixture_source = "provided-output-structure"
        else:
            try:
                output_data = bytes.fromhex(args.iokit_run_versioned_output_hex)
            except ValueError as error:
                parser.error(
                    "--iokit-run-versioned-output-hex must contain hexadecimal bytes"
                )
            if len(output_data) > 0x200:
                parser.error(
                    "--iokit-run-versioned-output-hex must contain at most 0x200 bytes"
                )
            try:
                output_auxiliary = bytes.fromhex(
                    args.iokit_run_versioned_output_auxiliary_hex or "00" * 20
                )
            except ValueError as error:
                parser.error(
                    "--iokit-run-versioned-output-auxiliary-hex must contain "
                    "hexadecimal bytes"
                )
            if len(output_auxiliary) != 20:
                parser.error(
                    "--iokit-run-versioned-output-auxiliary-hex must contain "
                    "exactly 20 bytes"
                )
            output_structure = bytearray(0x228)
            output_structure[0xC:0x20] = output_auxiliary
            output_structure[0x20 : 0x20 + len(output_data)] = output_data
            output_structure[0x220:0x224] = len(output_data).to_bytes(4, "little")
            fixture_source = "provided-output-fields"
        iokit_struct_method_outputs[0x15] = bytes(output_structure)

        def model_run_versioned_fixture(
            _input_structure: bytes,
            output_capacity: int,
            _user_evaluator: Any,
        ) -> tuple[int, bytes]:
            if output_capacity < len(output_structure):
                raise RuntimeError(
                    "selector 0x15 fixture exceeds startup output capacity"
                )
            return 0, bytes(output_structure)

        if iokit_struct_method_handlers is None:
            iokit_struct_method_handlers = {}
        iokit_struct_method_handlers[0x15] = model_run_versioned_fixture
        modeled_iokit_runs.append(
            {
                "source": fixture_source,
                "provider_status": "0x0",
                "output_structure_sha256": hashlib.sha256(
                    output_structure
                ).hexdigest(),
                "output_length": len(output_data),
            }
        )

    startup_fingerprint = startup_cache_fingerprint(args.binary)
    startup_uses_iokit_model = bool(iokit_struct_method_handlers)
    startup_cache_allowed = not startup_uses_iokit_model
    if args.model_iokit_run_versioned or args.model_iokit_fp_message:
        iokit_binary_for_cache = (
            args.fairplay_iokit_binary or iokit_profile["binary"]
        )
        model_digest = hashlib.sha256(
            iokit_binary_for_cache.read_bytes()
            + Path(__file__).with_name(
                "trace_fairplay_iokit_run_versioned.py"
            ).read_bytes()
            + bytes.fromhex(effective_monotonic_clock_hex)
            + args.iokit_calendar_seconds.to_bytes(8, "little", signed=True)
            + args.iokit_calendar_microseconds.to_bytes(4, "little", signed=True)
        ).hexdigest()[:16]
        args.startup_cache = args.startup_cache.with_name(
            f"{args.startup_cache.stem}-iokit-model-{model_digest}"
            f"{args.startup_cache.suffix}"
        )
        startup_cache_allowed = True
    if (
        (
            args.iokit_run_versioned_output_hex is not None
            or args.iokit_run_versioned_output_structure is not None
        )
        and not args.model_iokit_run_versioned
        and not args.model_iokit_fp_message
    ):
        fixture_digest = hashlib.sha256(bytes(output_structure)).hexdigest()[:16]
        if iokit_input_structure is not None:
            fixture_digest = hashlib.sha256(
                iokit_input_structure + bytes(output_structure)
            ).hexdigest()[:16]
        args.startup_cache = args.startup_cache.with_name(
            f"{args.startup_cache.stem}-iokit15-{fixture_digest}"
            f"{args.startup_cache.suffix}"
        )
        startup_cache_allowed = True
    startup_has_explicit_files = bool(args.startup_file or args.startup_directory)
    startup = (
        None
        if not startup_cache_allowed or startup_has_explicit_files
        else load_startup_cache(args.startup_cache, startup_fingerprint)
    )
    startup_cache_hit = startup is not None
    if startup is None:
        startup = initialize_daemon(
            db,
            main_address=args.main_address,
            iokit_version=daemon_profile["iokit_version"],
            iokit_capabilities=daemon_profile["iokit_capabilities"],
            iokit_struct_method_handlers=iokit_struct_method_handlers,
            iokit_struct_method_input_overrides=(
                iokit_struct_method_input_overrides
            ),
            unique_device_id=(
                args.unique_device_id.encode()
                if args.unique_device_id is not None
                else b"00000000-0000000000000000"
            ),
            probe_xpc_listener=args.probe_xpc_listener,
            probe_xpc_message=args.probe_xpc_message,
            xpc_message_data=(
                bytes.fromhex(args.probe_xpc_message_data_hex)
                if args.probe_xpc_message_data_hex is not None
                else None
            ),
            recent_pc_limit=args.recent_pcs,
            xpc_dictionary_type_token=daemon_profile.get(
                "xpc_dictionary_type_token"
            ),
            file_payloads=file_payloads,
            file_stat_metadata=file_stat_metadata,
            directory_paths=frozenset(args.startup_directory),
            missing_files_are_enoent=True,
        )
        if startup_cache_allowed and not startup_has_explicit_files:
            save_startup_cache(args.startup_cache, startup_fingerprint, startup)

    register_overrides: dict[int, dict[str, int]] = {}
    register_override_hits: dict[int, int] = {}
    for address, register, register_value, hit in args.override_register:
        previous_hit = register_override_hits.get(address)
        if previous_hit is not None and previous_hit != hit:
            parser.error(
                "all --override-register entries for one address must use "
                "the same HIT"
            )
        register_overrides.setdefault(address, {})[register] = register_value
        register_override_hits[address] = hit

    address_redirects: dict[int, int] = {}
    for source, target in args.redirect_address:
        if source in address_redirects and address_redirects[source] != target:
            parser.error("one redirect source cannot have multiple targets")
        address_redirects[source] = target

    memory_copies: dict[int, list[tuple[int, int, int]]] = {}
    for pc, source, destination, size in args.copy_memory_at:
        memory_copies.setdefault(pc, []).append((source, destination, size))

    initial_memory = dict(startup["memory"])
    initialized_once_tokens = set(startup["once_tokens"])
    initial_registers = None
    initial_nzcv = None
    if args.handler_initial_checkpoint is not None:
        if args.handler_initial_checkpoint.name.endswith(".pkl.gz"):
            with gzip.open(args.handler_initial_checkpoint, "rb") as stream:
                checkpoint = pickle.load(stream)
            if checkpoint.get("schema") != 1:
                parser.error("handler initial checkpoint is incompatible")
            initial_memory = dict(checkpoint["memory"])
            initialized_once_tokens = set(checkpoint["once_tokens"])
            checkpoint_registers = dict(checkpoint["registers"])
            checkpoint_nzcv = dict(checkpoint["nzcv"])
        else:
            checkpoint = json.loads(args.handler_initial_checkpoint.read_text())
            if checkpoint.get("schema") != 2:
                parser.error("handler initial checkpoint is incompatible")
            initial_memory = {
                int(address, 16): int(value)
                for address, value in checkpoint["memory"]
            }
            initialized_once_tokens = {
                int(value, 16) for value in checkpoint["once_tokens"]
            }
            checkpoint_registers = {
                name: int(value, 16)
                for name, value in checkpoint["registers"].items()
            }
            checkpoint_nzcv = {
                name: int(value) for name, value in checkpoint["nzcv"].items()
            }
        if (
            checkpoint.get("binary_sha256")
            != hashlib.sha256(args.binary.read_bytes()).hexdigest()
        ):
            parser.error("handler initial checkpoint is incompatible")
        if args.resume_handler_checkpoint:
            args.setup_impl_address = int(checkpoint["pc"], 16)
            initial_registers = checkpoint_registers
            initial_nzcv = checkpoint_nzcv
    elif args.resume_handler_checkpoint:
        parser.error("--resume-handler-checkpoint requires --handler-initial-checkpoint")
    for address, qword_value in args.override_memory_qword:
        for byte_index in range(8):
            initial_memory[address + byte_index] = (
                qword_value >> (8 * byte_index)
            ) & 0xFF

    watched_registers = (
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22",
        "x23", "x24", "x25", "x26", "x27", "x28", "x30",
    )
    result = trace_fairplay_setup(
        db,
        path=args.executable_path.encode() + b"\0",
        setup_impl=args.setup_impl_address,
        chained_pointer_base=IMAGE_BASE,
        chained_pointer_format="arm64e-userland",
        request_token=args.request_token,
        origin=args.origin,
        audit_token=(
            args.audit_token_hex
            if args.audit_token_hex is not None
            else bytes(32)
        ),
        coreke_return=(0xFFFF58FE if args.model_coreke_operation_10 else 0),
        coreke_buffer_updates=(
            {10: (8, bytes.fromhex("0000000000000001"))}
            if args.model_coreke_operation_10
            else None
        ),
        max_stages=args.max_stages,
        force_post_sinf_status=args.force_post_sinf_status,
        force_post_supf_status=args.force_post_supf_status,
        initial_memory=initial_memory,
        initial_registers=initial_registers,
        initial_nzcv=initial_nzcv,
        initialized_once_tokens=initialized_once_tokens,
        registry_property_values=registry_values,
        mobile_gestalt_answers=mobile_gestalt_answers,
        io_mac_address=io_mac_address,
        hypervisor_present=not args.model_physical_host,
        follow_internal_transfers=True,
        max_instructions_per_stage=args.handler_instruction_limit,
        file_read_break_offsets=(
            {
                **(
                    {".v5.supf": args.stop_supf_offset}
                    if args.stop_supf_offset is not None
                    else {}
                ),
                **(
                    {".sinf": args.stop_sinf_offset}
                    if args.stop_sinf_offset is not None
                    else {}
                ),
            }
            or None
        ),
        extra_memory_watch_ranges=(
            (
                (0x7000000FFF80, 0x7000000FFF84),
                (0x7000000F6F3C, 0x7000000F6F40),
            )
            if args.watch_status
            else ()
        )
        + (
            (
                (0x710000000000, 0x710100000000),
            )
            if args.watch_memory
            else ()
        )
        + tuple(args.extra_watch_range),
        initial_memory_break_ranges=tuple(args.stop_memory_read_range),
        watch_allocations=args.watch_memory,
        register_watch_names=tuple(
            dict.fromkeys(
                (
                    (
                        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                        "x22", "x28", "x30",
                    )
                    if args.watch_status
                    else ()
                )
                + (
                    ("x5", "x22", "x23", "x25", "x30")
                    if args.watch_memory
                    else ()
                )
                + (
                    ("x19", "x20", "x21")
                    if args.include_final_register_accesses
                    else ()
                )
                + tuple(args.watch_register)
            )
        ),
        stage_register_names=watched_registers,
        stage_sp_memory_offsets=tuple(
            dict.fromkeys((0x190, 0x198, *args.stage_sp_memory_offset))
        ),
        accelerate_ios_supf_reverse_copy=args.accelerate_supf_copy,
        accelerate_ios_udid_byte_scan=args.accelerate_udid_byte_scan,
        capture_ios_udid_simd_generator=args.capture_udid_simd_generator,
        post_acceleration_instruction_limit=args.post_copy_instruction_limit,
        stop_addresses=frozenset(args.stop_address),
        stop_address_hit=args.stop_address_hit,
        profile_instructions=args.profile_instructions,
        recent_pc_limit=args.recent_pcs,
        missing_files_are_enoent=args.missing_files_enoent,
        iokit_struct_method_outputs=iokit_struct_method_outputs,
        iokit_struct_method_handlers=iokit_struct_method_handlers,
        iokit_struct_method_input_overrides=iokit_struct_method_input_overrides,
        file_payloads=file_payloads,
        file_stat_metadata=file_stat_metadata,
        register_overrides=register_overrides,
        register_override_hits=register_override_hits,
        address_redirects=address_redirects,
        memory_copies=memory_copies,
        redirect_instruction_limit=args.redirect_instruction_limit,
        trace_addresses=frozenset(args.trace_address),
        repeated_trace_addresses=frozenset(args.trace_address_repeated),
        ios26_sean_graft_clear=sean_graft_clear,
        ios26_sean_graft_source_ordinal=args.sean_graft_source_ordinal,
        ios26_sean_graft_source_size=args.sean_graft_source_size,
        ios26_sean_graft_rebase_aliases=args.sean_graft_rebase_aliases,
        ios26_sean_graft_in_place=args.sean_graft_in_place,
        ios26_sean_graft_enable_repairs=args.sean_graft_repairs,
        ios26_sean_graft_adjust_owner_bounds=args.sean_graft_adjust_owner_bounds,
    )

    if args.checkpoint_file is not None:
        checkpoint_registers = {
            **result["final_registers"],
            **result["final_vector_registers"],
        }
        checkpoint = {
            "schema": 2,
            "binary": str(args.binary.resolve()),
            "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "pc": (
                result["stages"][-1]["site"] if result["stages"] else hex(SETUP_IMPL)
            ),
            "registers": {
                name: hex(value) for name, value in checkpoint_registers.items()
            },
            "nzcv": result["final_nzcv"],
            "once_tokens": [
                hex(value) for value in result["final_once_tokens"]
            ],
            "memory": [
                [hex(address), value]
                for address, value in sorted(result["final_memory"].items())
            ],
        }
        args.checkpoint_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if args.checkpoint_file.name.endswith(".pkl.gz"):
            unicorn_checkpoint = {
                "schema": 1,
                "binary": str(args.binary),
                "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                "pc": checkpoint["pc"],
                "registers": checkpoint_registers,
                "nzcv": result["final_nzcv"],
                "memory": result["final_memory"],
                "working_sinf": 0,
                "priv_offset": 0,
                "priv_length": 1,
                "state_slot": 0,
                "once_tokens": result["final_once_tokens"],
            }
            with gzip.open(args.checkpoint_file, "wb", compresslevel=1) as stream:
                pickle.dump(
                    unicorn_checkpoint, stream, protocol=pickle.HIGHEST_PROTOCOL
                )
        else:
            args.checkpoint_file.write_text(
                json.dumps(checkpoint, separators=(",", ":"))
            )
        args.checkpoint_file.chmod(0o600)

    file_accesses = []
    for event in result["events"]:
        if event.get("kind") != "mmap-file":
            continue
        base = int(event["address"], 16)
        requested_length = event["length"]
        length = event.get("populated_length", requested_length)
        read_offsets: set[int] = set()
        for access in result["memory_accesses"]:
            if (
                access["operation"] == "read"
                and base <= access["address"] < base + length
            ):
                read_offsets.update(
                    range(
                        access["address"] - base,
                        access["address"] - base + access["size"],
                    )
                )
        file_accesses.append(
            {
                "path": event["path"],
                "base": event["address"],
                "length": requested_length,
                "populated_length": length,
                "unique_read_bytes": len(read_offsets),
                "read_ranges": [
                    {"start": hex(start), "end": hex(end), "size": end - start}
                    for start, end in contiguous_ranges(read_offsets)
                ],
                "top_read_pcs": [
                    {"pc": hex(pc), "count": count}
                    for pc, count in Counter(
                        access["pc"]
                        for access in result["memory_accesses"]
                        if (
                            access["operation"] == "read"
                            and base <= access["address"] < base + length
                        )
                    ).most_common(30)
                ],
            }
        )
        if event["path"].endswith(".sinf"):
            priv_start = base + 0x1D0
            priv_end = base + 0x390
            priv_accesses = [
                access
                for access in result["memory_accesses"]
                if (
                    access["operation"] == "read"
                    and access["address"] < priv_end
                    and access["address"] + access["size"] > priv_start
                )
            ]
            file_accesses[-1]["priv_payload"] = {
                "offset_start": "0x1d0",
                "offset_end": "0x390",
                "operations": len(priv_accesses),
                "top_pcs": [
                    {"pc": hex(pc), "count": count}
                    for pc, count in Counter(
                        access["pc"] for access in priv_accesses
                    ).most_common(30)
                ],
                "first_accesses": [
                    {
                        "pc": hex(access["pc"]),
                        "offset": hex(access["address"] - base),
                        "size": access["size"],
                        "stage": access.get("stage"),
                    }
                    for access in priv_accesses[:40]
                ],
            }

    anonymous_accesses = []
    for event in result["events"]:
        if event.get("kind") not in ("mmap-anonymous", "heap-allocation"):
            continue
        base = int(event["address"], 16)
        length = event["length"]
        summary: dict[str, Any] = {
            "base": event["address"],
            "length": length,
        }
        for operation in ("read", "write"):
            accesses = [
                access
                for access in result["memory_accesses"]
                if access["operation"] == operation
                and base <= access["address"] < base + length
            ]
            offsets: set[int] = set()
            for access in accesses:
                offsets.update(
                    range(
                        access["address"] - base,
                        access["address"] - base + access["size"],
                    )
                )
            ranges = contiguous_ranges(offsets)
            shown_ranges = ranges
            if len(ranges) > 40:
                shown_ranges = ranges[:20] + ranges[-20:]
            summary[operation] = {
                "operations": len(accesses),
                "unique_bytes": len(offsets),
                "range_count": len(ranges),
                "ranges": [
                    {"start": hex(start), "end": hex(end), "size": end - start}
                    for start, end in shown_ranges
                ],
                "top_pcs": [
                    {"pc": hex(pc), "count": count}
                    for pc, count in Counter(
                        access["pc"] for access in accesses
                    ).most_common(20)
                ],
            }
        anonymous_accesses.append(summary)

    sinf_copy_writes = [
        access
        for access in result["memory_accesses"]
        if access["operation"] == "write" and access["pc"] == 0x100551328
    ]
    copied_sinf_priv = None
    if sinf_copy_writes:
        copied_sinf_base = min(access["address"] for access in sinf_copy_writes)
        copied_sinf_end = copied_sinf_base + 0x418
        priv_start = copied_sinf_base + 0x1D0
        priv_end = copied_sinf_base + 0x390
        copied_sinf_reads = [
            access
            for access in result["memory_accesses"]
            if (
                access["operation"] == "read"
                and access["address"] < copied_sinf_end
                and access["address"] + access["size"] > copied_sinf_base
            )
        ]
        copied_read_offsets: set[int] = set()
        for access in copied_sinf_reads:
            start = max(access["address"], copied_sinf_base) - copied_sinf_base
            end = min(
                access["address"] + access["size"], copied_sinf_end
            ) - copied_sinf_base
            copied_read_offsets.update(range(start, end))
        copied_priv_accesses = [
            access
            for access in result["memory_accesses"]
            if (
                access["address"] < priv_end
                and access["address"] + access["size"] > priv_start
            )
        ]
        copied_sinf_priv = {
            "copy_base": hex(copied_sinf_base),
            "all_reads": {
                "operations": len(copied_sinf_reads),
                "unique_bytes": len(copied_read_offsets),
                "ranges": [
                    {"start": hex(start), "end": hex(end), "size": end - start}
                    for start, end in contiguous_ranges(copied_read_offsets)
                ],
                "top_pcs": [
                    {"pc": hex(pc), "count": count}
                    for pc, count in Counter(
                        access["pc"] for access in copied_sinf_reads
                    ).most_common(40)
                ],
            },
            "start": hex(priv_start),
            "end": hex(priv_end),
            "copy_writes": len(sinf_copy_writes),
            "reads": [
                {
                    "pc": hex(access["pc"]),
                    "offset": hex(access["address"] - copied_sinf_base),
                    "size": access["size"],
                    "stage": access.get("stage"),
                }
                for access in copied_priv_accesses
                if access["operation"] == "read"
            ][:100],
            "read_top_pcs": [
                {"pc": hex(pc), "count": count}
                for pc, count in Counter(
                    access["pc"]
                    for access in copied_priv_accesses
                    if access["operation"] == "read"
                ).most_common(30)
            ],
            "write_top_pcs": [
                {"pc": hex(pc), "count": count}
                for pc, count in Counter(
                    access["pc"]
                    for access in copied_priv_accesses
                    if access["operation"] == "write"
                ).most_common(30)
            ],
        }

    clear_sinf_candidates = []
    clear_sinf_header = b"\x00\x00\x00\x18key "
    final_memory = result["final_memory"]
    for candidate_address, first_byte in final_memory.items():
        if first_byte != clear_sinf_header[0]:
            continue
        if any(
            final_memory.get(candidate_address + offset) != value
            for offset, value in enumerate(clear_sinf_header)
        ):
            continue
        cursor = 0
        atom_rows = []
        valid = True
        for expected_type, expected_sizes in (
            (b"key ", (24,)),
            (b"iviv", (24,)),
            (b"tmpr", (24,)),
            (b"righ", (88, 96)),
            (b"name", (264,)),
        ):
            header = bytes(
                final_memory.get(candidate_address + cursor + offset, 0)
                for offset in range(8)
            )
            atom_size = int.from_bytes(header[:4], "big")
            if header[4:8] != expected_type or atom_size not in expected_sizes:
                valid = False
                break
            atom_rows.append(
                {
                    "type": expected_type.decode("ascii"),
                    "offset": hex(cursor),
                    "bytes": atom_size,
                }
            )
            cursor += atom_size
        if not valid or cursor not in (424, 432):
            continue
        plaintext = bytes(
            final_memory.get(candidate_address + offset, 0)
            for offset in range(cursor)
        )
        inner_key = plaintext[8:24]
        clear_sinf_candidates.append(
            {
                "address": hex(candidate_address),
                "bytes": len(plaintext),
                "sha256": hashlib.sha256(plaintext).hexdigest(),
                "inner_key_hex": inner_key.hex(),
                "inner_key_sha256": hashlib.sha256(inner_key).hexdigest(),
                "plaintext_hex": plaintext.hex(),
                "atoms": atom_rows,
            }
        )
        if len(clear_sinf_candidates) >= 32:
            break

    report = {
        "startup": {
            "daemon_profile": args.daemon_profile,
            "cache_hit": startup_cache_hit,
            "cache_path": str(args.startup_cache),
            "stop": startup["stop"],
            "instructions": startup["instructions"],
            "overlay_bytes": len(startup["memory"]),
            "once_tokens": [hex(token) for token in sorted(startup["once_tokens"])],
            "external_calls": startup["external_calls"],
            "xpc_connections": startup.get("xpc_connections", []),
            "xpc_objects": startup.get("xpc_objects", []),
            "xpc_events": startup.get("xpc_events", []),
            "ascii_strings": startup.get("ascii_strings", []),
            "recent_pcs": [
                hex(address) for address in startup.get("recent_pcs", [])
            ],
        },
        "handler": {
            "supf_member": args.supf_member,
            "executable_member": args.executable_member,
            "executable_path": args.executable_path,
            "fairplay_state_files": fairplay_state_files,
            "sean_graft": (
                {
                    "path": str(args.sean_graft_clear),
                    "bytes": len(sean_graft_clear),
                    "sha256": hashlib.sha256(sean_graft_clear).hexdigest(),
                    "offline_forced_input": True,
                }
                if sean_graft_clear is not None
                else None
            ),
            "fairplay_iokit_profile": (
                args.fairplay_iokit_profile
                if args.model_iokit_run_versioned
                else None
            ),
            "io_mac_source": io_mac_source,
            "modeled_coreke_operation_10": args.model_coreke_operation_10,
            "fairplay_iokit_parameters": (
                {
                    "version": hex(effective_iokit_version),
                    "protocol_capabilities": hex(
                        effective_iokit_protocol_capabilities
                    ),
                    "monotonic_clock_size": monotonic_clock_size,
                }
                if args.model_iokit_run_versioned
                else None
            ),
            "modeled_iokit_runs": modeled_iokit_runs,
            "memory_qword_overrides": [
                {"address": hex(address), "value": hex(qword_value)}
                for address, qword_value in args.override_memory_qword
            ],
            "stage_count": len(result["stages"]),
            "events": result["events"],
            "file_accesses": file_accesses,
            "anonymous_accesses": anonymous_accesses,
            "copied_sinf_priv": copied_sinf_priv,
            "clear_sinf_candidates": clear_sinf_candidates,
            "last_stages": (
                result["stages"] if args.include_all_stages else result["stages"][-20:]
            ),
        },
    }
    if startup_file_reports or args.startup_directory:
        report["startup_inputs"] = {
            "files": startup_file_reports,
            "directories": sorted(args.startup_directory),
        }
    report["handler"]["status_slot_accesses"] = [
        {
            **access,
            "pc": hex(access["pc"]),
            "address": hex(access["address"]),
            "value": hex(access["value"]),
        }
        for access in result["memory_accesses"]
        if 0x7000000FFF80 <= access["address"] < 0x7000000FFF84
    ]
    report["handler"]["internal_status_accesses"] = [
        {
            **access,
            "pc": hex(access["pc"]),
            "address": hex(access["address"]),
            "value": hex(access["value"]),
        }
        for access in result["memory_accesses"]
        if 0x7000000F6F3C <= access["address"] < 0x7000000F6F40
    ]
    report["handler"]["result_object_field_accesses"] = [
        {
            **access,
            "pc": hex(access["pc"]),
            "address": hex(access["address"]),
            "value": hex(access["value"]),
        }
        for access in result["memory_accesses"]
        if 0x710000025498 <= access["address"] < 0x7100000254A0
    ]
    if args.watch_status:
        report["handler"]["encoded_status_register_writes"] = [
            {
                **access,
                "pc": hex(access["pc"]),
                "value": hex(access["value"]),
            }
            for access in result["register_accesses"]
            if (
                access["register"]
                in (
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                    "x22", "x28", "x30",
                )
                and (access["value"] & 0xFFFF0000) == 0x14E50000
            )
        ]
    if args.extra_watch_range:
        report["handler"]["extra_watch_accesses"] = [
            {
                **access,
                "pc": hex(access["pc"]),
                "address": hex(access["address"]),
                "value": hex(access["value"]),
            }
            for access in result["memory_accesses"]
            if any(
                start <= access["address"] < end
                for start, end in args.extra_watch_range
            )
        ]
    if args.watch_register:
        watched_registers = set(args.watch_register)
        report["handler"]["watched_register_accesses"] = [
            {
                **access,
                "pc": hex(access["pc"]),
                "value": hex(access["value"]),
            }
            for access in result["register_accesses"]
            if access["register"] in watched_registers
        ]
    sean_graft_event = next(
        (
            event
            for event in result["events"]
            if event.get("kind") == "ios26-sean-graft-installed"
        ),
        None,
    )
    if sean_graft_event is not None:
        graft_start = int(sean_graft_event["graft_address"], 16)
        graft_end = graft_start + int(sean_graft_event["graft_bytes"])
        report["handler"]["sean_graft_accesses"] = [
            {
                "operation": access["operation"],
                "pc": hex(access["pc"]),
                "offset": hex(access["address"] - graft_start),
                "size": access["size"],
                **(
                    {"stage": access["stage"]}
                    if "stage" in access
                    else {}
                ),
            }
            for access in result["memory_accesses"]
            if access["address"] < graft_end
            and access["address"] + access["size"] > graft_start
        ]
    if result["stages"]:
        final_stage = result["stages"][-1]
        scratch_text = final_stage.get("sp_memory", {}).get("0x198")
        if scratch_text is not None:
            scratch = int(scratch_text, 16)
            memory = result["final_memory"]
            report["handler"]["final_scratch"] = {
                "address": hex(scratch),
                "bytes": bytes(memory.get(scratch + offset, 0) for offset in range(66)).hex(),
            }
        if args.include_final_register_accesses:
            report["handler"]["x28_register_writes"] = [
                {
                    **access,
                    "pc": hex(access["pc"]),
                    "value": hex(access["value"]),
                }
                for access in result["register_accesses"]
                if access["register"] == "x28"
            ][-100:]
            report["handler"]["parser_status_register_writes"] = [
                {
                    **access,
                    "pc": hex(access["pc"]),
                    "value": hex(access["value"]),
                }
                for access in result["register_accesses"]
                if access["register"] in ("x19", "x20", "x21", "x22")
            ][-400:]
            report["handler"]["lineage_register_writes"] = [
                {
                    **access,
                    "pc": hex(access["pc"]),
                    "value": hex(access["value"]),
                }
                for access in result["register_accesses"]
                if access["register"] in ("x19", "x20", "x21")
            ][-2000:]
            final_stage_index = final_stage["index"]
            accesses = [
                access
                for access in result["register_accesses"]
                if access.get("stage") == final_stage_index
            ]
            selected_accesses = []
            for register in sorted({access["register"] for access in accesses}):
                selected_accesses.extend(
                    [
                        access
                        for access in accesses
                        if access["register"] == register
                    ][-50:]
                )
            selected_accesses.sort(key=lambda access: access["pc"])
            report["handler"]["final_register_accesses"] = [
                {
                    **access,
                    "pc": hex(access["pc"]),
                    "value": hex(access["value"]),
                }
                for access in selected_accesses
            ]
        if args.dump_final_memory_register or args.dump_final_memory_address:
            memory = result["final_memory"]
            dumps = []
            for register in args.dump_final_memory_register:
                address = int(final_stage.get("registers", {}).get(register, "0"), 16)
                data = bytearray()
                for offset in range(args.dump_final_memory_size):
                    byte = memory.get(address + offset)
                    if byte is None:
                        byte = db.bytes.get_byte_at(
                            address + offset,
                            allow_uninitialized=True,
                        )
                    data.append(byte & 0xFF)
                dumps.append(
                    {
                        "register": register,
                        "address": hex(address),
                        "bytes": bytes(data).hex(),
                    }
                )
            for address in args.dump_final_memory_address:
                data = bytearray()
                for offset in range(args.dump_final_memory_size):
                    byte = memory.get(address + offset)
                    if byte is None:
                        byte = db.bytes.get_byte_at(
                            address + offset,
                            allow_uninitialized=True,
                        )
                    data.append(byte & 0xFF)
                dumps.append(
                    {
                        "address": hex(address),
                        "bytes": bytes(data).hex(),
                    }
                )
            report["handler"]["final_memory_dumps"] = dumps
        if args.include_final_outputs:
            memory = result["final_memory"]
            report["handler"]["final_outputs"] = {
                "out_136": bytes(
                    memory.get(0x700000220000 + offset, 0)
                    for offset in range(136)
                ).hex(),
                "out_172": bytes(
                    memory.get(0x700000230000 + offset, 0)
                    for offset in range(172)
                ).hex(),
                "ool_slots": {
                    hex(address): hex(
                        sum(
                            memory.get(address + byte, 0) << (8 * byte)
                            for byte in range(8)
                        )
                    )
                    for address in (
                        0x700000240000,
                        0x700000250000,
                        0x700000260000,
                        0x700000270000,
                    )
                },
            }
    encoded_report = json.dumps(report, indent=2) + "\n"
    if args.output is None:
        print(encoded_report, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded_report)
        args.output.chmod(0o600)


if __name__ == "__main__":
    main()
