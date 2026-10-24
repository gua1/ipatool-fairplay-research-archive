"""Minimal file-backed Mach-O facade for :mod:`ida_static_arm64`.

This is intentionally small: it maps file-backed ``LC_SEGMENT_64`` ranges and
implements the byte/name methods consumed by the static evaluator.  It does
not replace IDA analysis.  Its purpose is to keep tracing moving when an IDA
worker is busy auto-analyzing a heavily protected image.  Optional mappings
from ``dyld_info -fixups`` make on-disk chained rebases and binds look like the
values dyld would install without modifying the input image.
"""

from __future__ import annotations

import struct
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
SYNTHETIC_EXTERNAL_BASE = 0xF100000000000000
SYNTHETIC_EXTERNAL_STRIDE = 0x1000


@dataclass(frozen=True)
class MachOSegment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int

    @property
    def end_ea(self) -> int:
        return self.vmaddr + self.vmsize

    @property
    def file_end_ea(self) -> int:
        return self.vmaddr + self.filesize


@dataclass(frozen=True)
class MachOSection:
    name: str
    segment_name: str
    vmaddr: int
    size: int
    fileoff: int
    flags: int

    @property
    def end_ea(self) -> int:
        return self.vmaddr + self.size

    @property
    def contains_instructions(self) -> bool:
        # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        return bool(self.flags & (0x80000000 | 0x00000400))


class _RawBytes:
    def __init__(self, owner: "RawMachODatabase") -> None:
        self.owner = owner

    def is_value_initialized_at(self, address: int) -> bool:
        return self.owner.address_to_offset(address) is not None

    def _get(self, address: int, size: int, allow_uninitialized: bool = False) -> int:
        offset = self.owner.address_to_offset(address, size)
        if offset is None:
            if allow_uninitialized:
                return 0
            raise ValueError(f"uninitialized Mach-O address {address:#x}")
        return int.from_bytes(self.owner.image[offset : offset + size], "little")

    def get_byte_at(self, address: int, allow_uninitialized: bool = False) -> int:
        return self._get(address, 1, allow_uninitialized)

    def get_word_at(self, address: int, allow_uninitialized: bool = False) -> int:
        return self._get(address, 2, allow_uninitialized)

    def get_dword_at(self, address: int, allow_uninitialized: bool = False) -> int:
        return self._get(address, 4, allow_uninitialized)

    def get_qword_at(self, address: int, allow_uninitialized: bool = False) -> int:
        return self._get(address, 8, allow_uninitialized)


class _RawNames:
    def __init__(self, names: dict[int, str]) -> None:
        self.names = names

    def get_at(self, address: int) -> str | None:
        return self.names.get(address)


class _RawFunctions:
    @staticmethod
    def get_at(_address: int) -> None:
        return None

    @staticmethod
    def get_name(_function: Any) -> str | None:
        return None


class RawMachODatabase:
    """Expose file-backed Mach-O bytes through the evaluator's DB protocol."""

    def __init__(
        self,
        path: str | Path,
        *,
        names: dict[int, str] | None = None,
        fixups: dict[int, int] | None = None,
    ) -> None:
        self.path = Path(path)
        self.image = self.path.read_bytes()
        self.segments = self._parse_segments()
        self.sections = self._parse_sections()
        mapped = [
            segment
            for segment in self.segments
            if segment.vmsize and segment.name != "__PAGEZERO"
        ]
        if not mapped:
            raise ValueError("Mach-O has no non-PAGEZERO 64-bit segments")
        self.minimum_ea = min(segment.vmaddr for segment in mapped)
        self.maximum_ea = max(segment.end_ea for segment in mapped)
        self.bytes = _RawBytes(self)
        self.names = _RawNames(dict(names or {}))
        self.functions = _RawFunctions()
        self.fixups = dict(fixups or {})
        # ``dyld_info -fixups`` gives this facade the authoritative set of
        # pointer storage locations.  Callers must not heuristically decode a
        # high-bit 64-bit numeric constant merely because it resembles an
        # arm64e chained-pointer word.
        self.exact_pointer_fixups = fixups is not None

    def _parse_segments(self) -> list[MachOSegment]:
        if len(self.image) < 32:
            raise ValueError("truncated Mach-O header")
        magic, = struct.unpack_from("<I", self.image, 0)
        if magic != MH_MAGIC_64:
            raise ValueError(f"unsupported Mach-O magic {magic:#x}")
        ncmds, sizeofcmds = struct.unpack_from("<II", self.image, 16)
        command_offset = 32
        command_end = command_offset + sizeofcmds
        if command_end > len(self.image):
            raise ValueError("truncated Mach-O load commands")

        segments: list[MachOSegment] = []
        for _ in range(ncmds):
            command, command_size = struct.unpack_from("<II", self.image, command_offset)
            if command_size < 8 or command_offset + command_size > command_end:
                raise ValueError("invalid Mach-O load command size")
            if command == LC_SEGMENT_64:
                raw_name = self.image[command_offset + 8 : command_offset + 24]
                name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ",
                    self.image,
                    command_offset + 24,
                )
                segments.append(
                    MachOSegment(name, vmaddr, vmsize, fileoff, filesize)
                )
            command_offset += command_size
        return segments

    def _parse_sections(self) -> list[MachOSection]:
        ncmds, sizeofcmds = struct.unpack_from("<II", self.image, 16)
        command_offset = 32
        command_end = command_offset + sizeofcmds
        sections: list[MachOSection] = []
        for _ in range(ncmds):
            command, command_size = struct.unpack_from(
                "<II", self.image, command_offset
            )
            if command_size < 8 or command_offset + command_size > command_end:
                raise ValueError("invalid Mach-O load command size")
            if command == LC_SEGMENT_64:
                section_count, = struct.unpack_from(
                    "<I", self.image, command_offset + 64
                )
                section_offset = command_offset + 72
                if section_offset + section_count * 80 > command_offset + command_size:
                    raise ValueError("truncated Mach-O section table")
                for section_index in range(section_count):
                    offset = section_offset + section_index * 80
                    raw_name = self.image[offset : offset + 16]
                    raw_segment = self.image[offset + 16 : offset + 32]
                    name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
                    segment_name = raw_segment.split(b"\0", 1)[0].decode(
                        "ascii", "replace"
                    )
                    vmaddr, size = struct.unpack_from("<QQ", self.image, offset + 32)
                    fileoff, = struct.unpack_from("<I", self.image, offset + 48)
                    flags, = struct.unpack_from("<I", self.image, offset + 64)
                    sections.append(
                        MachOSection(
                            name,
                            segment_name,
                            vmaddr,
                            size,
                            fileoff,
                            flags,
                        )
                    )
            command_offset += command_size
        return sections

    def address_to_offset(self, address: int, size: int = 1) -> int | None:
        for segment in self.segments:
            if (
                segment.filesize
                and segment.vmaddr <= address
                and address + size <= segment.file_end_ea
            ):
                offset = segment.fileoff + address - segment.vmaddr
                if offset + size <= len(self.image):
                    return offset
        return None

    def is_valid_ea(self, address: int) -> bool:
        return any(
            segment.name != "__PAGEZERO"
            and segment.vmaddr <= address < segment.end_ea
            for segment in self.segments
        )

    def resolve_pointer(self, address: int, _raw_value: int) -> int | None:
        """Return dyld's resolved value for a pointer storage location."""

        return self.fixups.get(address)


def dyld_info_fixups(
    path: str | Path,
) -> tuple[dict[int, int], dict[int, str]]:
    """Return resolved pointer locations and names from ``dyld_info -fixups``.

    Rebase targets retain their real virtual addresses.  Each distinct import
    gets a stable synthetic address outside the Mach-O image, allowing the
    evaluator to report and hook it without mistaking it for internal code.
    """

    output = subprocess.run(
        ["xcrun", "dyld_info", "-fixups", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fixups: dict[int, int] = {}
    names: dict[int, str] = {}
    external_addresses: dict[str, int] = {}
    pattern = re.compile(
        r"^\s*\S+\s+\S+\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(auth-bind|bind|auth-rebase|rebase)\s+"
        r"(.+?)\s*$"
    )

    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        location = int(match.group(1), 16)
        kind = match.group(2)
        target_text = re.sub(r"\s+\([^)]*\)\s*$", "", match.group(3))
        if kind.endswith("rebase"):
            target_match = re.match(r"0x[0-9a-fA-F]+", target_text)
            if target_match:
                fixups[location] = int(target_match.group(0), 16)
            continue

        target_text = re.sub(r"\s+\[weak-import\]\s*$", "", target_text)
        symbol = target_text.rsplit("/", 1)[-1]
        synthetic = external_addresses.get(symbol)
        if synthetic is None:
            synthetic = (
                SYNTHETIC_EXTERNAL_BASE
                + len(external_addresses) * SYNTHETIC_EXTERNAL_STRIDE
            )
            external_addresses[symbol] = synthetic
            names[synthetic] = symbol
        fixups[location] = synthetic

    return fixups, names


def otool_indirect_names(path: str | Path) -> dict[int, str]:
    """Return address-to-symbol names reported by ``otool -Iv``."""

    output = subprocess.run(
        ["otool", "-Iv", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names: dict[int, str] = {}
    pattern = re.compile(r"^0x([0-9a-fA-F]+)\s+\d+\s+(\S+)$")
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            names[int(match.group(1), 16)] = match.group(2)
    return names
