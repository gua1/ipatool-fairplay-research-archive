#!/usr/bin/env python3
"""Generate the repeated 26A428 enrollment-state block evaluator."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x100132AD0
generator.STOP = 0x1002FBB24
generator.BLOCK = 0x7000000FB524
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.INSTRUCTION_PATH_FIRST_REPEAT = True
generator.REPEAT_COUNT = 14


def sanitize_page(address: int, data: bytes) -> bytes:
    mutable = (
        address >= 0x700000000000
        or address in (0x101074000, 0x101075000, 0x101081000, 0x101084000)
    )
    if not mutable:
        return data
    result = bytearray(0x1000)
    for offset in range(0x1000):
        absolute = address + offset
        if absolute in generator.MODEL_INITIAL_READ_BYTES:
            result[offset] = data[offset]
    input_start = generator.BLOCK
    input_end = input_start + 224
    for absolute in range(max(address, input_start), min(address + 0x1000, input_end)):
        result[absolute - address] = 0
    return bytes(result)


generator.MODEL_PAGE_SANITIZER = sanitize_page


if __name__ == "__main__":
    generator.main()
