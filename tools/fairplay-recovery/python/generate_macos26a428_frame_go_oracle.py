#!/usr/bin/env python3
"""Generate the portable 26A428 enrollment-frame evaluator."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x1002FBB24
generator.STOP = 0x1002FF8D8
generator.BLOCK = 0x7000000FB524
generator.RESULT_BLOCK = 0x7000000FB724
generator.COPY_RESULT_TO_BLOCK = True
generator.FAULT_SITES = {}


def sanitize_page(address: int, data: bytes) -> bytes:
    """Retain only public build state and the two required stack pointers."""
    if address == 0x7000000FB000:
        return bytes(0x1000)
    if address == 0x7000000EE000:
        result = bytearray(0x1000)
        for target in (0x7000000EEAF8, 0x7000000EEB00):
            offset = target - address
            result[offset : offset + 8] = data[offset : offset + 8]
        return bytes(result)
    if address in (0x101074000, 0x101075000):
        target = 0x1010744C8 if address == 0x101074000 else 0x101075B40
        offset = target - address
        result = bytearray(0x1000)
        result[offset : offset + 4] = data[offset : offset + 4]
        return bytes(result)
    return data


generator.MODEL_PAGE_SANITIZER = sanitize_page


if __name__ == "__main__":
    generator.main()
