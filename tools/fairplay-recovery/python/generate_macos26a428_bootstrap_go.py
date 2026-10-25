#!/usr/bin/env python3
"""Generate the portable 26A428 account-state bootstrap loop."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x10057AE74
generator.STOP = generator.START
generator.BLOCK = 0x7000000EC3A0
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.INSTRUCTION_PATH_FIRST_REPEAT = True
generator.FUNCTION_NAME = "runRawSourceBootstrapKernel"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)


def page_range(start: int, end: int) -> set[int]:
    return set(range(start & ~0xFFF, (end + 0xFFF) & ~0xFFF, 0x1000))


entries = 166_464
generator.EXTRA_MODEL_PAGES = (
    page_range(0x7000000EC3A0, 0x7000000EC3A0 + entries * 4)
    | page_range(0x7000000ECEE0, 0x7000000ECEE0 + entries * 4)
    | page_range(0x710000014E04, 0x710000014E04 + entries * 4)
    | set(range(0x100FF1000, 0x101049000, 0x1000))
)


if __name__ == "__main__":
    generator.main()
