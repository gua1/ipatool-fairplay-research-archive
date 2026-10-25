#!/usr/bin/env python3
"""Generate the 26A428 six-iteration raw-state cycle boundary."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x1007822CC
generator.STOP = 0x1005B7438
generator.BLOCK = 0x7000000F2148
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.FUNCTION_NAME = "runRawSourceCycleBoundary"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)


if __name__ == "__main__":
    generator.main()
