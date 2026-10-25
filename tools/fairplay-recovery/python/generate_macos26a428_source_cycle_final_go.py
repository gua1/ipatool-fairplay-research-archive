#!/usr/bin/env python3
"""Generate the optional final block of the 26A428 source cycle."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x10046119C
generator.STOP = 0x1004612B4
generator.BLOCK = 0x7000000F2148
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.FUNCTION_NAME = "runRawSourceCycleFinal"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)


if __name__ == "__main__":
    generator.main()
