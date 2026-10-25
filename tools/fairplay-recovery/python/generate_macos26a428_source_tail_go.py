#!/usr/bin/env python3
"""Generate one portable 26A428 raw-state tail-writer iteration."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x1004DB84C
generator.STOP = generator.START
generator.BLOCK = 0x7000000FB304
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.INSTRUCTION_PATH_FIRST_REPEAT = True
generator.FUNCTION_NAME = "runRawSourceTailKernel"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)


if __name__ == "__main__":
    generator.main()
