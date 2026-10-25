#!/usr/bin/env python3
"""Generate the 26A428 raw-state digest loop prologue."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x1007A8214
generator.STOP = 0x1007A8248
generator.BLOCK = 0x700012908004
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.FUNCTION_NAME = "runRawSourceDigestPrologue"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)


if __name__ == "__main__":
    generator.main()
