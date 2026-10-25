#!/usr/bin/env python3
"""Generate the optional 26A428 outer-iteration source block."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x1005BA520
generator.STOP = 0x1005BA6F8
generator.BLOCK = 0x7000000FB304
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.FUNCTION_NAME = "runRawSourceOptionalKernel"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)


if __name__ == "__main__":
    generator.main()
