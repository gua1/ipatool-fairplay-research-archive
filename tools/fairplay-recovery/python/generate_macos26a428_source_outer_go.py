#!/usr/bin/env python3
"""Generate one 26A428 raw-state outer iteration with lifted inner loops."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x1005B7438
generator.STOP = generator.START
generator.BLOCK = 0x7000000FB304
generator.RESULT_BLOCK = generator.BLOCK
generator.FAULT_SITES = {}
generator.INSTRUCTION_PATH_FIRST_REPEAT = True
generator.FUNCTION_NAME = "runRawSourceOuterIteration"
generator.EMIT_PROFILE_PREAMBLE = False
generator.DEFAULT_BUILD_TAG = (
    "fairplayrawsource && !fairplaysidb && !fairplayframe && "
    "!fairplaystate && !fairplay26a428"
)
generator.EXTRA_MODEL_PAGES = set(range(0x100FF1000, 0x10103B000, 0x1000))
generator.BLOCK_PATH_MACROS = {
    0x1005BA520: (
        0x1007B753C,
        "if s.x[9] == 0x1005BA520 { if err := runRawSourceOptionalKernel(s, fault{}); err != nil { return err } }",
    ),
    0x1004DB84C: (
        0x10042DFD4,
        "if _, err := runRawSourceKernelLoop(s, \"tail\"); err != nil { return err }",
    ),
    0x10063D134: (
        0x100808348,
        "if _, err := runRawSourceKernelLoop(s, \"even\"); err != nil { return err }",
    ),
    0x100767498: (
        0x1004A7604,
        "if _, err := runRawSourceKernelLoop(s, \"odd\"); err != nil { return err }",
    ),
    0x1007A8214: (
        0x1005D8A84,
        "if _, err := runRawSourceKernelLoop(s, \"digest-natural\"); err != nil { return err }",
    ),
    0x10051F828: (
        0x10050DF6C,
        "if _, err := runRawSourceKernelLoop(s, \"writer\"); err != nil { return err }",
    ),
}


if __name__ == "__main__":
    generator.main()
