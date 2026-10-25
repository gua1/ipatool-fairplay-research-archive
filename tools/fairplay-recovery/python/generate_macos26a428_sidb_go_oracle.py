#!/usr/bin/env python3
"""Generate the 26A428 SIDB white-box Go oracle and private model."""

from __future__ import annotations

import generate_macos_fairplay_go_oracle as generator


generator.START = 0x10008A644
generator.STOP = 0x100090780
generator.BLOCK = 0x700013400000
generator.INSTRUCTION_PATH = tuple(
    range(generator.START, 0x10008E974, 4)
) + tuple(range(0x10008ED6C, generator.STOP, 4))

# (PC, W-register, kind, byte shift) at three validated AES round boundaries.
generator.FAULT_SITES = {
    8: tuple(
        (0x10008FEFC, f"w{register}", "index-shift", shift)
        for register, shift in (
            (1, 0), (8, 8), (10, 16), (16, 16),
            (2, 16), (8, 0), (10, 8), (16, 8),
            (2, 8), (8, 24), (15, 0), (16, 0),
            (2, 0), (8, 16), (10, 24), (16, 24),
        )
    ),
    7: tuple(
        (0x10008FD3C, f"w{register}", "index-shift", shift)
        for register, shift in (
            (2, 0), (10, 24), (16, 0), (15, 24),
            (8, 24), (15, 0), (10, 8), (15, 16),
            (10, 16), (8, 8), (10, 0), (16, 8),
            (1, 8), (8, 0), (15, 8), (20, 8),
        )
    ),
    6: tuple(
        (0x10008FBC0, f"w{register}", "index-shift", shift)
        for register, shift in (
            (2, 8), (8, 8), (8, 0), (16, 0),
            (2, 0), (6, 16), (8, 24), (16, 24),
            (2, 24), (6, 8), (8, 16), (16, 16),
            (2, 16), (6, 0), (10, 0), (16, 8),
        )
    ),
}


if __name__ == "__main__":
    generator.main()
