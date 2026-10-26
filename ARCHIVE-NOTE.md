# Archive note

This repository preserves the FairPlay research fork of ipatool by Jurre van Bergen (DrWhax),
formerly published at https://github.com/DrWhax/ipatool. That repository was deleted around
2026-10-26. Its work continues in https://github.com/DrWhax/unfairplay, whose NOTICE says it
contains code from this fork "through commit 60208cf".

## How it was recovered

GitHub keeps the commits of a deleted fork inside its fork network. The fork's last commit,
60208cfa0998ca687f4f53da20981ab57a9b0368 (2026-10-25, "fairplay: verify portable 25G83 recovery"),
was fetched by its SHA from https://github.com/majd/ipatool. Its history holds 315 commits,
44 of them by Jurre van Bergen (2026-10-20 to 2026-10-25), including the research tooling in
tools/fairplay-recovery.

## What changed

- One file was removed from every commit that contained it:
  internal/fairplay/models/macos26-26A428-current-sinf.bin, an enrollment model holding the
  original author's private account key material (added 2026-10-20, deleted by the author on
  2026-10-24). A scan of every blob in the history found that key nowhere else.
- Two FairPlay account selectors belonging to the original author's enrollments were replaced
  with the placeholders aaaaaaaa and bbbbbbbb wherever they appeared (README.md,
  internal/fairplay/current_sinf.go, internal/fairplay/current_sinf_test.go,
  internal/fairplay/models/README.md and tools/fairplay-recovery/README.md). Selectors used by
  synthetic test fixtures were left as they are.
- Nothing else was altered. Authors, dates and messages are preserved. The final tree differs
  from the tree of 60208cf only by the placeholder in two README lines. Every commit by the
  original author has a new SHA; SHA-MAP.txt lists the old and new SHA of each.
- This note and SHA-MAP.txt are the only additions.

## Licensing

- ipatool is MIT licensed, Copyright (c) 2021 Majd Alfhaily (see LICENSE).
- tools/fairplay-recovery includes code adapted from DarkPhoenix under the Apache License 2.0
  (see tools/fairplay-recovery/LICENSE-DARKPHOENIX.txt).

This archive is not affiliated with or endorsed by Apple, ipatool's maintainers or the original
author. Apple, FairPlay, macOS, iOS and App Store are trademarks of Apple Inc.
