# Offline checkpoint tooling

These scripts construct and validate the exact-build private checkpoints used
by `ipatool fairplay-enroll recover`.

The public command launches `recover_capture.py` through `uv` with:

- `capstone` for ARM64 decoding;
- `unicorn` for bounded checkpoint continuation and differential validation;
- `pycryptodome` for packaging the recovered enrollment model.

The scripts do not attach to a running process and do not contact Apple. They
consume only the private bundle produced by `fairplay-enroll collect`, the
account-independent startup profile, and the checked Go evaluator.

No Apple binary, enrollment record, SINF, SUPF, SIDB, hardware identifier,
password, cookie, Store token, or recovered key is stored in this directory.
Generated checkpoints, oracle models, JSON recovery files, and enrollment
packs are private outputs and must remain mode `0600` inside a mode-`0700`
directory.

`build_startup_profile.py` exists only for adding a newly validated fairplayd
build. It strips registers, paths, request buffers, and file payloads from a
pre-request startup checkpoint before producing a deterministic profile.
