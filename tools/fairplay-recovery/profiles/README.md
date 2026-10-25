# Packaged startup profiles

The packaged account-independent fairplayd startup overlays are:

- `macos26a428-startup.json.gz` for arm64e SHA-256
  `1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784`;
- `macos26b118-startup.json.gz` for arm64e SHA-256
  `f68e4407e90af5466d2766e1b1c4637260d08cb0518f991e1797ac6c4964439d`.

The canonical compressed profile SHA-256 values are
`ae76565e...e0bca9e` (26A428) and `ed03021a...7c0b43` (26B118). Tests reject
unknown fields, digest changes, unsorted/duplicate addresses, non-byte memory
values, or changed once-token geometry.

It contains only:

- the exact fairplayd binary hash;
- initialized virtual-memory bytes from deterministic daemon startup;
- two initialized `pthread_once` token addresses.

It does not contain an Apple Account identifier, SINF, SIDB, SUPF, IPA,
hardware MAC address, password, token, cookie, logical application key, or
recovered enrollment key. `trace_ios_fairplay_setup.py` verifies the captured
fairplayd hash before using it.

`macos26a428-frame-public.model.gz` is a separate, sanitized Go-evaluator
model (SHA-256 `b10da4b2...eba849`). It contains fixed build state only. Its
account input/output and unused object/stack bytes are zero, and tagged tests
enforce the exact nonzero-byte allowlist before the model can be used.

`macos26a428-state-public.model.gz` is the sanitized model for the repeated
14-slot evaluator (SHA-256 `d4b05fba...232288`). Its complete 224-byte input
is zero in the published artifact. Dynamic pages retain only bytes read before
the generated evaluator overwrites them; unused checkpoint memory is removed.
The separate generated 16-byte periodic decoder converts the 192/224-byte
object source field into that working-buffer representation.

`macos26a428-sidb-public.model.gz` is the sanitized 71-page model for both
validated paths through the SIDB block consumer (SHA-256
`cee524a1...adeadba`). Its 16-byte enrollment frame is zero and supplied only
at runtime. Dynamic pages retain only bytes read before overwrite. Tagged tests
execute the complete generated path with a public deterministic frame/input,
and local privacy checks find neither retained enrollment frame, source field,
nor recovered key in the compressed or decompressed artifact.

`macos26a428-account-entry-public.model.gz` is the sanitized pre-license model
for the complete Go enrollment-source path (SHA-256
`3f5efce0...8aea9af`). It is captured before the installed SINF and SUPF are
opened. The executable-path page is all zero and supplied at runtime. The
retained pages are restricted to the union accessed by two independent
account controls; private-window audits find no account-specific SINF, SIDB,
source field, hardware address, or executable path. The same model reproduces
the preserved older-account 192-byte source without iPhone/iOS 16 material.

The profile is necessary because ordinary offline startup stops at the native
IOKit boundary before the daemon finishes generating its protected global
tables. Account-specific state is applied later from the private bundle created
by `ipatool fairplay-enroll collect`.
