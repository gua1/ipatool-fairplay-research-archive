# Packaged startup profiles

`macos26a428-startup.json.gz` is the account-independent fairplayd startup
overlay for the checked arm64e binary with SHA-256
`1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784`.

It contains only:

- the exact fairplayd binary hash;
- initialized virtual-memory bytes from deterministic daemon startup;
- two initialized `pthread_once` token addresses.

It does not contain an Apple Account identifier, SINF, SIDB, SUPF, IPA,
hardware MAC address, password, token, cookie, logical application key, or
recovered enrollment key. `trace_ios_fairplay_setup.py` verifies the captured
fairplayd hash before using it.

The profile is necessary because ordinary offline startup stops at the native
IOKit boundary before the daemon finishes generating its protected global
tables. Account-specific state is applied later from the private bundle created
by `ipatool fairplay-enroll collect`.
