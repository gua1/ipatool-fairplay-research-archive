# FairPlay enrollment model packs

`fairplay-decrypt --model` accepts either one private model file or a private
directory of selector-bound models. No enrollment keys or recovered models are
embedded in the ipatool binary or repository. `fairplay-decrypt` therefore
requires an explicit private `--model` for current-SINF decryption.

Accounts on the same OS build can use incompatible AES white-box profiles. A
model pack contains a recovered SINF decoder; it does not contain executable
code or require Apple hardware when it is used. Generate it locally, keep it
private, and move it to another machine only through a trusted channel.

All integers are little-endian. Version 2 is exactly 4,184 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x0000` | 8 | `FPSENR2\0` |
| `0x0008` | 4 | Format version (`2`) |
| `0x000c` | 4 | Complete pack size (`4184`) |
| `0x0010` | 32 | SHA-256 of the `fairplayd` build used for recovery |
| `0x0030` | 4 | SINF `user` selector |
| `0x0034` | 4 | SINF `key ` selector |
| `0x0038` | 16 | Recovered AES-128 key |
| `0x0048` | 16 | External-byte whitening period |
| `0x0058` | 4096 | Sixteen 256-byte inverse input permutations |

The selector prevents one account's AES model from being tried against another
account's license. A model directory accepts selector-bound version-2 or
version-3 packs and requires exactly one model for the input SINF selector.
Version-1 `FPSENR1\0` packs are still accepted only when passed as one explicit
file.

Every input table must be a permutation of all byte values. The SINF decoder
also validates the complete clear `key `/`iviv`/`tmpr`/`righ`/`name` atom
layout before accepting a logical key.

The pack contains private enrollment key material. Keep each file mode `0600`
and a model directory mode `0700`; the CLI rejects group- or world-readable
models and refuses to overwrite them even when `--force` is set.

The recovery step still needs a fault-capable white-box oracle. Once that AES
key, whitening period, and sixteen byte decoders have been recovered, the
version-2 pack makes the result directly reusable by ipatool without more
hardware calls.

## Version 3: 27-block current private codec

Version 3 represents the newer 432-byte current-SINF pipeline. It is exactly
8,708 bytes and remains a decoder model: using it performs ordinary Go AES
and table lookups only. Unicorn, the native FairPlay binary, and the recovery
oracle are not part of the runtime path.

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x0000` | 8 | `FPSENR3\0` |
| `0x0008` | 4 | Format version (`3`) |
| `0x000c` | 4 | Complete pack size (`8708`) |
| `0x0010` | 32 | SHA-256 of the `fairplayd` build used for recovery |
| `0x0030` | 4 | SINF `user` selector |
| `0x0034` | 4 | SINF `key ` selector |
| `0x0038` | 4 | Signed absolute source offset from the SINF root |
| `0x003c` | 4 | Source size (`432`) |
| `0x0040` | 1 | Final plaintext XOR byte |
| `0x0041` | 3 | Reserved; must be zero |
| `0x0044` | 16 | Recovered AES-128 key |
| `0x0054` | 4096 | Sixteen base output permutations |
| `0x1054` | 432 | Per-block/per-position output XOR masks |
| `0x1204` | 4096 | Sixteen final byte-codec permutations |

The decoder takes 27 ordinary AES input blocks from the model-selected SINF
range. For each block it applies AES-128 block decryption, the base output
permutation plus that block's XOR mask, and the final byte codec.
It then validates the complete `itun`/`vers`/`key `/`iviv`/`tmpr`/`righ`/`name`
layout before deriving a logical application key. All 48 byte tables must be
permutations, the source geometry is fixed at 432 bytes, and malformed models
or SINF bounds are rejected.

Version 3 stores about 8.5 KiB. The pack may contain enrollment-specific key
material and has the same `0600` handling requirement as older packs. Never
commit or distribute a recovered pack. Accept it only after it has produced the
correct logical-key hash and decrypted the matching IPA fixture end to end.

The DarkPhoenix input encoding is deliberately not stored. On the proven
26B118 path, decoding the bytes at the AES entry produces the exact 432-byte
SINF source range, so that range is already the ordinary AES input. The native
daemon needs its input encoding only to enter the white-box; the direct Go
implementation does not. The model records an absolute SINF source offset.
Both proven 26B118 layouts use absolute `0x1e0`: licenses with `crdt`/`asdt`
place that at `priv+0`, while compact licenses without those fields place it
at `priv+0x18`.

The version-3 builder requires at least one end-to-end SINF fixture and refuses
to emit an unvalidated pack.

