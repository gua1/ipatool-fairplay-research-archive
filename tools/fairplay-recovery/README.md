# Go FairPlay white-box recovery

This is a build-specific, generated evaluator for the recovered macOS 26B118
FairPlay AES white-box boundary `0x100221894..0x100223a30`.

The default 26B118 path is exactly 2,151 straight-line ARM64 instructions. The
26A428 profile contains 2,153 traced operations plus two fixed authenticated
branch detours. Both are represented as unrolled Go. Dynamic checkpoint
memory, registers, and any encoded index domains live in a separate private
model. The Go runtime does not use Unicorn or execute Apple code.

The private oracle model contains enrollment state. Keep it mode `0600`; never
add it to source control or distribute it with ipatool. The generated Go source
holds only build-specific operations, addresses, and fault-site metadata.

The recovery algorithm is a narrow Go adaptation of DarkPhoenix's Apache-2.0
partial AES-128 decrypt attack. Its attribution and license are in
`LICENSE-DARKPHOENIX.txt`. It implements only the path used here: fixed fault
sites, Steps 1 through 4, one Step-5 round key, and external encodings. It does
not include the generic Metal, AES-192/256, reverse-oracle, encryption, or
automatic fault-discovery features.

## Supported profiles

| Profile | Status |
| --- | --- |
| `26A428` (`-tags fairplay26a428`, including the checked fairplayd slice shipped on macOS `26A434`) | Full recovery and end-to-end IPA decryption proven for a matching modern Apple Account enrollment |
| `26B118` capture | End-to-end recovery is proven through the checked 26A428 CBC compatibility evaluator; the native V3 consumer remains research-only |
| `26A428` SIDB bulk decoder (`-tags fairplaysidb`) | Pure-Go recovery with an embedded sanitized build model; a private 16-byte enrollment frame is supplied at runtime |
| `26A428` frame evaluator (`-tags fairplayframe`) | Pure-Go direct evaluator with an embedded sanitized build model; exact across two independent enrollment inputs |
| `26A428` state-slot evaluator (`-tags fairplaystate`) | Pure-Go 14-slot transform with an embedded sanitized build model; every retained native slot matches across two enrollments |
| All other fairplayd builds | Unsupported until their evaluator and fault map are generated and differentially validated |

Only modern App Store enrollments from newly created Apple Accounts are in
scope. Legacy or migrated accounts are not currently supported. Do not infer
support from the macOS product version alone: the exact build and fairplayd
SHA-256 must match.

## What the private model represents

“Generated once” means once per exact fairplayd build and local App Store
enrollment. The private model is a snapshot-derived set of registers, memory
pages, and generated lookup tables from the white-box entry. It is not a
generic model for every user, and another person's model must not be reused.

Before capture, the fresh Apple Account must have completed native App Store
setup and a free app must have been installed and opened through the Mac App
Store. Downloading only through ipatool does not initialize the same native
enrollment. `ipatool fairplay-enroll collect` creates the private bundle and
`fairplay-enroll recover` runs the packaged offline trace. Neither command
attaches to the live fairplayd process or provisions an Apple Account.

The recovered enrollment pack can be reused for matching IPAs while the
account enrollment and SINF selector remain unchanged. Recapture after an
enrollment reset, selector change, or when recovering from another fairplayd
build. Treat the checkpoint, oracle model, recovered JSON, and final enrollment
pack as private secrets.

For 26B118, pass the exact checked 26A428 arm64e fairplayd image with
`--compat-fairplayd`. It is used only as an offline evaluator and is not
bundled. A model is published as `fairplay-enrollment.bin` only after the
matching downloaded IPA passes every decryption check; failed output remains
`fairplay-enrollment.candidate.bin` and must not be used.

## Normal workflow

Run the public commands from the ipatool source tree:

```sh
sudo ipatool fairplay-enroll collect \
  --app /Applications/App.app \
  --ipa /private/path/App.ipa \
  --output /private/path/App.capture

ipatool fairplay-doctor --capture /private/path/App.capture

ipatool fairplay-enroll recover \
  --capture /private/path/App.capture \
  --output /private/path/App.recovery
```

The recover command uses the Python tools in `python/`, the sanitized
account-independent startup state in `profiles/`, and the Go evaluator in this
directory. It requires `uv` and a Go toolchain. The capture and recovery output
directories are private and must not already exist.

The packaged startup profile initializes only deterministic build state. Its
contents and privacy boundary are documented in `profiles/README.md`; all
account, license, SIDB, hardware, and IPA inputs come from the private capture
at runtime.

## Generate

First collect one bounded Unicorn memory trace for the exact checkpoint. From
the outer research workspace, generate the private evaluator model with:

```sh
uv run --with capstone --with unicorn python \
  analysis/generate_macos_fairplay_go_oracle.py \
  /private/path/whitebox-entry.checkpoint.pkl.gz \
  --memory-trace /private/path/oracle-memory-trace.json \
  --go-output /private/tmp/generated_26b118.go \
  --model-output /private/tmp/fairplay-go-oracle-model.bin.gz
```

The checked-in `generated_26b118.go` was produced by that generator. A new
fairplayd build must be regenerated and differentially validated; addresses
must not be rebased by guesswork.

Run the exact normal/fault differential with:

```sh
uv run --with capstone --with unicorn python \
  analysis/validate_macos_fairplay_go_oracle.py \
  /private/path/whitebox-entry.checkpoint.pkl.gz \
  --go-oracle /private/tmp/fairplay-go-oracle \
  --model /private/tmp/fairplay-go-oracle-model.bin.gz
```

## Build and recover

```sh
umask 077
cd analysis/third_party/ipatool-main-kbsync
go build -o /private/tmp/fairplay-recovery ./tools/fairplay-recovery

/private/tmp/fairplay-recovery \
  --model /private/tmp/fairplay-go-oracle-model.bin.gz \
  --workers 15 \
  --recover-output /private/tmp/recovered-whitebox-model.json
```

The recovery is intentionally partial: one recovered AES-128 round key is
sufficient to reverse the key schedule. Recovering every earlier round wastes
work and requires additional fault sites. The output contains private key
material, is written atomically with mode `0600`, and must not be published.

## Validation and performance

The 26B118 implementation was checked against Unicorn for normal execution and
144 faulted cases covering rounds 6, 7, and 8 with XOR values `1`, `7`, and
`255`. Every 16-byte output matched exactly.

The complete in-process Go recovery finishes in roughly 0.8 to 1.0 seconds on
this 15-core machine. On 26B118 the recovered AES key, input encoding, and
output encoding are byte-identical to the earlier independent recovery. A
standalone batch of 1,048,576 faulted evaluations completes in about 1.10
seconds.

Without `--recover-output`, the same binary still speaks the binary external
oracle protocol for differential testing. Production recovery uses the
in-process path and has no Swift, Metal, DarkPhoenix executable, or Unicorn
runtime dependency.

## Packaged pipeline

`analysis/run_portable_fairplay_pipeline.py` ties together checkpoint
continuation, Go-oracle generation, differential validation, Go recovery,
`FPSENR3` construction, ipatool, and end-to-end CodeDirectory checks.

Recover from an exact 26B118 white-box checkpoint and decrypt its matching IPA:

```sh
python3 analysis/run_portable_fairplay_pipeline.py \
  --oracle-checkpoint /private/path/whitebox-entry.checkpoint.pkl.gz \
  --sinf /private/path/App.sinf \
  --ipa /private/path/App.ipa \
  --output-dir /private/path/App-recovery
```

An earlier request-502 SINF-copy checkpoint can be passed with
`--entry-checkpoint`; the pipeline then performs the bounded continuation to
the white-box entry itself.

The 26A428 current-SINF profile has its own checked Go evaluator, selected with
the `fairplay26a428` build tag. Its fixed authenticated-branch detours and
state-lane fault sites are modeled explicitly. It is packaged by the same
command and must be validated immediately against a matching IPA:

```sh
python3 analysis/run_portable_fairplay_pipeline.py \
  --recovery-profile macos26a428 \
  --oracle-checkpoint /private/path/core-entry.checkpoint.pkl.gz \
  --source-checkpoint /private/path/first-private-read.checkpoint.pkl.gz \
  --whitebox-output-checkpoint /private/path/first-transform-output.checkpoint.pkl.gz \
  --sinf /private/path/App.sinf \
  --ipa /private/path/App.ipa \
  --output-dir /private/path/App-recovery
```

The 26A428 mode deliberately has no recovery-only option: the candidate model
is accepted only if the matching IPA passes all page-hash checks.
Instead of the three prepared checkpoints, `--entry-checkpoint` may point to
the supported 26A428 selected-record checkpoint (`0x1005cba90`) or its earlier
account-loop checkpoint (`0x10057ae74`). The pipeline derives the source,
first-transform, and core-oracle checkpoints automatically.

The 26A428 Go profile is validated against 256 random ordinary inputs and 144
faulted cases before recovery. Its complete in-process recovery takes about
one second on the 15-core development Mac.

### Portable SIDB bulk decoder

The `fairplaysidb` build tag selects a separate 26A428 evaluator for the
unrolled SIDB block consumer at `0x10008a644..0x100090780`. It contains 5,969
operations in the one validated path, including its fixed authenticated-branch
detour. Its embedded `profiles/macos26a428-sidb-public.model.gz` contains only
sanitized build state. The enrollment frame is zero in that artifact and must
be supplied from a mode-`0600` file with `--enrollment-frame`.

The in-process Go recovery was checked against two independent accepted
enrollments. It reproduced their earlier key hashes exactly in about 2.7 and
3.4 seconds. Both enrollments produced byte-identical input and output
encodings. A sixteen-case causal differential also showed that each byte of
the preceding enrollment frame has full diffusion into the recovered key,
while neither external encoding changes.

The public model includes both validated 26A428 control-flow variants. Replacing
only its runtime frame reproduces both retained enrollments' exact recovered
keys. Exact searches for either retained frame, source field, or recovered key
are negative in both the compressed and decompressed artifact.

```sh
go build -tags fairplaysidb -o /private/tmp/fairplay-sidb \
  ./tools/fairplay-recovery

/private/tmp/fairplay-sidb \
  --enrollment-frame /private/path/enrollment-frame.bin \
  --recover-output /private/path/recovered-sidb-model.json
```

Both files are private; the frame is exactly 16 bytes and the output must not
already exist. Do not ship a recovered SIDB key as a build-global constant.
This component is not yet the normal `fairplay-enroll recover` path because the
remaining upstream stage still has to construct the 192/224-byte source field
at object `+0x304` from captured raw state and hardware identity.

### Enrollment-frame evaluator

The `fairplayframe` tag selects the direct 26A428 evaluator for
`0x1002fbb24..0x1002ff8d8`. This is the second natural invocation of that
mixer: the first writes neighboring state at object `+0x744`; the second maps
the 16-byte block at object `+0x524` to the decoder frame at object `+0x724`.
Changing the neighboring `+0x744` field has no effect on the recovered SIDB
AES model.

This evaluator does not need DarkPhoenix or a private oracle model. Its
embedded `profiles/macos26a428-frame-public.model.gz` contains only fixed
26A428 code/data, two required internal pointers, and two build-state words.
The generator zeros the input, output, unused object bytes, and unused stack
bytes before publication. Tests enforce that allowlist. The same embedded
model maps both retained enrollments' distinct inputs to their exact native
frames, so no account key or enrollment secret is hardcoded.

```sh
go build -tags fairplayframe -o /private/tmp/fairplay-frame \
  ./tools/fairplay-recovery
```

Use `--evaluate-input` and `--evaluate-output` with mode-`0600` 16-byte files
to map one transformed candidate to its enrollment frame. It is a portable
component for the capture-to-model pipeline. The remaining upstream task is
deriving the state evaluator's 192/224-byte input directly from captured raw
state and hardware identity.

### State-slot evaluator

The `fairplaystate` tag selects the repeated transform beginning at
`0x100132ad0`. The same 2,378-instruction path processes fourteen 16-byte
slots. The generated Go keeps one copy of that path and executes it fourteen
times; it does not embed a trace interpreter or Apple binary.

Its evaluator accepts the 192- or 224-byte source field at object `+0x304`.
The generated build profile applies the proved repeating 16-byte input
encoding and zero-pads the shorter form to fourteen slots. Only real candidate
slots are tested downstream. The transformed slots match every retained
native slot for both enrollments. Their selected slots differ (1 for the local
control, 8 for the external control), so portable recovery can try every real
slot through the frame evaluator and accept only the candidate whose decrypted
SINF atom tree validates.

```sh
go build -tags fairplaystate -o /private/tmp/fairplay-state \
  ./tools/fairplay-recovery

/private/tmp/fairplay-state \
  --evaluate-input /private/path/state-slots.bin \
  --evaluate-output /private/path/state-slots.transformed.bin
```

Both files must be mode `0600`; the output must not already exist. Only hashes
are printed. The embedded model zeros the complete 224-byte working buffer and
retains only memory bytes read before the evaluator overwrites them.

### Raw source-kernel port

The research-only `fairplayrawsource` build contains generated Go for the five
hottest repeated kernels between raw SIDB loading and object `+0x304`:

- the 652-operation general writer;
- the 453-operation tail writer;
- the 221-operation even-byte writer;
- the 312-operation odd-byte writer;
- the 1,719-operation digest core plus its 13-operation loop prologue.

Each function was generated independently from both retained enrollments; the
Go source is byte-identical. One-step and natural-loop state digests match the
native checkpoints exactly for both controls. The checked loop counts are
61/55, 140/140, 50/50, 50/50, and 11/11 respectively. Together these kernels
cover about 82% and 81% of the dynamic instructions represented by the top-250
block profiles.

The surrounding outer source loop is generated too. It replaces the five hot
spans with direct Go calls, models the optional block and six-iteration cycle
boundary, and matches the complete native state after 226 iterations for A and
116 for B. It emits the exact native 224/192-byte `+0x304` fields in roughly
0.05/0.02 seconds. Feeding those outputs through the existing Go state, frame,
and SIDB evaluators reproduces both retained enrollment frames and decoder-key
hashes end to end.

This build intentionally has no embedded account model and is not part of the
normal user workflow. It consumes a mode-`0600` private outer-entry model and
can write the exact `+0x304` source with `--raw-source-output` and
`--raw-source-bytes`. The remaining work is upstream: construct that outer-entry
model directly from the captured raw SIDB and hardware identity. No private
outer model is embedded or committed.

Use an already recovered external model without placing it in the ipatool
repository:

```sh
python3 analysis/run_portable_fairplay_pipeline.py \
  --existing-model /private/path/fairplay-enrollment.bin \
  --ipa /private/path/App.ipa \
  --output-dir /private/path/App-decrypted
```

The output directory must not exist. It is created mode `0700`, and all
secret-bearing files are mode `0600`. The pipeline fails unless every encrypted
Mach-O has `cryptid=0` and every available CodeDirectory page hash matches.
