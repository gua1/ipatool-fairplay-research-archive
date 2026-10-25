<p align="center">
  <a href="https://GitHub.com/majd/ipatool/releases/"><img src="https://img.shields.io/github/release/majd/ipatool.svg?label=Release" alt="Release"></a>
  <a href="https://github.com/majd/ipatool/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
  <a href="https://github.com/sponsors/majd"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink.svg" alt="Sponsor"></a>
</p>

<p align="center">
  <code>ipatool</code> is a command line tool that allows you to search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps on the <a href="https://apps.apple.com">App Store</a>, and download <code>.ipa</code> or macOS <code>.pkg</code> app packages.
</p>

<p align="center">
  <img src="./resources/demo.gif" alt="Demo">
</p>

## Requirements

- A supported operating system (macOS, Linux, Windows or iOS).
- An Apple Account already configured to use the App Store.

## Installation

### Linux and Windows

You can grab the latest version of `ipatool` from [GitHub releases](https://github.com/majd/ipatool/releases).

### macOS

You can install `ipatool` using [Homebrew](https://brew.sh).

```shell
$ brew install ipatool
```

## Usage

To get started, run the following command.

```text
$ ipatool --help
A cli tool for interacting with Apple's ipa files

Usage:
  ipatool [command]

Available Commands:
  auth                 Authenticate with the App Store
  completion           Generate the autocompletion script for the specified shell
  download             Download iOS, iPadOS, tvOS, watchOS, visionOS, and macOS app packages from the App Store
  fairplay-doctor      Diagnose FairPlay build, enrollment, SINF, and model compatibility
  fairplay-decrypt     Decrypt a personalized IPA using the portable FairPlay pipeline
  fairplay-enroll      Collect and recover private native FairPlay enrollment
  get-version-metadata Retrieves the metadata for a specific version of an app
  help                 Help about any command
  list-purchases       List apps owned by the authenticated App Store account
  list-versions        List the available versions of an App Store app
  mcp                  Serve App Store tools over MCP using stdio
  purchase             Obtain a license for the app from the App Store
  search               Search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps available on the App Store

Flags:
      --format format                sets output format for command; can be 'text', 'json' (default text)
  -h, --help                         help for ipatool
      --keychain-passphrase string   passphrase for unlocking keychain
      --non-interactive              run in non-interactive session
      --verbose                      enables verbose logs
  -v, --version                      version for ipatool

Use "ipatool [command] --help" for more information about a command.
```

**Note:** the tool runs in interactive mode by default. Use the `--non-interactive` flag
if running in an automated environment.

### FairPlay decryption

> **Experimental:** Current-SINF decryption requires a private enrollment
> model generated for the matching account profile and SINF. No recovered
> enrollment keys are embedded in this repository or binary.

#### Current support

Only a **modern App Store enrollment from a newly created Apple Account** is
currently supported. Older, migrated, or legacy Store profiles are not
supported, even when their IPA uses the modern SINF layout. A new account is a
requirement, not a guarantee: the recovered model must still match the SINF
selector in the downloaded IPA.

| Host/FairPlay profile | Recovery status | End-to-end IPA status |
| --- | --- | --- |
| macOS 27.0.1 `26A434` with arm64e fairplayd SHA-256 `1e58d37e…e4ea1784` | Supported by the `macos26a428` binary profile | Proven with a modern account and matching selector |
| arm64e fairplayd SHA-256 `f68e4407…4964439d` (`26B118` profile) | Supported through the checked `macos26a428` offline compatibility evaluator | Proven with an external fresh-account control: 39 images and 10,080 pages |
| Any other fairplayd arm64e hash | Unsupported | A new evaluator and differential validation are required |

The fairplayd arm64e slice hash is authoritative. The macOS host build and the
internal FairPlay binary profile do not always have the same build label: the
validated macOS `26A434` installation contains the checked `26A428` fairplayd
slice. `fairplay-doctor` computes the exact slice hash and rejects a different
binary instead of guessing from the marketing version.

The experimental `fairplay-decrypt` command currently runs only on macOS and
Linux because it enforces Unix private-file permissions. The standalone Go
recovery helper can be cross-compiled for Windows, but the final ipatool
decryption command intentionally rejects Windows for now.

#### Quick usage with an existing model

Decrypting an existing personalized IPA is offline once the matching model is
available; it does not require an App Store login or network connection:

```shell
chmod 600 fairplay-enrollment.bin

ipatool fairplay-decrypt \
  --input App.ipa \
  --model fairplay-enrollment.bin \
  --output App.decrypted.ipa \
  --report App.decrypted.json
```

To download another personalized IPA, first authenticate the same Apple
Account whose enrollment produced the model:

```shell
ipatool auth login
```

Then purchase when necessary, download, and decrypt in one command:

```shell
ipatool download \
  --app-id APP_ID \
  --purchase \
  --output App.ipa \
  --fairplay-decrypt \
  --fairplay-model fairplay-enrollment.bin \
  --fairplay-output App.decrypted.ipa \
  --fairplay-report App.decrypted.json
```

For scripts, request machine-readable command output while keeping the private
decryption report in its own file:

```shell
ipatool --format json fairplay-decrypt \
  --input App.ipa \
  --model fairplay-enrollment.bin \
  --report App.decrypted.json
```

The model may be either one `.bin` file or a private directory containing up
to 256 selector-bound `.bin` models. Directory mode is useful for several
accounts because ipatool reads the IPA selector and chooses the matching model:

```shell
mkdir -m 700 fairplay-models
install -m 600 Account-A.bin fairplay-models/
install -m 600 Account-B.bin fairplay-models/

ipatool fairplay-decrypt \
  --input App.ipa \
  --model fairplay-models
```

Model directories must be mode `0700` or stricter, and every model must be
mode `0600` or stricter. Symlinks are rejected. Files without a `.bin`
extension are ignored.

Unless explicit paths are supplied, `App.ipa` produces
`App.decrypted.ipa` and `App.decrypted.json` beside the input. Existing output
or report files are never replaced unless `--force` is passed (or
`--fairplay-force` on `download`). A successful run still leaves the original
encrypted IPA unchanged.

Common failures are intentional fail-closed checks:

- `requires a private enrollment model`: pass `--model FILE` or
  `--model DIRECTORY`;
- `unsupported FairPlay profile`: the account/SINF selector does not match the
  selected model;
- a fairplayd build/hash mismatch: use the exact supported recovery profile;
- a permission error: remove group/other access with `chmod 600 MODEL` and
  `chmod 700 MODEL_DIRECTORY`;
- an existing-output error: choose another path or explicitly pass `--force`.

#### What “generate a matching checkpoint once” means

The checked-in Go files contain control flow and fault locations, but no
account data. Recovery also needs a private snapshot taken while the matching
fairplayd build is processing a SINF under the account's real App Store
enrollment. That snapshot supplies the live registers, generated tables, and
memory pages used by the white-box. It is specific to the combination of:

- exact fairplayd binary;
- local App Store enrollment state;
- Apple Account profile and SINF selector.

In practice, use a fresh Apple Account on the supported Mac, accept the App
Store terms, install a free app through the native App Store, and open it once.
An ipatool-only purchase or download does not create the required native Mac
enrollment. The bounded trace pipeline can then capture the white-box entry,
generate the private oracle model, run `tools/fairplay-recovery`, and package
the result as `fairplay-enrollment.bin`.

The checked profiles now construct their checkpoints offline through
`fairplay-enroll recover`; it does not attach to the live fairplayd process.
Recovery still cannot reconstruct missing enrollment from only an IPA, SINF,
SIDB, MAC address, or Apple Account password—the complete capture bundle is
required.

The native 26B118 `FPSENR3` consumer is not the consumer used by downloaded
Windows-profile SINF files. For a 26B118 capture, recovery therefore uses the
checked 26A428 CBC consumer as an offline compatibility evaluator. Supply its
exact arm64e fairplayd image (SHA-256 `1e58d37e…e4ea1784`); the Apple binary is
not bundled with ipatool:

```shell
ipatool fairplay-enroll recover \
  --capture /private/path/App.capture \
  --compat-fairplayd /private/path/fairplayd-26A428.arm64e \
  --output /private/path/App.recovery
```

The evaluator is never installed or executed natively. Every intermediate
checkpoint, recovered SINF plaintext, decrypted Mach-O, and mutation boundary
must validate before the candidate model is promoted to
`fairplay-enrollment.bin`.

The resulting `fairplay-enrollment.bin` is normally reusable for IPAs
personalized to the same account enrollment and selector. Generate a new one
when the account is re-enrolled, the SINF selector changes, or recovery must be
performed from a different fairplayd build. Never share the checkpoint or
model: both contain private account-derived key material.

#### Enrollment, recovery, and decryption workflow

1. On the supported Mac, confirm the exact build:

   ```shell
   sw_vers -productVersion
   sw_vers -buildVersion
   ```

   Continue only with a build listed as supported above. A close build number
   is not compatible.

2. Create a new Apple Account. Sign in with it in the native Mac App Store and
   complete all first-use prompts and Store terms. Do not reuse an older or
   migrated account for the currently supported path.

3. In the native App Store, obtain and install a free app. Launch that installed
   app once and wait for it to finish opening. This causes macOS to create the
   local FairPlay enrollment/`SC Info` state and gives the app a SINF tied to
   that enrollment. Merely purchasing or downloading the IPA with ipatool does
   not perform this step.

4. Keep the account signed in and do not delete `SC Info`, reinstall macOS, or
   reset the App Store state. Obtain an encrypted IPA personalized to the same
   Apple Account. Then collect the installed app, exact fairplayd slice,
   hardware identity, SC Info/ADI state, SINF/SUPFs, and IPA into one private
   bundle. Reading `/private/var/db/fpsd` normally requires `sudo`; the command
   restores ownership to the invoking user when run through sudo:

   ```shell
   sudo ipatool fairplay-enroll collect \
     --app /Applications/App.app \
     --ipa /private/path/App.ipa \
     --output /private/path/App.capture
   ```

5. Inspect the bundle before recovery. The report contains hashes and geometry,
   not passwords or plaintext keys:

   ```shell
   ipatool fairplay-doctor \
     --capture /private/path/App.capture \
     --report /private/path/App.doctor.json
   ```

6. From the ipatool source tree, install `uv` and the Go toolchain, then run the
   offline checkpoint constructor and recovery pipeline:

   ```shell
   ipatool fairplay-enroll recover \
     --capture /private/path/App.capture \
     --output /private/path/App.recovery
   ```

   Add `--compat-fairplayd /private/path/fairplayd-26A428.arm64e` when
   `fairplay-doctor` reports that a 26B118 capture requires the compatibility
   evaluator.

   This executes the build-specific static trace, derives the internal
   checkpoints, validates the generated Go oracle, performs the Go AES
   recovery, writes `fairplay-enrollment.bin`, decrypts the captured IPA, and
   verifies every encrypted Mach-O and available CodeDirectory page hash. It
   can take several minutes because checkpoint construction is intentionally
   offline and conservative. Do not accept a model from a failed or incomplete
   validation run.

7. Store the recovered model privately and reuse it for another IPA from the
   same enrollment and selector:

   ```shell
   chmod 600 /private/path/App.recovery/fairplay-enrollment.bin

   ipatool fairplay-decrypt \
     --input AnotherApp.ipa \
     --model /private/path/App.recovery/fairplay-enrollment.bin
   ```

   Or decrypt immediately after a same-account download:

   ```shell
   ipatool download \
     --app-id APP_ID \
     --purchase \
     --fairplay-decrypt \
     --fairplay-model /private/path/App.recovery/fairplay-enrollment.bin
   ```

8. Check the private JSON report. Success requires every previously encrypted
   image to have `cryptid_after: 0`, all expected pages to be processed, and
   every listed CodeDirectory to have `matched_slots == slot_count`. The output
   is an analysis IPA and still needs recursive code signing before it can be
   installed.

`fairplay-decrypt` decrypts a personalized IPA using an explicit private model.
After local model recovery, no device state, Wine, Unicorn, or runtime hardware
call is needed:

```shell
ipatool fairplay-decrypt \
  --input App.ipa \
  --model fairplay-enrollment.bin
```

The same experimental option is available as `--fairplay-model` when
decrypting directly after `ipatool download`. Model files contain private key
material and must be readable only by their owner; ipatool rejects group- or
world-readable files. Never commit or publish a model. The companion tool at
`tools/fairplay-recovery` recovers the AES model for an exact supported
fairplayd build. Private checkpoint material stays outside this repository.

Pass `--fairplay-decrypt` to `ipatool download` to decrypt immediately after
download and SINF replication. The decoder validates the complete decrypted
`key `/`iviv`/`tmpr`/`righ`/`name` atom geometry and fails closed when the SINF
does not match the selected model. Inputs are never overwritten; outputs and
private reports default beside the source IPA. A profile mismatch reports the
selected profile, SINF selector, SINF SHA-256, and private-payload size/hash,
then fails closed without creating an output IPA. These diagnostics contain no
plaintext key. The decrypted analysis IPA must be recursively re-signed before
installation.

The build-specific recovery implementation is included under
`tools/fairplay-recovery`. It is pure Go and performs the supported partial
AES-128 white-box attack in-process; it does not require Swift, Metal, or a
DarkPhoenix executable. It still needs a private oracle model generated from a
matching exact-build checkpoint. That model contains enrollment state and is
never embedded in ipatool.

The newer 26A428 research components for the state-slot transform, frame
builder, and SIDB block consumer now use sanitized embedded build models. The
SIDB component accepts its private 16-byte enrollment frame only at runtime;
the embedded model contains no retained account frame or recovered key. This
does not yet make `fairplay-enroll recover` fully Go: constructing the upstream
192/224-byte source field from raw `SC Info.sidb` and hardware identity still
uses the checked offline Python/Unicorn continuation. The final
`fairplay-enrollment.bin` remains private in every workflow.

### FairPlay enrollment diagnostics

This diagnostic branch can preserve the transaction-bound FairPlay inputs from
one successful `ent/download` request:

```shell
ipatool download \
  --app-id 333903271 \
  --external-version-id 893310510 \
  --output X-12.36.ipa \
  --fairplay-capture-dir X-12.36-fairplay-capture
```

The capture directory must not already exist. It is created with private
permissions and contains `kbsync.bin`, `keybag.bin`, the returned SINF, and a
`receipt.json` containing selectors, byte lengths, and SHA-256 hashes. The
KBSync and keybag are taken from the same Store transaction. Passwords, 2FA
codes, cookies, and Store authentication tokens are not written.

The captured blobs are personalized material. Share the directory privately;
do not attach it to a public issue.

`--fairplay-capture-dir` is a Store transaction diagnostic. It does not create
the native fairplayd checkpoint or `fairplay-enrollment.bin`, and it cannot
replace the enrollment/recovery workflow above.

### MCP tools

Run `ipatool auth login` in a terminal, then configure your MCP client to launch the stdio server:

```json
{
  "mcpServers": {
    "ipatool": {
      "command": "ipatool",
      "args": ["mcp"]
    }
  }
}
```

## Compiling

The tool can be compiled using the Go toolchain.

```shell
$ go build -o ipatool
```

Unit tests can be executed with the following commands.

```shell
$ go generate ./...
$ go test -v ./...
```

## License

ipatool is released under the [MIT license](https://github.com/majd/ipatool/blob/main/LICENSE).
