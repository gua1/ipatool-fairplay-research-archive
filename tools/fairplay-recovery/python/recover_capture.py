#!/usr/bin/env python3
"""Build and validate one private 26A428 enrollment model from a capture."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import pickle
import plistlib
import shutil
import subprocess
import sys
from zipfile import ZipFile


SCHEMA = "ipatool-fairplay-native-enrollment-capture-v1"
BUILD_HASH = "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"
SCRIPT_DIR = Path(__file__).resolve().parent
RECOVERY_DIR = SCRIPT_DIR.parent
REPO = RECOVERY_DIR.parents[1]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def private_file(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb")


def run(command: list[str], log: Path, cwd: Path = REPO) -> None:
    with private_file(log) as stream:
        subprocess.run(command, cwd=cwd, check=True, stdout=stream, stderr=subprocess.STDOUT)


def progress(stage: str) -> None:
    print(f"fairplay_recovery_stage={stage}", flush=True)


def load_capture(path: Path) -> dict[str, object]:
    if path.stat().st_mode & 0o077:
        raise ValueError("capture directory must be mode 0700 or stricter")
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported capture schema")
    for item in manifest.get("files", []):
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"capture contains an unsafe path: {item['path']}")
        target = path / relative
        if not target.is_file() or target.stat().st_mode & 0o077:
            raise ValueError(f"capture file is missing or not private: {item['path']}")
        if target.stat().st_size != item["bytes"] or digest(target) != item["sha256"]:
            raise ValueError(f"capture file changed: {item['path']}")
    if manifest["fairplayd"]["sha256"] != BUILD_HASH:
        raise ValueError("capture is not the checked 26A428 fairplayd")
    if not manifest.get("ipa"):
        raise ValueError("capture has no matching IPA")
    return manifest


def capture_file(root: Path, relative_text: str) -> Path:
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"capture contains an unsafe path: {relative_text}")
    return root / relative


def ipa_members(ipa: Path, manifest: dict[str, object]) -> tuple[str, str, str]:
    app = manifest["app"]
    root = app.get("ipa_member_root")
    executable = app["executable"]
    if not root:
        with ZipFile(ipa) as archive:
            candidates = [
                name.removesuffix("/Info.plist")
                for name in archive.namelist()
                if name.startswith("Payload/") and name.count("/") == 2 and name.endswith(".app/Info.plist")
            ]
            if len(candidates) != 1:
                raise ValueError("IPA root app is ambiguous")
            root = candidates[0]
    supf = f"{root}/SC_Info/{executable}.v5.supf"
    legacy = f"{root}/SC_Info/{executable}.supf"
    executable_member = f"{root}/{executable}"
    with ZipFile(ipa) as archive:
        names = set(archive.namelist())
    for name in (supf, legacy, executable_member):
        if name not in names:
            raise ValueError(f"IPA lacks required member {name}")
    return supf, legacy, executable_member


def continue_checkpoint(
    source: Path,
    destination: Path | None,
    report: Path,
    *,
    start: int,
    stop: int,
    count: int,
    stop_hit: int = 1,
    trace_memory: bool = False,
    file_payloads: list[tuple[str, Path]] | None = None,
    mac_address_file: Path | None = None,
) -> None:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "continue_fairplay_checkpoint_unicorn.py"),
        str(source),
        "--start-address", hex(start),
        "--stop-address", hex(stop),
        "--stop-hit", str(stop_hit),
        "--count", str(count),
        "--emulate-eor3", "--eor3-known-26a428",
        "--missing-files-are-enoent",
        "--output", str(report),
    ]
    if trace_memory:
        command += ["--trace-memory-reads", "--trace-memory-writes"]
    for suffix, path in file_payloads or []:
        command += ["--file-payload", f"{suffix}={path}"]
    if mac_address_file is not None:
        command += ["--mac-address-file", str(mac_address_file)]
    if destination is not None:
        command += ["--checkpoint-output", str(destination)]
    run(command, report.with_suffix(report.suffix + ".log"))


def checkpoint_pc(path: Path) -> int:
    with gzip.open(path, "rb") as stream:
        return int(pickle.load(stream)["pc"], 16)


def validate_decryption(report: Path) -> dict[str, object]:
    document = json.loads(report.read_text())
    images = document.get("images", [])
    if not document.get("complete") or not images:
        raise ValueError("decryption did not complete every encrypted image")
    for image in images:
        if image.get("cryptid_after") != 0:
            raise ValueError(f"cryptid remained set: {image.get('member')}")
        for directory in image.get("code_directories", []):
            if directory.get("matched_slots") != directory.get("slot_count"):
                raise ValueError(f"CodeDirectory mismatch: {image.get('member')}")
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--skip-differential", action="store_true")
    args = parser.parse_args()
    capture = args.capture.resolve()
    output = args.output_dir.resolve()
    if output.exists():
        parser.error(f"output exists: {output}")
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    try:
        manifest = load_capture(capture)
        ipa = capture_file(capture, manifest["ipa"]["path"])
        fairplayd = capture_file(capture, manifest["fairplayd"]["path"])
        iomac = capture_file(capture, manifest["hardware_iomac"]["path"])
        installed_sinf = capture_file(capture, manifest["app"]["sinf_path"])
        target_sinf = capture_file(
            capture,
            manifest["app"].get("target_sinf_path")
            or manifest["app"]["sinf_path"],
        )
        state = capture / "state"
        supf_member, legacy_member, executable_member = ipa_members(ipa, manifest)

        checkpoints = output / "checkpoints"
        checkpoints.mkdir(mode=0o700)
        executable_name = manifest["app"]["executable"]
        installed_sc_info = capture / "app" / "SC_Info"
        account = checkpoints / "account-entry.checkpoint.pkl.gz"
        progress("checkpoint-account")
        run(
            [
            sys.executable, str(SCRIPT_DIR / "trace_ios_fairplay_setup.py"),
            "--daemon-profile", "macos-26A428",
            "--binary", str(fairplayd),
            "--startup-cache", str(RECOVERY_DIR / "profiles" / "macos26a428-startup.json.gz"),
            "--ipa", str(ipa),
            "--supf-member", supf_member,
            "--legacy-supf-member", legacy_member,
            "--supf-file", str(installed_sc_info / f"{executable_name}.v5.supf"),
            "--legacy-supf-file", str(installed_sc_info / f"{executable_name}.supf"),
            "--executable-member", executable_member,
            "--executable-path", f"/Applications/{executable_name}.app/{executable_name}",
            "--sinf", str(installed_sinf),
            "--fairplay-state-dir", str(state),
            "--mac-address-file", str(iomac),
            "--model-physical-host",
            "--model-coreke-operation-10",
            "--missing-files-enoent",
            "--no-watch-memory", "--no-watch-status",
            "--stop-address", "0x10057ae74",
            "--checkpoint-file", str(account),
            "--output", str(checkpoints / "account-entry.json"),
            ],
            checkpoints / "account-entry.log",
        )
        if checkpoint_pc(account) != 0x10057AE74:
            raise ValueError("offline trace did not reach the account-state checkpoint")

        file_payloads = [
            (f"/{executable_name}", capture / "app" / "executable"),
            (f"{executable_name}.sinf", target_sinf),
            (f"{executable_name}.v5.supf", installed_sc_info / f"{executable_name}.v5.supf"),
            (f"{executable_name}.supf", installed_sc_info / f"{executable_name}.supf"),
        ]
        system_state = capture / "state" / "fpsd-sc-info"
        for state_path in sorted(system_state.glob("SC Info.*")):
            if state_path.is_file():
                file_payloads.append((f"/var/db/fpsd/SC Info/{state_path.name}", state_path))
        source = checkpoints / "first-private-read.checkpoint.pkl.gz"
        progress("derive-source")
        continue_checkpoint(
            account, source, checkpoints / "first-private-read.json",
            start=0x10057AE74, stop=0x10015321C, stop_hit=1,
            count=500_000_000, file_payloads=file_payloads,
            mac_address_file=iomac,
        )
        if checkpoint_pc(source) != 0x10015321C:
            raise ValueError("offline continuation did not reach the private-read checkpoint")
        transformed = checkpoints / "first-transform-output.checkpoint.pkl.gz"
        progress("derive-transform")
        continue_checkpoint(source, transformed, checkpoints / "first-transform-output.json", start=0x10015321C, stop=0x100153310, stop_hit=432, count=50_000_000)
        oracle = checkpoints / "core-entry.checkpoint.pkl.gz"
        progress("derive-oracle")
        continue_checkpoint(source, oracle, checkpoints / "core-entry.json", start=0x10015321C, stop=0x100234CDC, count=500_000_000)

        memory_trace = output / "oracle-memory-trace.json"
        progress("trace-oracle")
        continue_checkpoint(oracle, None, memory_trace, start=0x100234CDC, stop=0x100234CDC, stop_hit=2, count=200_000, trace_memory=True)
        oracle_model = output / "go-oracle-model.bin.gz"
        progress("export-oracle")
        run(
            [sys.executable, str(SCRIPT_DIR / "export_macos26a428_go_oracle_model.py"), str(oracle), "--memory-trace", str(memory_trace), "--model-output", str(oracle_model)],
            output / "export-go-oracle.log",
        )
        go_oracle = output / "fairplay-recovery"
        progress("build-go-recovery")
        run(["go", "build", "-tags", "fairplay26a428", "-o", str(go_oracle), "./tools/fairplay-recovery"], output / "build-recovery.log")
        go_oracle.chmod(0o700)
        if not args.skip_differential:
            progress("validate-oracle")
            run(
                [sys.executable, str(SCRIPT_DIR / "validate_macos26a428_go_oracle.py"), str(oracle), "--go-oracle", str(go_oracle), "--model", str(oracle_model)],
                output / "validate-go-oracle.log",
            )
        recovered = output / "recovered-whitebox-model.json"
        progress("recover-aes")
        run([str(go_oracle), "--model", str(oracle_model), "--recover-output", str(recovered)], output / "recover.log")
        recovered.chmod(0o600)

        enrollment = output / "fairplay-enrollment.bin"
        audit = output / "fairplay-enrollment-audit.json"
        progress("build-enrollment")
        run(
            [
                sys.executable, str(SCRIPT_DIR / "build_macos26_current_sinf_model.py"),
                "--source-checkpoint", str(source),
                "--whitebox-output-checkpoint", str(transformed),
                "--darkphoenix-model", str(recovered),
                "--output-address", "0x710000014ee8",
                "--selector", manifest["app"]["selector_id"],
                "--binary-output", str(enrollment),
                "--audit-output", str(audit),
            ],
            output / "build-enrollment.log",
        )
        ipatool = output / "ipatool"
        progress("build-ipatool")
        run(["go", "build", "-o", str(ipatool), "."], output / "build-ipatool.log")
        ipatool.chmod(0o700)
        decrypted = output / "App.decrypted.ipa"
        decryption_report = output / "App.decrypted.json"
        progress("decrypt-and-verify")
        run(
            [
                str(ipatool), "--format", "json", "fairplay-decrypt",
                "--input", str(ipa), "--model", str(enrollment),
                "--output", str(decrypted), "--report", str(decryption_report),
            ],
            output / "decrypt.log",
        )
        document = validate_decryption(decryption_report)
        summary = {
            "schema": "ipatool-fairplay-enrollment-recovery-v1",
            "success": True,
            "capture_manifest_sha256": digest(capture / "manifest.json"),
            "selector": manifest["app"]["selector_id"],
            "fairplayd_sha256": manifest["fairplayd"]["sha256"],
            "enrollment_model": str(enrollment),
            "enrollment_model_sha256": digest(enrollment),
            "decrypted_ipa": str(decrypted),
            "decrypted_ipa_sha256": digest(decrypted),
            "encrypted_images": document["encrypted_image_count"],
            "decrypted_pages": document["decrypted_page_count"],
            "all_cryptids_zero": True,
            "all_code_directory_slots_match": True,
        }
        with private_file(output / "recovery-report.json") as stream:
            stream.write((json.dumps(summary, indent=2, sort_keys=True) + "\n").encode())
        print(
            "fairplay_enrollment_recovery=1 success=1 "
            f"model={enrollment} decrypted={decrypted} report={output / 'recovery-report.json'}"
        )
    except subprocess.CalledProcessError as error:
        print(f"fairplay_enrollment_recovery=1 success=0 command_exit={error.returncode} output={output}", file=sys.stderr)
        raise
    except Exception:
        print(f"fairplay_enrollment_recovery=1 success=0 output={output}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
