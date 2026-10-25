package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/majd/ipatool/v2/internal/fairplay"
	"github.com/spf13/cobra"
)

func fairplayEnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fairplay-enroll",
		Short: "Collect and recover private native FairPlay enrollment",
	}
	cmd.AddCommand(fairplayEnrollCollectCmd())
	cmd.AddCommand(fairplayEnrollRecoverCmd())
	return cmd
}

func fairplayEnrollCollectCmd() *cobra.Command {
	var options fairplay.EnrollmentCollectOptions
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect one private native App Store enrollment bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, err := fairplay.CollectEnrollment(options)
			if err != nil {
				return err
			}
			dependencies.Logger.Log().
				Str("capture", options.OutputPath).
				Str("build", manifest.FairPlay.Build).
				Str("support", manifest.FairPlay.Status).
				Str("selector", manifest.App.SelectorID).
				Int("files", len(manifest.Files)).
				Bool("success", true).
				Send()
			return nil
		},
	}
	cmd.Flags().StringVar(&options.AppPath, "app", "", "Native App Store-installed .app path (required)")
	cmd.Flags().StringVar(&options.IPAPath, "ipa", "", "Matching personalized encrypted IPA")
	cmd.Flags().StringVar(&options.OutputPath, "output", "", "New private capture directory (required)")
	cmd.Flags().StringVar(&options.FairPlaydPath, "fairplayd", "", "fairplayd Mach-O (defaults to the system CoreFP framework)")
	cmd.Flags().StringVar(&options.SystemStatePath, "system-state", "", "System SC Info directory")
	cmd.Flags().StringVar(&options.SharedStatePath, "shared-state", "", "Shared SC Info directory")
	cmd.Flags().StringVar(&options.ADIPath, "adi-state", "", "Native ADI state directory")
	cmd.Flags().StringVar(&options.MACAddressPath, "iomac-file", "", "Private six-byte IOMACAddress file (otherwise read built-in IORegistry interface)")
	cmd.Flags().StringVar(&options.HardwareInterface, "interface", "en0", "Built-in IORegistry network interface")
	cmd.Flags().StringVar(&options.ProductVersion, "product-version", "", "Archived source macOS product version (defaults to the running system)")
	cmd.Flags().StringVar(&options.BuildVersion, "build-version", "", "Archived source macOS build version (defaults to the running system)")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

type fairplayRecoverOptions struct {
	Capture          string
	Output           string
	Script           string
	CompatFairPlayd  string
	SkipDifferential bool
}

func resolveRecoveryScript(explicit string) (string, error) {
	candidates := []string{explicit, os.Getenv("IPATOOL_FAIRPLAY_RECOVERY_SCRIPT")}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "tools", "fairplay-recovery", "python", "recover_capture.py"))
	}
	candidates = append(candidates, filepath.Join("tools", "fairplay-recovery", "python", "recover_capture.py"))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", errors.New("FairPlay recovery script was not found; run from the ipatool source tree or pass --script")
}

func runLegacyFairplayEnrollmentRecovery(ctx context.Context, options fairplayRecoverOptions) error {
	if options.Capture == "" || options.Output == "" {
		return errors.New("recovery requires capture and output paths")
	}
	if _, err := fairplay.LoadEnrollmentCapture(options.Capture, true); err != nil {
		return fmt.Errorf("validate enrollment capture: %w", err)
	}
	script, err := resolveRecoveryScript(options.Script)
	if err != nil {
		return err
	}
	uv, err := exec.LookPath("uv")
	if err != nil {
		return errors.New("FairPlay recovery requires uv (https://docs.astral.sh/uv/)")
	}
	arguments := []string{
		"run", "--with", "capstone", "--with", "unicorn", "--with", "pycryptodome",
		"python", script, "--capture", options.Capture, "--output-dir", options.Output,
	}
	if options.CompatFairPlayd != "" {
		arguments = append(arguments, "--compat-fairplayd", options.CompatFairPlayd)
	}
	if options.SkipDifferential {
		arguments = append(arguments, "--skip-differential")
	}
	command := exec.CommandContext(ctx, uv, arguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	if err := command.Run(); err != nil {
		return fmt.Errorf("recover FairPlay enrollment: %w", err)
	}
	return nil
}

func resolveRecoverySourceRoot() (string, error) {
	candidates := []string{"."}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(executable))
	}
	for _, candidate := range candidates {
		target := filepath.Join(candidate, "tools", "fairplay-recovery")
		if info, err := os.Stat(target); err == nil && info.IsDir() {
			absolute, absoluteErr := filepath.Abs(candidate)
			if absoluteErr != nil {
				return "", absoluteErr
			}
			return absolute, nil
		}
	}
	return "", errors.New("Go FairPlay recovery source was not found; run from the ipatool source tree")
}

func privateRecoveryFile(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(value); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func runGoFairplayEnrollmentRecovery(ctx context.Context, options fairplayRecoverOptions) error {
	if options.Capture == "" || options.Output == "" {
		return errors.New("recovery requires capture and output paths")
	}
	manifest, err := fairplay.LoadEnrollmentCapture(options.Capture, true)
	if err != nil {
		return fmt.Errorf("validate enrollment capture: %w", err)
	}
	if manifest.IPA == nil {
		return errors.New("enrollment capture has no matching IPA")
	}
	canonicalInput, err := fairplay.NormalizeEnrollmentCapture(options.Capture, manifest)
	if err != nil {
		return fmt.Errorf("normalize enrollment capture: %w", err)
	}
	if !canonicalInput.RecoveryReady {
		return errors.New("canonical enrollment input is not recovery-ready")
	}
	if err := os.Mkdir(options.Output, 0o700); err != nil {
		return err
	}
	canonicalDocument, err := fairplay.MarshalCanonicalEnrollmentInput(canonicalInput)
	if err != nil {
		return err
	}
	canonicalDocument = append(canonicalDocument, '\n')
	if err := privateRecoveryFile(filepath.Join(options.Output, "canonical-input.json"), canonicalDocument); err != nil {
		return err
	}
	root, err := resolveRecoverySourceRoot()
	if err != nil {
		return err
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		return errors.New("Go FairPlay recovery requires the Go toolchain")
	}
	temporary, err := os.CreateTemp(options.Output, ".fairplay-source-*")
	if err != nil {
		return err
	}
	helper := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(helper); err != nil {
		return err
	}
	defer os.Remove(helper)
	build := exec.CommandContext(ctx, goTool, "build", "-tags", "fairplayrawsource", "-o", helper, "./tools/fairplay-recovery")
	build.Dir, build.Stdout, build.Stderr = root, os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("build Go FairPlay recovery: %w", err)
	}
	if err := os.Chmod(helper, 0o700); err != nil {
		return err
	}

	executableName := manifest.App.Executable
	executablePath := manifest.App.ExecutablePath
	if executablePath == "" {
		executablePath = filepath.Join("/Applications", executableName+".app", executableName)
	}
	capturePath := func(relative string) string {
		return filepath.Join(options.Capture, filepath.FromSlash(relative))
	}
	arguments := []string{
		"--raw-source-kernel", "enrollment-sinf",
		"--raw-source-executable-path", executablePath,
		"--raw-source-file", "/" + executableName + "=" + canonicalInput.PrivateExecutablePath(),
		"--raw-source-mac", canonicalInput.PrivateHardwarePath(),
	}
	candidate := filepath.Join(options.Output, "fairplay-enrollment.candidate.bin")
	selectedInputProfile := ""
	var recoveryErrors []error
	for _, profile := range []struct {
		name     string
		expanded bool
	}{{"minimal-current-sinf", false}, {"expanded-capture", true}} {
		mappings, stateFiles := canonicalInput.RuntimeFileMappings(profile.expanded)
		if stateFiles == 0 {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s input profile has no FairPlay state files", profile.name))
			continue
		}
		attemptArguments := append([]string(nil), arguments...)
		for _, mapping := range mappings {
			attemptArguments = append(attemptArguments, "--raw-source-file", mapping)
		}
		attemptArguments = append(attemptArguments, "--raw-source-enrollment-output", candidate)
		recover := exec.CommandContext(ctx, helper, attemptArguments...)
		recover.Stdout, recover.Stderr = os.Stdout, os.Stderr
		if runErr := recover.Run(); runErr == nil {
			selectedInputProfile = profile.name
			break
		} else {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", profile.name, runErr))
			if removeErr := os.Remove(candidate); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return removeErr
			}
		}
	}
	if selectedInputProfile == "" {
		return fmt.Errorf("derive Go FairPlay enrollment: %w", errors.Join(recoveryErrors...))
	}

	ipa := capturePath(manifest.IPA.Path)
	decrypted := filepath.Join(options.Output, "App.decrypted.ipa")
	decryptionReport := filepath.Join(options.Output, "App.decrypted.json")
	result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
		InputPath: ipa, OutputPath: decrypted, ReportPath: decryptionReport, ModelPath: candidate,
	})
	if err != nil {
		return fmt.Errorf("validate recovered FairPlay enrollment: %w", err)
	}
	enrollment := filepath.Join(options.Output, "fairplay-enrollment.bin")
	if err := os.Rename(candidate, enrollment); err != nil {
		return err
	}
	summary := map[string]any{
		"schema": "ipatool-fairplay-enrollment-recovery-v2", "success": true,
		"selector": manifest.App.SelectorID, "fairplayd_sha256": manifest.FairPlayd.SHA256,
		"fairplayd_status": manifest.FairPlay.Status, "capture_profile_independently_verified": manifest.FairPlay.Decrypt,
		"fairplayd_independently_verified": manifest.FairPlay.Decrypt, "validation_basis": manifest.FairPlay.ValidationBasis,
		"canonical_contract": canonicalInput.Contract, "canonical_input_sha256": canonicalInput.FingerprintSHA256,
		"enrollment_model": enrollment, "decrypted_ipa": decrypted,
		"decrypted_ipa_sha256": result.OutputSHA256, "encrypted_images": result.EncryptedImages,
		"decrypted_pages": result.DecryptedPages, "all_cryptids_zero": true,
		"all_code_directory_slots_match": true, "runtime": "pure-go-portable-current-sinf",
		"input_profile": selectedInputProfile, "promotion_gate": "complete-sinf-and-ipa-validation",
	}
	document, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	document = append(document, '\n')
	report := filepath.Join(options.Output, "recovery-report.json")
	if err := privateRecoveryFile(report, document); err != nil {
		return err
	}
	dependencies.Logger.Log().Str("model", enrollment).Str("decrypted", decrypted).Str("report", report).Bool("success", true).Send()
	return nil
}

func runFairplayEnrollmentRecovery(ctx context.Context, options fairplayRecoverOptions) error {
	if options.Script != "" || os.Getenv("IPATOOL_FAIRPLAY_RECOVERY_SCRIPT") != "" {
		return runLegacyFairplayEnrollmentRecovery(ctx, options)
	}
	return runGoFairplayEnrollmentRecovery(ctx, options)
}

func fairplayEnrollRecoverCmd() *cobra.Command {
	var options fairplayRecoverOptions
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Build and validate fairplay-enrollment.bin from a private capture",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFairplayEnrollmentRecovery(cmd.Context(), options)
		},
	}
	cmd.Flags().StringVar(&options.Capture, "capture", "", "Private capture directory from fairplay-enroll collect (required)")
	cmd.Flags().StringVar(&options.Output, "output", "", "New private recovery output directory (required)")
	cmd.Flags().StringVar(&options.Script, "script", "", "Use the explicit legacy Python recover_capture.py instead of pure Go")
	cmd.Flags().StringVar(&options.CompatFairPlayd, "compat-fairplayd", "", "Legacy Python path: exact checked 26A428 arm64e fairplayd")
	cmd.Flags().BoolVar(&options.SkipDifferential, "skip-differential", false, "Legacy Python path: skip the Unicorn differential")
	_ = cmd.MarkFlagRequired("capture")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}
