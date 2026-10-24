package cmd

import (
	"context"
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
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

type fairplayRecoverOptions struct {
	Capture          string
	Output           string
	Script           string
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

func runFairplayEnrollmentRecovery(ctx context.Context, options fairplayRecoverOptions) error {
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
	cmd.Flags().StringVar(&options.Script, "script", "", "Explicit recover_capture.py path")
	cmd.Flags().BoolVar(&options.SkipDifferential, "skip-differential", false, "Skip the Unicorn differential (unsafe except for development regression)")
	_ = cmd.MarkFlagRequired("capture")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}
