package cmd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/majd/ipatool/v2/internal/fairplay"
)

func TestFairPlayCommandsAreRegistered(t *testing.T) {
	root := rootCmd()
	for _, name := range []string{"fairplay-decrypt", "fairplay-enroll", "fairplay-doctor"} {
		command, _, err := root.Find([]string{name})
		if err != nil || command == root || command.Name() != name {
			t.Fatalf("command %s is not registered: %v", name, err)
		}
	}
	enroll, _, err := root.Find([]string{"fairplay-enroll"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"collect", "recover"} {
		command, _, err := enroll.Find([]string{name})
		if err != nil || command == enroll || command.Name() != name {
			t.Fatalf("fairplay-enroll %s is not registered: %v", name, err)
		}
	}
}

func TestResolveRecoveryScriptExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recover_capture.py")
	if err := os.WriteFile(path, []byte("pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveRecoveryScript(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("script = %q, want %q", got, path)
	}
}

func TestRecoveryRequiresInputs(t *testing.T) {
	err := runFairplayEnrollmentRecovery(context.Background(), fairplayRecoverOptions{})
	if err == nil {
		t.Fatal("empty recovery input was accepted")
	}
}

func TestPortableCaptureFileMappingsIncludeAllStateAndLicenseVariants(t *testing.T) {
	capture := filepath.Join("private", "capture")
	manifest := fairplay.EnrollmentCaptureManifest{App: fairplay.EnrollmentCaptureApp{Executable: "App"}, Files: []fairplay.EnrollmentCaptureFile{
		{Path: "app/SC_Info/App.sinf"},
		{Path: "app/SC_Info/App.v6.supf"},
		{Path: "state/fpsd-sc-info/SC Info.sidb"},
		{Path: "state/shared-sc-info/SC Info.sidd"},
		{Path: "state/adi/device.pb"},
		{Path: "ipa/App.ipa"},
	}}
	minimal, stateFiles := portableCaptureFileMappings(capture, manifest, false)
	wantMinimal := []string{
		"/var/db/fpsd/SC Info/SC Info.sidb=" + filepath.Join(capture, "state", "fpsd-sc-info", "SC Info.sidb"),
		"App.sinf=" + filepath.Join(capture, "app", "SC_Info", "App.sinf"),
	}
	if stateFiles != 1 || !slices.Equal(minimal, wantMinimal) {
		t.Fatalf("minimal mappings = %#v, state files = %d", minimal, stateFiles)
	}
	expanded, stateFiles := portableCaptureFileMappings(capture, manifest, true)
	wantExpanded := []string{
		"/Users/Shared/SC Info/SC Info.sidd=" + filepath.Join(capture, "state", "shared-sc-info", "SC Info.sidd"),
		"/var/db/fpsd/SC Info/SC Info.sidb=" + filepath.Join(capture, "state", "fpsd-sc-info", "SC Info.sidb"),
		"/var/db/fpsd/adi/device.pb=" + filepath.Join(capture, "state", "adi", "device.pb"),
		"App.sinf=" + filepath.Join(capture, "app", "SC_Info", "App.sinf"),
		"App.v6.supf=" + filepath.Join(capture, "app", "SC_Info", "App.v6.supf"),
	}
	if stateFiles != 3 || !slices.Equal(expanded, wantExpanded) {
		t.Fatalf("expanded mappings = %#v, state files = %d", expanded, stateFiles)
	}
}
