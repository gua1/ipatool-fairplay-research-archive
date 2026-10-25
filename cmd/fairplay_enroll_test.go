package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
