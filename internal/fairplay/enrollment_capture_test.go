package fairplay

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func TestParseIORegistryHardwareMAC(t *testing.T) {
	want := []byte{0xc8, 0x89, 0xf3, 0xdd, 0x0d, 0x56}
	document := map[string]any{
		"IORegistryEntryChildren": []any{
			map[string]any{
				"IOMACAddress": want,
				"IORegistryEntryChildren": []any{
					map[string]any{"BSD Name": "en0", "IOBuiltin": true},
				},
			},
		},
	}
	encoded, err := plist.Marshal(document, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseIORegistryHardwareMAC(encoded, "en0")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("IOMACAddress = %x, want %x", got, want)
	}
	if _, err := parseIORegistryHardwareMAC(encoded, "en9"); err == nil {
		t.Fatal("missing interface was accepted")
	}
}

func currentLayoutSINF(selector SINFSelector) []byte {
	user := make([]byte, 4)
	key := make([]byte, 4)
	user[0], user[1], user[2], user[3] = byte(selector.User>>24), byte(selector.User>>16), byte(selector.User>>8), byte(selector.User)
	key[0], key[1], key[2], key[3] = byte(selector.Key>>24), byte(selector.Key>>16), byte(selector.Key>>8), byte(selector.Key)
	fields := append(testAtom("user", user), testAtom("key ", key)...)
	fields = append(fields, testAtom("priv", make([]byte, 448))...)
	return testAtom("sinf", testAtom("schi", fields))
}

func TestInspectSINFAndModel(t *testing.T) {
	selector := SINFSelector{User: 0x12345678, Key: 2}
	diagnostic, err := InspectSINF(currentLayoutSINF(selector))
	if err != nil {
		t.Fatal(err)
	}
	if diagnostic.Selector != selector || !diagnostic.CurrentLayout || diagnostic.LegacyMarkers || diagnostic.PrivateBytes != 448 {
		t.Fatalf("unexpected SINF diagnostic: %#v", diagnostic)
	}
	modelPath := filepath.Join(t.TempDir(), "model.bin")
	if err := os.WriteFile(modelPath, selectorBoundModelPack(t, selector), 0o600); err != nil {
		t.Fatal(err)
	}
	model, err := InspectEnrollmentModel(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	if model.Version != 2 || model.Selector == nil || *model.Selector != selector {
		t.Fatalf("unexpected model diagnostic: %#v", model)
	}
}

func TestFairPlayBuildRecoverySupport(t *testing.T) {
	stable, ok := LookupFairPlayBuild(FairPlayBuild26A428Hash)
	if !ok || !stable.Recovery || !stable.Decrypt {
		t.Fatalf("26A428 support = %#v, %v", stable, ok)
	}
	research, ok := LookupFairPlayBuild(FairPlayBuild26B118Hash)
	if !ok || !research.Recovery || research.Decrypt || research.Status != "recovery-supported" {
		t.Fatalf("26B118 support = %#v, %v", research, ok)
	}
}

func TestLoadEnrollmentCaptureIntegrity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "private.bin")
	private := []byte("private fixture")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(private)
	manifest := EnrollmentCaptureManifest{
		Schema: EnrollmentCaptureSchema,
		Files: []EnrollmentCaptureFile{{
			Path: "private.bin", Bytes: int64(len(private)), SHA256: hex.EncodeToString(digest[:]), Mode: "0600",
		}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnrollmentCapture(directory, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnrollmentCapture(directory, true); err == nil {
		t.Fatal("modified capture was accepted")
	}
	manifest.Files[0].Path = "../outside.bin"
	encoded, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnrollmentCapture(directory, true); err == nil {
		t.Fatal("capture path traversal was accepted")
	}
}

func TestFairPlayDoctorMatchesSelector(t *testing.T) {
	directory := t.TempDir()
	selector := SINFSelector{User: 0x12345678, Key: 2}
	ipaPath := filepath.Join(directory, "App.ipa")
	output, err := os.Create(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(output)
	member, err := archive.Create("Payload/App.app/SC_Info/App.sinf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(currentLayoutSINF(selector)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	modelPath := filepath.Join(directory, "model.bin")
	if err := os.WriteFile(modelPath, selectorBoundModelPack(t, selector), 0o600); err != nil {
		t.Fatal(err)
	}
	report := DoctorFairPlay("", ipaPath, modelPath)
	if !report.Ready || !report.Checks["selector_match"] || report.CompatibleModel != modelPath {
		t.Fatalf("doctor did not accept matching inputs: %#v", report)
	}
}
