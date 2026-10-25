package fairplay

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalSIDBClassifiesKnownGeometry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SC Info.sidb")
	data := make([]byte, 630)
	binary.BigEndian.PutUint32(data[:4], 0x0007000b)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sidb, err := canonicalSIDB(CanonicalEnrollmentFile{
		CapturePath: "state/fpsd-sc-info/SC Info.sidb", Bytes: int64(len(data)), localPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sidb.Version != 0x0007000b || sidb.Format != "macos-sidb-v7000b" || sidb.ExpectedSourceBytes != 192 {
		t.Fatalf("unexpected SIDB classification: %#v", sidb)
	}
}

func TestCanonicalInputFingerprintExcludesLocalPaths(t *testing.T) {
	base := CanonicalEnrollmentInput{
		Schema: CanonicalEnrollmentInputSchema, Contract: "macos-current-sinf-v1",
		SelectorID: "synthetic:00000002",
		Executable: CanonicalEnrollmentFile{Role: "installed-executable", CapturePath: "app/executable", SHA256: "01", localPath: "/private/one"},
	}
	left, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Executable.localPath = "/different/private/path"
	right, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatal("canonical fingerprint depends on a private local path")
	}
	base.Executable.SHA256 = "02"
	changed, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if changed == left {
		t.Fatal("canonical fingerprint ignored exported file identity")
	}
}
