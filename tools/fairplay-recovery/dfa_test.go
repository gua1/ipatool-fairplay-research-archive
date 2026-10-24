package main

import (
	"crypto/aes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func mustBlock(t *testing.T, value string) (result [16]byte) {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("invalid AES fixture %q", value)
	}
	copy(result[:], decoded)
	return
}

func TestDPAES128(t *testing.T) {
	key := mustBlock(t, "000102030405060708090a0b0c0d0e0f")
	plaintext := mustBlock(t, "00112233445566778899aabbccddeeff")
	want := mustBlock(t, "69c4e0d86a7b0430d8cdb78070b4c55a")
	expanded := dpExpandKey(key)
	if got := dpAESEncrypt(plaintext, expanded); got != want {
		t.Fatalf("encrypt = %x, want %x", got, want)
	}
	if got := dpAESDecrypt(want, expanded); got != plaintext {
		t.Fatalf("decrypt = %x, want %x", got, plaintext)
	}
	standard, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	var standardOutput [16]byte
	standard.Encrypt(standardOutput[:], plaintext[:])
	if standardOutput != want {
		t.Fatal("standard library fixture mismatch")
	}
	if reverted := dpRevertAES128RoundKey(dpRoundKey(expanded, 2), 2); reverted != key {
		t.Fatalf("reverted key = %x, want %x", reverted, key)
	}
}

func TestDPLinearAlgebra(t *testing.T) {
	if err := dpLinearSelfTest(); err != nil {
		t.Fatal(err)
	}
}

func TestWritePrivateJSONDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := writePrivateJSON(path, map[string]int{"value": 1}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private output mode = %04o", info.Mode().Perm())
	}
	if err := writePrivateJSON(path, map[string]int{"value": 2}); err == nil {
		t.Fatal("private recovery was overwritten")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "{\n  \"value\": 1\n}\n" {
		t.Fatalf("private output changed: %q", value)
	}
}
