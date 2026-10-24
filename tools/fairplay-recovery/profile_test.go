package main

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPackagedStartupProfileIsSanitized(t *testing.T) {
	input, err := os.Open("profiles/macos26a428-startup.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	stream, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var value struct {
		Schema       string            `json:"schema"`
		BinarySHA256 string            `json:"binary_sha256"`
		Memory       []json.RawMessage `json:"memory"`
		OnceTokens   []string          `json:"once_tokens"`
	}
	if err := json.NewDecoder(stream).Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.Schema != "ipatool-fairplay-startup-cache-v1" || value.BinarySHA256 != "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784" {
		t.Fatalf("unexpected startup profile identity: %q %q", value.Schema, value.BinarySHA256)
	}
	if len(value.Memory) != 774144 || len(value.OnceTokens) != 2 {
		t.Fatalf("unexpected startup geometry: memory=%d once=%d", len(value.Memory), len(value.OnceTokens))
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"@gmail", "@riseup", "drwhax", "/users/", "sc info.sidb", "whatsapp", "airalo"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("startup profile contains forbidden account marker %q", forbidden)
		}
	}
}
