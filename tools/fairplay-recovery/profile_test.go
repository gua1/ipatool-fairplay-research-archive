package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
)

func TestPackagedStartupProfilesMatchCheckedBuildState(t *testing.T) {
	profiles := []struct {
		path, binaryHash, profileHash string
		memory                        int
		once                          [2]string
	}{
		{
			"profiles/macos26a428-startup.json.gz",
			"1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784",
			"ae76565eb5ca10301d4eec27ce109024008b9e40eac67670702043358e0bca9e",
			774144,
			[2]string{"0x1010746b0", "0x101075b48"},
		},
		{
			"profiles/macos26b118-startup.json.gz",
			"f68e4407e90af5466d2766e1b1c4637260d08cb0518f991e1797ac6c4964439d",
			"ed03021a3856c5bc67076cb8eb481804aa567b909c4c3ae76f1334f6157c0b43",
			14501,
			[2]string{"0x1010b70c8", "0x1010b8cd0"},
		},
	}
	for _, profile := range profiles {
		t.Run(profile.path, func(t *testing.T) {
			compressed, err := os.ReadFile(profile.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(compressed)); got != profile.profileHash {
				t.Fatalf("profile digest = %s, want %s", got, profile.profileHash)
			}
			stream, err := gzip.NewReader(bytes.NewReader(compressed))
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			plain, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(plain, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 4 {
				t.Fatalf("startup profile has %d fields, want 4", len(fields))
			}
			for _, name := range []string{"schema", "binary_sha256", "memory", "once_tokens"} {
				if _, ok := fields[name]; !ok {
					t.Fatalf("startup profile lacks %q", name)
				}
			}
			var value struct {
				Schema       string               `json:"schema"`
				BinarySHA256 string               `json:"binary_sha256"`
				Memory       [][2]json.RawMessage `json:"memory"`
				OnceTokens   []string             `json:"once_tokens"`
			}
			if err := json.Unmarshal(plain, &value); err != nil {
				t.Fatal(err)
			}
			if value.Schema != "ipatool-fairplay-startup-cache-v1" || value.BinarySHA256 != profile.binaryHash {
				t.Fatalf("unexpected startup profile identity: %q %q", value.Schema, value.BinarySHA256)
			}
			if len(value.Memory) != profile.memory || len(value.OnceTokens) != len(profile.once) {
				t.Fatalf("unexpected startup geometry: memory=%d once=%d", len(value.Memory), len(value.OnceTokens))
			}
			for index, token := range profile.once {
				if value.OnceTokens[index] != token {
					t.Fatalf("once token %d = %q, want %q", index, value.OnceTokens[index], token)
				}
			}
			var previous uint64
			for index, entry := range value.Memory {
				var addressText string
				var octet int
				if err := json.Unmarshal(entry[0], &addressText); err != nil {
					t.Fatal(err)
				}
				address, err := strconv.ParseUint(addressText, 0, 64)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(entry[1], &octet); err != nil {
					t.Fatal(err)
				}
				if octet < 0 || octet > 255 {
					t.Fatalf("memory byte %d is outside byte range: %d", index, octet)
				}
				if index != 0 && address <= previous {
					t.Fatalf("memory address %d is not strictly sorted: %#x after %#x", index, address, previous)
				}
				previous = address
			}
		})
	}
}
