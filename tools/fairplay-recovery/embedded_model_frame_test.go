//go:build fairplayframe

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEmbeddedFrameModelIsSanitized(t *testing.T) {
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	for address, allowed := range map[uint64][][2]int{
		0x7000000fb000: {},
		0x7000000ee000: {{0xaf8, 0xb08}},
		0x101074000:    {{0x4c8, 0x4cc}},
		0x101075000:    {{0xb40, 0xb44}},
	} {
		page := value.pages[address]
		if page == nil {
			t.Fatalf("embedded model lacks page %#x", address)
		}
		for offset, current := range page {
			permitted := false
			for _, span := range allowed {
				permitted = permitted || offset >= span[0] && offset < span[1]
			}
			if current != 0 && !permitted {
				t.Fatalf("embedded page %#x retains byte at offset %#x", address, offset)
			}
		}
	}
}

func TestEmbeddedFrameEvaluator(t *testing.T) {
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	worker := newState(value)
	var block [16]byte
	if err := worker.begin(block); err != nil {
		t.Fatal(err)
	}
	if err := runGenerated(worker, fault{}); err != nil {
		t.Fatal(err)
	}
	output, err := worker.output()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(output[:])
	if observed := hex.EncodeToString(digest[:]); observed != "7d3b5648332a3ca5df0971442b796a4df472c09e63e9861756d982c2ff3d5fb4" {
		t.Fatalf("zero-input output SHA-256 = %s", observed)
	}
}
