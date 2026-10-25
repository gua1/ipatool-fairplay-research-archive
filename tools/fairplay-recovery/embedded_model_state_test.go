//go:build fairplaystate

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEmbeddedStateModelIsSanitized(t *testing.T) {
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	page := value.pages[0x7000000fb000]
	if page == nil {
		t.Fatal("embedded state model lacks its input page")
	}
	for offset, current := range page[0x524:0x604] {
		if current != 0 {
			t.Fatalf("embedded state model retains input byte %d", offset)
		}
	}
}

func TestEmbeddedStateEvaluator(t *testing.T) {
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	worker := newState(value)
	input := make([]byte, generatedInputBytes())
	if err := worker.beginBytes(input); err != nil {
		t.Fatal(err)
	}
	if err := runGenerated(worker, fault{}); err != nil {
		t.Fatal(err)
	}
	output, err := worker.outputBytes(value.block, len(input))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(output)
	if observed := hex.EncodeToString(digest[:]); observed != "9e9f0073f8732cd41f7afa3106b5d25c068864e4974814944186664865b3aa93" {
		t.Fatalf("zero-input output SHA-256 = %s", observed)
	}
}
