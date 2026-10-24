package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestGeneratedFaultMapping(t *testing.T) {
	for protocolRound, siteRound := range map[uint16]uint16{6: 6, 7: 6, 8: 7, 9: 8} {
		value, err := generatedFault(uint32(protocolRound) | 3<<16 | 7<<24)
		if err != nil {
			t.Fatal(err)
		}
		if value.pc != generatedFaultSites[siteRound][3].pc || value.value != 7 {
			t.Fatalf("protocol round %d selected %#v", protocolRound, value)
		}
	}
	if _, err := generatedFault(5 | 1<<24); err == nil {
		t.Fatal("unsupported round was accepted")
	}
}

func TestBitHelpers(t *testing.T) {
	if got := rotateRight(0x12345678, 8, 32); got != 0x78123456 {
		t.Fatalf("rotateRight32 = %#x", got)
	}
	if got := insertBits(0xffffffff, 0, 8, 8, 32); got != 0xffff00ff {
		t.Fatalf("insertBits = %#x", got)
	}
	if got := extractPair(0x11223344, 0x55667788, 16, 32); got != 0x33445566 {
		t.Fatalf("extractPair = %#x", got)
	}
}

func TestPrivateOracleFixture(t *testing.T) {
	path := os.Getenv("FAIRPLAY_GO_ORACLE_MODEL")
	expected := os.Getenv("FAIRPLAY_GO_ORACLE_BASELINE_SHA256")
	if path == "" && expected == "" {
		t.Skip("private Go oracle model is not configured")
	}
	if path == "" || len(expected) != 64 {
		t.Fatal("private regression requires model and baseline SHA-256")
	}
	value, err := loadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkModelBuild(value); err != nil {
		t.Fatal(err)
	}
	var block [16]byte
	page := value.pages[value.block&^(pageSize-1)]
	if page == nil {
		t.Fatal("private model does not contain its input block")
	}
	copy(block[:], page[value.block&(pageSize-1):])
	worker := newState(value)
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
	if observed := hex.EncodeToString(digest[:]); observed != expected {
		t.Fatalf("baseline SHA-256 = %s, want %s", observed, expected)
	}
}
