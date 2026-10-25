//go:build fairplaysidb && !fairplayframe && !fairplaystate

package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestEmbeddedSIDBModelExecutesWithInjectedPublicFrame(t *testing.T) {
	if got := fmt.Sprintf("%x", sha256.Sum256(embeddedSIDBModel)); got != "cee524a1210189005f1fc334ad56a84381dfd381426cef4364871c962adeadba" {
		t.Fatalf("embedded SIDB model digest = %s", got)
	}
	value, err := loadModelBytes(embeddedSIDBModel)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.pages) != 71 {
		t.Fatalf("embedded SIDB model has %d pages, want 71", len(value.pages))
	}
	for _, address := range []uint64{0x100D85000, 0x100F1C000} {
		if value.pages[address] == nil {
			t.Fatalf("embedded SIDB model lacks validated path page %#x", address)
		}
	}
	for _, address := range []uint64{0x101075000, 0x7000000FB000} {
		page := value.pages[address]
		if page == nil {
			t.Fatalf("embedded SIDB model lacks sanitized page %#x", address)
		}
		for offset, octet := range page {
			if octet != 0 {
				t.Fatalf("sanitized SIDB page %#x retains byte %#x", address, offset)
			}
		}
	}
	inputPage := value.pages[value.block&^(pageSize-1)]
	inputOffset := value.block & (pageSize - 1)
	for index, octet := range inputPage[inputOffset : inputOffset+16] {
		if octet != 0 {
			t.Fatalf("embedded SIDB model retains oracle-input byte %d", index)
		}
	}
	frameAddress, ok := enrollmentFrameAddress()
	if !ok || !embeddedModelNeedsEnrollmentFrame() {
		t.Fatal("SIDB enrollment-frame contract is disabled")
	}
	page := value.pages[frameAddress&^(pageSize-1)]
	if page == nil {
		t.Fatal("embedded SIDB model lacks its enrollment-frame page")
	}
	frameOffset := frameAddress & (pageSize - 1)
	for index, octet := range page[frameOffset : frameOffset+16] {
		if octet != 0 {
			t.Fatalf("embedded SIDB model retains enrollment-frame byte %d", index)
		}
	}
	frame := sha256.Sum256([]byte("ipatool public SIDB frame fixture"))
	if err := value.patch(frameAddress, frame[:16]); err != nil {
		t.Fatal(err)
	}
	input := sha256.Sum256([]byte("ipatool public SIDB block fixture"))
	worker := newState(value)
	if err := worker.beginBytes(input[:16]); err != nil {
		t.Fatal(err)
	}
	if err := runGenerated(worker, fault{}); err != nil {
		t.Fatal(err)
	}
	output, err := worker.output()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(output[:])); got != "fa60630407415ac643265feb92f467340dd4bc63fb3f37cf308a6619436cb898" {
		t.Fatalf("public SIDB fixture output digest = %s", got)
	}
}
