package fairplay

import (
	"encoding/hex"
	"testing"
)

func TestNormalizedARM64AnchorIgnoresImmediateChanges(t *testing.T) {
	data, err := hex.DecodeString(fairPlayAnchorDefinitions[0].encoded)
	if err != nil {
		t.Fatal(err)
	}
	patterns, err := fairPlayAnchorPatterns()
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), data...)
	mutated[1] ^= 0x20  // MOVK immediate, without changing its operation.
	mutated[16] ^= 0x04 // Branch displacement, without changing B.
	operations, valid := normalizedARM64Operations(mutated)
	matches := normalizedOperationMatches(operations, valid, patterns[0].operations, 0x1000, 4)
	if len(matches) != 1 || matches[0] != 0x1000 {
		t.Fatalf("normalized matches = %#v", matches)
	}
}

func TestByteMatchesAreBoundedAndAddressed(t *testing.T) {
	pattern := []byte{1, 2, 3, 4}
	blob := append(append(append([]byte{}, pattern...), pattern...), pattern...)
	matches := allByteMatches(blob, pattern, 0x2000, 2)
	if len(matches) != 2 || matches[0] != 0x2000 || matches[1] != 0x2004 {
		t.Fatalf("byte matches = %#v", matches)
	}
}
