//go:build fairplayrawsource && !fairplaysidb && !fairplayframe && !fairplaystate && !fairplay26a428

package main

import "testing"

func TestVectorUnsignedMultiplyLongSupportsDestinationAlias(t *testing.T) {
	var state state
	state.setVectorLane(2, 0, 32, 3)
	state.setVectorLane(2, 1, 32, 4)
	state.setVectorLane(4, 0, 32, 5)
	state.setVectorLane(4, 1, 32, 6)

	state.vectorUnsignedMultiplyLong(4, 2, 4, 2, 32, false)

	if got := state.vectorLane(4, 0, 64); got != 15 {
		t.Fatalf("lane 0 = %d, want 15", got)
	}
	if got := state.vectorLane(4, 1, 64); got != 24 {
		t.Fatalf("lane 1 = %d, want 24", got)
	}
}

func TestVectorShiftRightNarrowSupportsDestinationAlias(t *testing.T) {
	var state state
	state.setVectorLane(5, 0, 64, 0x1122334455667788)
	state.setVectorLane(5, 1, 64, 0x99aabbccddeeff00)

	state.vectorShiftRightNarrow(5, 5, 2, 32, 32)

	if got := state.vectorLane(5, 0, 32); got != 0x11223344 {
		t.Fatalf("lane 0 = %#x, want %#x", got, uint64(0x11223344))
	}
	if got := state.vectorLane(5, 1, 32); got != 0x99aabbcc {
		t.Fatalf("lane 1 = %#x, want %#x", got, uint64(0x99aabbcc))
	}
}

func TestVectorTableUsesConcatenatedRegisters(t *testing.T) {
	var state state
	for register := 8; register < 12; register++ {
		for index := range 16 {
			state.vectors[register][index] = byte((register-8)*16 + index)
		}
	}
	for index := range 16 {
		state.vectors[18][index] = byte(63 - index)
	}

	state.vectorTable(21, []int{8, 9, 10, 11}, 18)

	for index := range 16 {
		want := byte(63 - index)
		if got := state.vectors[21][index]; got != want {
			t.Fatalf("byte %d = %#x, want %#x", index, got, want)
		}
	}
}
