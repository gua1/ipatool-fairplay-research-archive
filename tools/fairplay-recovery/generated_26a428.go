//go:build fairplay26a428 && !fairplaysidb

// Code generated from the validated macOS 26A428 oracle trace; DO NOT EDIT.
package main

import "fmt"

var generatedBinaryHash = [32]byte{0x1e, 0x58, 0xd3, 0x7e, 0x96, 0x02, 0xdd, 0x0c, 0xa5, 0xe2, 0x4b, 0x14, 0x76, 0x20, 0x63, 0xb6, 0xc3, 0x10, 0x24, 0x8b, 0x4d, 0x3a, 0x94, 0x27, 0x27, 0x71, 0xd8, 0x15, 0xe4, 0xea, 0x17, 0x84}

var generatedFaultSites = map[uint16][16]fault{
	6: {{pc: 0x100235dd0, register: 10, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 12, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 14, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 15, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 10, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 12, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 14, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 14, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 10, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 12, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 12, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 15, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 10, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 11, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 14, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235dd0, register: 15, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}},
	7: {{pc: 0x100235fa8, register: 8, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 9, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 11, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 12, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 8, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 9, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 11, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 12, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 8, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 9, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 11, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 11, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 8, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 9, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 10, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x100235fa8, register: 12, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}},
	8: {{pc: 0x1002361bc, register: 8, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 9, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 10, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 11, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 8, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 9, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 10, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 11, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 8, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 9, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 10, shift: 0, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 11, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 8, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 9, shift: 16, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 10, shift: 24, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}, {pc: 0x1002361bc, register: 11, shift: 8, kind: faultIndex, restore: false, tableBytes: 0x400, entryBytes: 4}},
}

func generatedFault(meta uint32) (fault, error) {
	round := uint16(meta & 0xffff)
	if round == 0xffff {
		return fault{}, nil
	}
	var siteRound uint16
	switch round {
	case 9:
		siteRound = 8
	case 8:
		siteRound = 7
	case 6, 7:
		siteRound = 6
	default:
		return fault{}, fmt.Errorf("unsupported oracle fault round=%d", round)
	}
	byteIndex := uint8(meta >> 16)
	xorValue := uint8(meta >> 24)
	sites := generatedFaultSites[siteRound]
	if byteIndex >= 16 || xorValue == 0 {
		return fault{}, fmt.Errorf("unsupported oracle fault round=%d byte=%d xor=%d", round, byteIndex, xorValue)
	}
	result := sites[byteIndex]
	result.value = xorValue
	return result, nil
}

func shiftLeft(value uint64, amount int, width int) uint64 {
	if width == 32 {
		return uint64(uint32(value) << (uint(amount) & 31))
	}
	return value << (uint(amount) & 63)
}

func shiftRight(value uint64, amount int, width int) uint64 {
	if width == 32 {
		return uint64(uint32(value) >> (uint(amount) & 31))
	}
	return value >> (uint(amount) & 63)
}

func shiftRightArithmetic(value uint64, amount int, width int) uint64 {
	if width == 32 {
		return uint64(uint32(int32(value) >> (uint(amount) & 31)))
	}
	return uint64(int64(value) >> (uint(amount) & 63))
}

func rotateRight(value uint64, amount int, width int) uint64 {
	if width == 32 {
		return uint64(rotateRight32(uint32(value), uint32(amount)))
	}
	amount &= 63
	if amount == 0 {
		return value
	}
	return value>>amount | value<<(64-amount)
}

func bitMask(bits int, width int) uint64 {
	if bits >= width {
		if width == 32 {
			return uint64(^uint32(0))
		}
		return ^uint64(0)
	}
	return uint64(1)<<bits - 1
}

func insertBits(destination, source uint64, lsb, bits, width int) uint64 {
	mask := bitMask(bits, width) << lsb
	value := (destination &^ mask) | ((source << lsb) & mask)
	if width == 32 {
		return uint64(uint32(value))
	}
	return value
}

func extractPair(high, low uint64, amount, width int) uint64 {
	if width == 32 {
		combined := uint64(uint32(high))<<32 | uint64(uint32(low))
		return uint64(uint32(combined >> amount))
	}
	if amount == 0 {
		return low
	}
	return high<<(64-amount) | low>>amount
}

func addOffset(value uint64, offset int64) uint64 { return value + uint64(offset) }

func boolValue(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func selectValue(condition bool, left, right uint64) uint64 {
	if condition {
		return left
	}
	return right
}

func runGenerated(s *state, selected fault) error {
	// 0x100234cdc: ldrb w8, [x28, x8]
	value0, err := s.load((s.x[28] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value0))
	// 0x100234ce0: mov w9, #0x292c
	s.x[9] = uint64(uint32(uint64(0x292c)))
	// 0x100234ce4: movk w9, #0x29ad, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x29ad, 16, 16, 32)))
	// 0x100234ce8: add w11, w10, w9
	s.x[11] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[9])))))
	// 0x100234cec: mov w9, #0x1a
	s.x[9] = uint64(uint32(uint64(0x1a)))
	// 0x100234cf0: str w11, [sp, #0x404]
	if err := s.storeValue(addOffset(s.sp, 1028), uint64(uint32(s.x[11])), 4); err != nil {
		return err
	}
	// 0x100234cf4: eor w9, w11, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[9])))))
	// 0x100234cf8: mov w10, #0xc5
	s.x[10] = uint64(uint32(uint64(0xc5)))
	// 0x100234cfc: eor x10, x8, x10
	s.x[10] = uint64((s.x[8] ^ s.x[10]))
	// 0x100234d00: ldr x21, [sp, #0x398]
	value9, err := s.load(addOffset(s.sp, 920), 8)
	if err != nil {
		return err
	}
	s.x[21] = uint64(value9)
	// 0x100234d04: ldrb w10, [x21, x10]
	value10, err := s.load((s.x[21] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value10))
	// 0x100234d08: eor w9, w9, w8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100234d0c: mov w11, #0x48
	s.x[11] = uint64(uint32(uint64(0x48)))
	// 0x100234d10: eor w8, w8, w11
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[11])))))
	// 0x100234d14: and w11, w12, #0xfffffffd
	s.x[11] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xfffffffd))))
	// 0x100234d18: mov w7, #0x911e
	s.x[7] = uint64(uint32(uint64(0x911e)))
	// 0x100234d1c: movk w7, #0x5ca7, lsl #16
	s.x[7] = uint64(uint32(insertBits(uint64(uint32(s.x[7])), 0x5ca7, 16, 16, 32)))
	// 0x100234d20: eor x11, x11, x7
	s.x[11] = uint64((s.x[11] ^ s.x[7]))
	// 0x100234d24: str x11, [sp, #0x478]
	if err := s.storeValue(addOffset(s.sp, 1144), s.x[11], 8); err != nil {
		return err
	}
	// 0x100234d28: ldrb w11, [x28, x11]
	value19, err := s.load((s.x[28] + s.x[11]), 1)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value19))
	// 0x100234d2c: mov w13, #0x32
	s.x[13] = uint64(uint32(uint64(0x32)))
	// 0x100234d30: eor x11, x11, x13
	s.x[11] = uint64((s.x[11] ^ s.x[13]))
	// 0x100234d34: ldr x20, [sp, #0x3a0]
	value22, err := s.load(addOffset(s.sp, 928), 8)
	if err != nil {
		return err
	}
	s.x[20] = uint64(value22)
	// 0x100234d38: ldr w11, [x20, x11, lsl #2]
	value23, err := s.load((s.x[20] + shiftLeft(s.x[11], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value23))
	// 0x100234d3c: ror w13, w11, #4
	s.x[13] = uint64(uint32(rotateRight(uint64(uint32(s.x[11])), int(uint64(0x4)), 32)))
	// 0x100234d40: add w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[9])))))
	// 0x100234d44: add w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[10])))))
	// 0x100234d48: mov w9, #-0xe
	s.x[9] = uint64(uint32(uint64(0xfffffff2)))
	// 0x100234d4c: and w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[9])))))
	// 0x100234d50: mov w19, #0x911d
	s.x[19] = uint64(uint32(uint64(0x911d)))
	// 0x100234d54: movk w19, #0x5ca7, lsl #16
	s.x[19] = uint64(uint32(insertBits(uint64(uint32(s.x[19])), 0x5ca7, 16, 16, 32)))
	// 0x100234d58: eor x10, x9, x19
	s.x[10] = uint64((s.x[9] ^ s.x[19]))
	// 0x100234d5c: str x10, [sp, #0x4a0]
	if err := s.storeValue(addOffset(s.sp, 1184), s.x[10], 8); err != nil {
		return err
	}
	// 0x100234d60: mov w9, #-0xb
	s.x[9] = uint64(uint32(uint64(0xfffffff5)))
	// 0x100234d64: and w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[9])))))
	// 0x100234d68: ldrb w10, [x28, x10]
	value35, err := s.load((s.x[28] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value35))
	// 0x100234d6c: eor x11, x9, x7
	s.x[11] = uint64((s.x[9] ^ s.x[7]))
	// 0x100234d70: str x11, [sp, #0x488]
	if err := s.storeValue(addOffset(s.sp, 1160), s.x[11], 8); err != nil {
		return err
	}
	// 0x100234d74: mov w9, #0x5f
	s.x[9] = uint64(uint32(uint64(0x5f)))
	// 0x100234d78: eor x9, x10, x9
	s.x[9] = uint64((s.x[10] ^ s.x[9]))
	// 0x100234d7c: ldrb w10, [x28, x11]
	value40, err := s.load((s.x[28] + s.x[11]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value40))
	// 0x100234d80: ldr x22, [sp, #0x390]
	value41, err := s.load(addOffset(s.sp, 912), 8)
	if err != nil {
		return err
	}
	s.x[22] = uint64(value41)
	// 0x100234d84: ldr w15, [x22, x9, lsl #2]
	value42, err := s.load((s.x[22] + shiftLeft(s.x[9], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value42))
	// 0x100234d88: sub w8, w8, #9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(0x9))))
	// 0x100234d8c: mov w9, #0x3a
	s.x[9] = uint64(uint32(uint64(0x3a)))
	// 0x100234d90: eor x9, x10, x9
	s.x[9] = uint64((s.x[10] ^ s.x[9]))
	// 0x100234d94: ldr w9, [x20, x9, lsl #2]
	value46, err := s.load((s.x[20] + shiftLeft(s.x[9], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value46))
	// 0x100234d98: and w17, w8, #0xff
	s.x[17] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100234d9c: mov w8, #-0xc
	s.x[8] = uint64(uint32(uint64(0xfffffff4)))
	// 0x100234da0: and w8, w12, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[8])))))
	// 0x100234da4: eor x10, x8, x27
	s.x[10] = uint64((s.x[8] ^ s.x[27]))
	// 0x100234da8: str x10, [sp, #0x4a8]
	if err := s.storeValue(addOffset(s.sp, 1192), s.x[10], 8); err != nil {
		return err
	}
	// 0x100234dac: mov w8, #-6
	s.x[8] = uint64(uint32(uint64(0xfffffffa)))
	// 0x100234db0: and w8, w12, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[8])))))
	// 0x100234db4: eor x30, x8, x19
	s.x[30] = uint64((s.x[8] ^ s.x[19]))
	// 0x100234db8: str x30, [sp, #0x438]
	if err := s.storeValue(addOffset(s.sp, 1080), s.x[30], 8); err != nil {
		return err
	}
	// 0x100234dbc: ror w11, w9, #4
	s.x[11] = uint64(uint32(rotateRight(uint64(uint32(s.x[9])), int(uint64(0x4)), 32)))
	// 0x100234dc0: mov w26, #0xf730
	s.x[26] = uint64(uint32(uint64(0xf730)))
	// 0x100234dc4: movk w26, #0xbb2c, lsl #16
	s.x[26] = uint64(uint32(insertBits(uint64(uint32(s.x[26])), 0xbb2c, 16, 16, 32)))
	// 0x100234dc8: eor w8, w26, w11, lsl #4
	s.x[8] = uint64(uint32((uint64(uint32(s.x[26])) ^ shiftLeft(uint64(uint32(s.x[11])), 4, 32))))
	// 0x100234dcc: ldrb w9, [x28, x10]
	value60, err := s.load((s.x[28] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value60))
	// 0x100234dd0: mov w10, #0x43
	s.x[10] = uint64(uint32(uint64(0x43)))
	// 0x100234dd4: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100234dd8: mov x4, x12
	s.x[4] = uint64(s.x[12])
	// 0x100234ddc: mov w12, #0x26
	s.x[12] = uint64(uint32(uint64(0x26)))
	// 0x100234de0: eor x12, x9, x12
	s.x[12] = uint64((s.x[9] ^ s.x[12]))
	// 0x100234de4: ldrb w12, [x21, x12]
	value66, err := s.load((s.x[21] + s.x[12]), 1)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value66))
	// 0x100234de8: mov w14, #0xab
	s.x[14] = uint64(uint32(uint64(0xab)))
	// 0x100234dec: eor w9, w9, w14
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x100234df0: add w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[9])))))
	// 0x100234df4: add w9, w9, w12
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[12])))))
	// 0x100234df8: sub w9, w9, #9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(0x9))))
	// 0x100234dfc: and w10, w4, #0xfffffff7
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffff7))))
	// 0x100234e00: mov w1, #0x911c
	s.x[1] = uint64(uint32(uint64(0x911c)))
	// 0x100234e04: movk w1, #0x5ca7, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x5ca7, 16, 16, 32)))
	// 0x100234e08: eor x10, x10, x1
	s.x[10] = uint64((s.x[10] ^ s.x[1]))
	// 0x100234e0c: str x10, [sp, #0x480]
	if err := s.storeValue(addOffset(s.sp, 1152), s.x[10], 8); err != nil {
		return err
	}
	// 0x100234e10: ldrb w10, [x28, x10]
	value77, err := s.load((s.x[28] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value77))
	// 0x100234e14: mov w12, #0x8a
	s.x[12] = uint64(uint32(uint64(0x8a)))
	// 0x100234e18: eor x10, x10, x12
	s.x[10] = uint64((s.x[10] ^ s.x[12]))
	// 0x100234e1c: ldr x6, [sp, #0x3a8]
	value80, err := s.load(addOffset(s.sp, 936), 8)
	if err != nil {
		return err
	}
	s.x[6] = uint64(value80)
	// 0x100234e20: ldr w10, [x6, x10, lsl #2]
	value81, err := s.load((s.x[6] + shiftLeft(s.x[10], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value81))
	// 0x100234e24: mov w12, #0x8683
	s.x[12] = uint64(uint32(uint64(0x8683)))
	// 0x100234e28: movk w12, #0xda0d, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xda0d, 16, 16, 32)))
	// 0x100234e2c: eor w12, w10, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100234e30: mov w14, #0x797d
	s.x[14] = uint64(uint32(uint64(0x797d)))
	// 0x100234e34: movk w14, #0x25f2, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x25f2, 16, 16, 32)))
	// 0x100234e38: add w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(uint32(s.x[14])))))
	// 0x100234e3c: mov w14, #0xfcbe
	s.x[14] = uint64(uint32(uint64(0xfcbe)))
	// 0x100234e40: movk w14, #0xaf94, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0xaf94, 16, 16, 32)))
	// 0x100234e44: eor w14, w10, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100234e48: mov w16, #0x342
	s.x[16] = uint64(uint32(uint64(0x342)))
	// 0x100234e4c: movk w16, #0x506b, lsl #16
	s.x[16] = uint64(uint32(insertBits(uint64(uint32(s.x[16])), 0x506b, 16, 16, 32)))
	// 0x100234e50: add w14, w14, w16
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) + uint64(uint32(s.x[16])))))
	// 0x100234e54: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100234e58: mov w14, #0x705a
	s.x[14] = uint64(uint32(uint64(0x705a)))
	// 0x100234e5c: movk w14, #0x8f40, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x8f40, 16, 16, 32)))
	// 0x100234e60: eor w14, w10, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100234e64: mov w16, #0x8fa6
	s.x[16] = uint64(uint32(uint64(0x8fa6)))
	// 0x100234e68: movk w16, #0x70bf, lsl #16
	s.x[16] = uint64(uint32(insertBits(uint64(uint32(s.x[16])), 0x70bf, 16, 16, 32)))
	// 0x100234e6c: add w14, w14, w16
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) + uint64(uint32(s.x[16])))))
	// 0x100234e70: eor w14, w12, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100234e74: and w16, w9, #0xff
	s.x[16] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x100234e78: and w9, w4, #0xfffffff3
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffff3))))
	// 0x100234e7c: eor x9, x9, x1
	s.x[9] = uint64((s.x[9] ^ s.x[1]))
	// 0x100234e80: str x9, [sp, #0x490]
	if err := s.storeValue(addOffset(s.sp, 1168), s.x[9], 8); err != nil {
		return err
	}
	// 0x100234e84: ldrb w9, [x28, x9]
	value106, err := s.load((s.x[28] + s.x[9]), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value106))
	// 0x100234e88: mov w23, #0x299c
	s.x[23] = uint64(uint32(uint64(0x299c)))
	// 0x100234e8c: movk w23, #0xeb64, lsl #16
	s.x[23] = uint64(uint32(insertBits(uint64(uint32(s.x[23])), 0xeb64, 16, 16, 32)))
	// 0x100234e90: eor w0, w23, w10, lsl #2
	s.x[0] = uint64(uint32((uint64(uint32(s.x[23])) ^ shiftLeft(uint64(uint32(s.x[10])), 2, 32))))
	// 0x100234e94: lsl w10, w9, #1
	s.x[10] = uint64(uint32(shiftLeft(uint64(uint32(s.x[9])), int(uint64(0x1)), 32)))
	// 0x100234e98: and w10, w10, #0xf8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0xf8))))
	// 0x100234e9c: sub w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[10])))))
	// 0x100234ea0: add w9, w9, #0x7c
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(0x7c))))
	// 0x100234ea4: mov w10, #0xd9
	s.x[10] = uint64(uint32(uint64(0xd9)))
	// 0x100234ea8: eor x9, x9, x10
	s.x[9] = uint64((s.x[9] ^ s.x[10]))
	// 0x100234eac: ldr w9, [x6, x9, lsl #2]
	value116, err := s.load((s.x[6] + shiftLeft(s.x[9], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value116))
	// 0x100234eb0: mov w10, #0x6c1f
	s.x[10] = uint64(uint32(uint64(0x6c1f)))
	// 0x100234eb4: movk w10, #0x6f6f, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x6f6f, 16, 16, 32)))
	// 0x100234eb8: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100234ebc: mov w12, #0x93e1
	s.x[12] = uint64(uint32(uint64(0x93e1)))
	// 0x100234ec0: movk w12, #0x9090, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x9090, 16, 16, 32)))
	// 0x100234ec4: add w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[12])))))
	// 0x100234ec8: mov w12, #0x9126
	s.x[12] = uint64(uint32(uint64(0x9126)))
	// 0x100234ecc: movk w12, #0xc83a, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xc83a, 16, 16, 32)))
	// 0x100234ed0: eor w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x100234ed4: mov w2, #0x6eda
	s.x[2] = uint64(uint32(uint64(0x6eda)))
	// 0x100234ed8: movk w2, #0x37c5, lsl #16
	s.x[2] = uint64(uint32(insertBits(uint64(uint32(s.x[2])), 0x37c5, 16, 16, 32)))
	// 0x100234edc: add w12, w12, w2
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(uint32(s.x[2])))))
	// 0x100234ee0: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100234ee4: mov w12, #0xf75e
	s.x[12] = uint64(uint32(uint64(0xf75e)))
	// 0x100234ee8: movk w12, #0x5d8c, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x5d8c, 16, 16, 32)))
	// 0x100234eec: eor w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x100234ef0: mov w2, #0x8a2
	s.x[2] = uint64(uint32(uint64(0x8a2)))
	// 0x100234ef4: movk w2, #0xa273, lsl #16
	s.x[2] = uint64(uint32(insertBits(uint64(uint32(s.x[2])), 0xa273, 16, 16, 32)))
	// 0x100234ef8: add w12, w12, w2
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(uint32(s.x[2])))))
	// 0x100234efc: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100234f00: eor w9, w23, w9, lsl #2
	s.x[9] = uint64(uint32((uint64(uint32(s.x[23])) ^ shiftLeft(uint64(uint32(s.x[9])), 2, 32))))
	// 0x100234f04: and w12, w4, #0xfffffffb
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffffb))))
	// 0x100234f08: eor x12, x12, x1
	s.x[12] = uint64((s.x[12] ^ s.x[1]))
	// 0x100234f0c: str x12, [sp, #0x448]
	if err := s.storeValue(addOffset(s.sp, 1096), s.x[12], 8); err != nil {
		return err
	}
	// 0x100234f10: ldrb w12, [x28, x12]
	value141, err := s.load((s.x[28] + s.x[12]), 1)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value141))
	// 0x100234f14: mov w2, #0x42
	s.x[2] = uint64(uint32(uint64(0x42)))
	// 0x100234f18: eor x12, x12, x2
	s.x[12] = uint64((s.x[12] ^ s.x[2]))
	// 0x100234f1c: ldr w2, [x6, x12, lsl #2]
	value144, err := s.load((s.x[6] + shiftLeft(s.x[12], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[2] = uint64(uint32(value144))
	// 0x100234f20: and w12, w4, #0xfffffff1
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffff1))))
	// 0x100234f24: eor x24, x12, x7
	s.x[24] = uint64((s.x[12] ^ s.x[7]))
	// 0x100234f28: str x24, [sp, #0x470]
	if err := s.storeValue(addOffset(s.sp, 1136), s.x[24], 8); err != nil {
		return err
	}
	// 0x100234f2c: mov w12, #0xea67
	s.x[12] = uint64(uint32(uint64(0xea67)))
	// 0x100234f30: movk w12, #0x5488, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x5488, 16, 16, 32)))
	// 0x100234f34: eor w12, w2, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[2])) ^ uint64(uint32(s.x[12])))))
	// 0x100234f38: mov w3, #0x1599
	s.x[3] = uint64(uint32(uint64(0x1599)))
	// 0x100234f3c: movk w3, #0xab77, lsl #16
	s.x[3] = uint64(uint32(insertBits(uint64(uint32(s.x[3])), 0xab77, 16, 16, 32)))
	// 0x100234f40: add w12, w12, w3
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(uint32(s.x[3])))))
	// 0x100234f44: mov w3, #0xd9b4
	s.x[3] = uint64(uint32(uint64(0xd9b4)))
	// 0x100234f48: movk w3, #0xca60, lsl #16
	s.x[3] = uint64(uint32(insertBits(uint64(uint32(s.x[3])), 0xca60, 16, 16, 32)))
	// 0x100234f4c: eor w3, w2, w3
	s.x[3] = uint64(uint32((uint64(uint32(s.x[2])) ^ uint64(uint32(s.x[3])))))
	// 0x100234f50: mov w5, #0x264c
	s.x[5] = uint64(uint32(uint64(0x264c)))
	// 0x100234f54: movk w5, #0x359f, lsl #16
	s.x[5] = uint64(uint32(insertBits(uint64(uint32(s.x[5])), 0x359f, 16, 16, 32)))
	// 0x100234f58: add w3, w3, w5
	s.x[3] = uint64(uint32((uint64(uint32(s.x[3])) + uint64(uint32(s.x[5])))))
	// 0x100234f5c: eor w12, w12, w3
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[3])))))
	// 0x100234f60: mov w3, #0x39b4
	s.x[3] = uint64(uint32(uint64(0x39b4)))
	// 0x100234f64: movk w3, #0x6431, lsl #16
	s.x[3] = uint64(uint32(insertBits(uint64(uint32(s.x[3])), 0x6431, 16, 16, 32)))
	// 0x100234f68: eor w3, w2, w3
	s.x[3] = uint64(uint32((uint64(uint32(s.x[2])) ^ uint64(uint32(s.x[3])))))
	// 0x100234f6c: mov w5, #0xc64c
	s.x[5] = uint64(uint32(uint64(0xc64c)))
	// 0x100234f70: movk w5, #0x9bce, lsl #16
	s.x[5] = uint64(uint32(insertBits(uint64(uint32(s.x[5])), 0x9bce, 16, 16, 32)))
	// 0x100234f74: add w3, w3, w5
	s.x[3] = uint64(uint32((uint64(uint32(s.x[3])) + uint64(uint32(s.x[5])))))
	// 0x100234f78: eor w12, w12, w3
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[3])))))
	// 0x100234f7c: ldrb w3, [x28, x24]
	value168, err := s.load((s.x[28] + s.x[24]), 1)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value168))
	// 0x100234f80: mov w5, #0x52
	s.x[5] = uint64(uint32(uint64(0x52)))
	// 0x100234f84: eor x3, x3, x5
	s.x[3] = uint64((s.x[3] ^ s.x[5]))
	// 0x100234f88: ldr w3, [x20, x3, lsl #2]
	value171, err := s.load((s.x[20] + shiftLeft(s.x[3], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value171))
	// 0x100234f8c: ror w3, w3, #4
	s.x[3] = uint64(uint32(rotateRight(uint64(uint32(s.x[3])), int(uint64(0x4)), 32)))
	// 0x100234f90: eor w15, w15, w17
	s.x[15] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[17])))))
	// 0x100234f94: eor w17, w26, w3, lsl #4
	s.x[17] = uint64(uint32((uint64(uint32(s.x[26])) ^ shiftLeft(uint64(uint32(s.x[3])), 4, 32))))
	// 0x100234f98: mov w5, #0xfec0
	s.x[5] = uint64(uint32(uint64(0xfec0)))
	// 0x100234f9c: movk w5, #0x315e, lsl #16
	s.x[5] = uint64(uint32(insertBits(uint64(uint32(s.x[5])), 0x315e, 16, 16, 32)))
	// 0x100234fa0: add w9, w9, w5
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[5])))))
	// 0x100234fa4: eor w9, w15, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[9])))))
	// 0x100234fa8: mov w15, w4
	s.x[15] = uint64(uint32(uint64(uint32(s.x[4]))))
	// 0x100234fac: eor x15, x15, x1
	s.x[15] = uint64((s.x[15] ^ s.x[1]))
	// 0x100234fb0: str x15, [sp, #0x440]
	if err := s.storeValue(addOffset(s.sp, 1088), s.x[15], 8); err != nil {
		return err
	}
	// 0x100234fb4: eor w9, w9, w3
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[3])))))
	// 0x100234fb8: ldrb w15, [x28, x15]
	value183, err := s.load((s.x[28] + s.x[15]), 1)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value183))
	// 0x100234fbc: mov w24, #0x85df
	s.x[24] = uint64(uint32(uint64(0x85df)))
	// 0x100234fc0: movk w24, #0xdac1, lsl #16
	s.x[24] = uint64(uint32(insertBits(uint64(uint32(s.x[24])), 0xdac1, 16, 16, 32)))
	// 0x100234fc4: add w10, w10, w24
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[24])))))
	// 0x100234fc8: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100234fcc: mov w1, #0xf8d0
	s.x[1] = uint64(uint32(uint64(0xf8d0)))
	// 0x100234fd0: movk w1, #0x87da, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x87da, 16, 16, 32)))
	// 0x100234fd4: add w10, w17, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) + uint64(uint32(s.x[1])))))
	// 0x100234fd8: eor w25, w9, w10
	s.x[25] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100234fdc: eor x9, x15, #0xc
	s.x[9] = uint64((s.x[15] ^ uint64(0xc)))
	// 0x100234fe0: ldr w15, [x6, x9, lsl #2]
	value193, err := s.load((s.x[6] + shiftLeft(s.x[9], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value193))
	// 0x100234fe4: mov w9, #0xc4e0
	s.x[9] = uint64(uint32(uint64(0xc4e0)))
	// 0x100234fe8: movk w9, #0xb22b, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0xb22b, 16, 16, 32)))
	// 0x100234fec: eor w9, w15, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[9])))))
	// 0x100234ff0: mov w10, #0x3b20
	s.x[10] = uint64(uint32(uint64(0x3b20)))
	// 0x100234ff4: movk w10, #0x4dd4, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x4dd4, 16, 16, 32)))
	// 0x100234ff8: add w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[10])))))
	// 0x100234ffc: mov w10, #0x99d3
	s.x[10] = uint64(uint32(uint64(0x99d3)))
	// 0x100235000: movk w10, #0x658c, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x658c, 16, 16, 32)))
	// 0x100235004: eor w10, w15, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[10])))))
	// 0x100235008: mov w17, #0x662d
	s.x[17] = uint64(uint32(uint64(0x662d)))
	// 0x10023500c: movk w17, #0x9a73, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x9a73, 16, 16, 32)))
	// 0x100235010: add w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[17])))))
	// 0x100235014: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235018: mov w10, #0x5754
	s.x[10] = uint64(uint32(uint64(0x5754)))
	// 0x10023501c: movk w10, #0x2d7e, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x2d7e, 16, 16, 32)))
	// 0x100235020: eor w10, w15, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[10])))))
	// 0x100235024: mov w17, #0xa8ac
	s.x[17] = uint64(uint32(uint64(0xa8ac)))
	// 0x100235028: movk w17, #0xd281, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0xd281, 16, 16, 32)))
	// 0x10023502c: add w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[17])))))
	// 0x100235030: eor w3, w9, w10
	s.x[3] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235034: mov w9, #-0xa
	s.x[9] = uint64(uint32(uint64(0xfffffff6)))
	// 0x100235038: and w9, w4, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(uint32(s.x[9])))))
	// 0x10023503c: eor x10, x9, x19
	s.x[10] = uint64((s.x[9] ^ s.x[19]))
	// 0x100235040: str x10, [sp, #0x468]
	if err := s.storeValue(addOffset(s.sp, 1128), s.x[10], 8); err != nil {
		return err
	}
	// 0x100235044: eor w9, w11, w16
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[16])))))
	// 0x100235048: ldrb w10, [x28, x10]
	value219, err := s.load((s.x[28] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value219))
	// 0x10023504c: add w11, w0, w5
	s.x[11] = uint64(uint32((uint64(uint32(s.x[0])) + uint64(uint32(s.x[5])))))
	// 0x100235050: eor w9, w9, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100235054: and w11, w4, #0xfffffff8
	s.x[11] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffff8))))
	// 0x100235058: eor x16, x11, x27
	s.x[16] = uint64((s.x[11] ^ s.x[27]))
	// 0x10023505c: str x16, [sp, #0x428]
	if err := s.storeValue(addOffset(s.sp, 1064), s.x[16], 8); err != nil {
		return err
	}
	// 0x100235060: mov w11, #0x3b
	s.x[11] = uint64(uint32(uint64(0x3b)))
	// 0x100235064: eor x10, x10, x11
	s.x[10] = uint64((s.x[10] ^ s.x[11]))
	// 0x100235068: ldr w10, [x22, x10, lsl #2]
	value227, err := s.load((s.x[22] + shiftLeft(s.x[10], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value227))
	// 0x10023506c: add w8, w8, w1
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[1])))))
	// 0x100235070: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100235074: ldrb w9, [x28, x16]
	value230, err := s.load((s.x[28] + s.x[16]), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value230))
	// 0x100235078: add w11, w14, w24
	s.x[11] = uint64(uint32((uint64(uint32(s.x[14])) + uint64(uint32(s.x[24])))))
	// 0x10023507c: eor w10, w11, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[10])))))
	// 0x100235080: mov w11, #0x79
	s.x[11] = uint64(uint32(uint64(0x79)))
	// 0x100235084: eor w11, w9, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100235088: eor w0, w8, w10
	s.x[0] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x10023508c: eor x8, x9, #0x1c
	s.x[8] = uint64((s.x[9] ^ uint64(0x1c)))
	// 0x100235090: ldrb w8, [x21, x8]
	value237, err := s.load((s.x[21] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value237))
	// 0x100235094: mov w10, #0x91
	s.x[10] = uint64(uint32(uint64(0x91)))
	// 0x100235098: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x10023509c: add w9, w11, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[9])))))
	// 0x1002350a0: ldrb w10, [x28, x30]
	value241, err := s.load((s.x[28] + s.x[30]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value241))
	// 0x1002350a4: mov w11, #0x6c
	s.x[11] = uint64(uint32(uint64(0x6c)))
	// 0x1002350a8: eor x10, x10, x11
	s.x[10] = uint64((s.x[10] ^ s.x[11]))
	// 0x1002350ac: ldr w10, [x22, x10, lsl #2]
	value244, err := s.load((s.x[22] + shiftLeft(s.x[10], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value244))
	// 0x1002350b0: and w11, w4, #0xfffffff9
	s.x[11] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffff9))))
	// 0x1002350b4: eor x11, x11, x7
	s.x[11] = uint64((s.x[11] ^ s.x[7]))
	// 0x1002350b8: str x11, [sp, #0x458]
	if err := s.storeValue(addOffset(s.sp, 1112), s.x[11], 8); err != nil {
		return err
	}
	// 0x1002350bc: ldrb w11, [x28, x11]
	value248, err := s.load((s.x[28] + s.x[11]), 1)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value248))
	// 0x1002350c0: mov w14, #0x6e
	s.x[14] = uint64(uint32(uint64(0x6e)))
	// 0x1002350c4: eor x11, x11, x14
	s.x[11] = uint64((s.x[11] ^ s.x[14]))
	// 0x1002350c8: ldr w11, [x20, x11, lsl #2]
	value251, err := s.load((s.x[20] + shiftLeft(s.x[11], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value251))
	// 0x1002350cc: add w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[8])))))
	// 0x1002350d0: ror w9, w11, #4
	s.x[9] = uint64(uint32(rotateRight(uint64(uint32(s.x[11])), int(uint64(0x4)), 32)))
	// 0x1002350d4: eor w11, w23, w2, lsl #2
	s.x[11] = uint64(uint32((uint64(uint32(s.x[23])) ^ shiftLeft(uint64(uint32(s.x[2])), 2, 32))))
	// 0x1002350d8: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002350dc: add w11, w11, w5
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[5])))))
	// 0x1002350e0: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x1002350e4: eor w9, w26, w9, lsl #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[26])) ^ shiftLeft(uint64(uint32(s.x[9])), 4, 32))))
	// 0x1002350e8: add w9, w9, w1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[1])))))
	// 0x1002350ec: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x1002350f0: str w4, [sp, #0x464]
	if err := s.storeValue(addOffset(s.sp, 1124), uint64(uint32(s.x[4])), 4); err != nil {
		return err
	}
	// 0x1002350f4: and w10, w4, #0xfffffffc
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffffc))))
	// 0x1002350f8: eor x11, x10, x27
	s.x[11] = uint64((s.x[10] ^ s.x[27]))
	// 0x1002350fc: str x11, [sp, #0x430]
	if err := s.storeValue(addOffset(s.sp, 1072), s.x[11], 8); err != nil {
		return err
	}
	// 0x100235100: sub w8, w8, #9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(0x9))))
	// 0x100235104: and w8, w8, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100235108: add w10, w12, w24
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(uint32(s.x[24])))))
	// 0x10023510c: eor w8, w10, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[8])))))
	// 0x100235110: ldrb w10, [x28, x11]
	value269, err := s.load((s.x[28] + s.x[11]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value269))
	// 0x100235114: eor w30, w9, w8
	s.x[30] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100235118: mov w7, #0xb7
	s.x[7] = uint64(uint32(uint64(0xb7)))
	// 0x10023511c: eor x8, x10, x7
	s.x[8] = uint64((s.x[10] ^ s.x[7]))
	// 0x100235120: ldrb w8, [x21, x8]
	value273, err := s.load((s.x[21] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value273))
	// 0x100235124: mov w9, #0xd2
	s.x[9] = uint64(uint32(uint64(0xd2)))
	// 0x100235128: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x10023512c: mov w11, #0x3a
	s.x[11] = uint64(uint32(uint64(0x3a)))
	// 0x100235130: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100235134: add w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[9])))))
	// 0x100235138: add w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[8])))))
	// 0x10023513c: and w9, w4, #0xfffffffe
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & uint64(0xfffffffe))))
	// 0x100235140: eor x9, x9, x19
	s.x[9] = uint64((s.x[9] ^ s.x[19]))
	// 0x100235144: str x9, [sp, #0x450]
	if err := s.storeValue(addOffset(s.sp, 1104), s.x[9], 8); err != nil {
		return err
	}
	// 0x100235148: ldrb w9, [x28, x9]
	value283, err := s.load((s.x[28] + s.x[9]), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value283))
	// 0x10023514c: mov w10, #0x62
	s.x[10] = uint64(uint32(uint64(0x62)))
	// 0x100235150: eor x9, x9, x10
	s.x[9] = uint64((s.x[9] ^ s.x[10]))
	// 0x100235154: ldr w9, [x22, x9, lsl #2]
	value286, err := s.load((s.x[22] + shiftLeft(s.x[9], 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value286))
	// 0x100235158: eor w10, w23, w15, lsl #2
	s.x[10] = uint64(uint32((uint64(uint32(s.x[23])) ^ shiftLeft(uint64(uint32(s.x[15])), 2, 32))))
	// 0x10023515c: eor w9, w13, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[9])))))
	// 0x100235160: add w10, w10, w5
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[5])))))
	// 0x100235164: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235168: eor w10, w26, w13, lsl #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[26])) ^ shiftLeft(uint64(uint32(s.x[13])), 4, 32))))
	// 0x10023516c: sub w8, w8, #9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(0x9))))
	// 0x100235170: and w8, w8, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100235174: add w11, w3, w24
	s.x[11] = uint64(uint32((uint64(uint32(s.x[3])) + uint64(uint32(s.x[24])))))
	// 0x100235178: eor w9, w9, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x10023517c: add w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[1])))))
	// 0x100235180: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x100235184: eor w3, w9, w8
	s.x[3] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100235188: adrp x8, #0x101075000
	s.x[8] = uint64(0x101075000)
	// 0x10023518c: ldr w21, [x8, #0x588]
	value300, err := s.load(addOffset(s.x[8], 1416), 4)
	if err != nil {
		return err
	}
	s.x[21] = uint64(uint32(value300))
	// 0x100235190: adrp x8, #0x101075000
	s.x[8] = uint64(0x101075000)
	// 0x100235194: ldr w10, [x8, #0xb40]
	value302, err := s.load(addOffset(s.x[8], 2880), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value302))
	// 0x100235198: str w10, [sp, #0x424]
	if err := s.storeValue(addOffset(s.sp, 1060), uint64(uint32(s.x[10])), 4); err != nil {
		return err
	}
	// 0x10023519c: mov w8, #0xd1a6
	s.x[8] = uint64(uint32(uint64(0xd1a6)))
	// 0x1002351a0: movk w8, #0x8eae, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x8eae, 16, 16, 32)))
	// 0x1002351a4: eor w9, w21, w8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[21])) ^ uint64(uint32(s.x[8])))))
	// 0x1002351a8: eor w8, w9, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002351ac: mov w10, #0xd4cf
	s.x[10] = uint64(uint32(uint64(0xd4cf)))
	// 0x1002351b0: movk w10, #0xa5c, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xa5c, 16, 16, 32)))
	// 0x1002351b4: mul w20, w8, w10
	s.x[20] = uint64(uint32((uint64(uint32(s.x[8])) * uint64(uint32(s.x[10])))))
	// 0x1002351b8: mov w1, #0xd4cf
	s.x[1] = uint64(uint32(uint64(0xd4cf)))
	// 0x1002351bc: movk w1, #0xa5c, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0xa5c, 16, 16, 32)))
	// 0x1002351c0: and x2, x20, #0xff
	s.x[2] = uint64((s.x[20] & uint64(0xff)))
	// 0x1002351c4: ldur x8, [x29, #-0xb8]
	value314, err := s.load(addOffset(s.x[29], -184), 8)
	if err != nil {
		return err
	}
	s.x[8] = uint64(value314)
	// 0x1002351c8: add x8, x8, x2
	s.x[8] = uint64((s.x[8] + s.x[2]))
	// 0x1002351cc: ldrb w8, [x8]
	value316, err := s.load(s.x[8], 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value316))
	// 0x1002351d0: mov w10, #0x5d
	s.x[10] = uint64(uint32(uint64(0x5d)))
	// 0x1002351d4: eor w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x1002351d8: ldur x10, [x29, #-0xa8]
	value319, err := s.load(addOffset(s.x[29], -168), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value319)
	// 0x1002351dc: ldrb w8, [x10, w8, uxtw]
	value320, err := s.load((s.x[10] + uint64(uint32(uint64(uint32(s.x[8]))))), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value320))
	// 0x1002351e0: eor w8, w20, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[20])) ^ uint64(uint32(s.x[8])))))
	// 0x1002351e4: mov w10, #0x152c
	s.x[10] = uint64(uint32(uint64(0x152c)))
	// 0x1002351e8: add w8, w10, w8, uxtb
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint8(uint64(uint32(s.x[8])))))))
	// 0x1002351ec: adrp x17, #0x10105b000
	s.x[17] = uint64(0x10105b000)
	// 0x1002351f0: add x17, x17, #0x6f0
	s.x[17] = uint64((s.x[17] + uint64(0x6f0)))
	// 0x1002351f4: ldr x8, [x17, w8, uxtw #3]
	value326, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[8] = uint64(value326)
	// 0x1002351f8: mov x10, #-0x433e
	s.x[10] = uint64(uint64(0xffffffffffffbcc2))
	// 0x1002351fc: movk x10, #0xa28e, lsl #16
	s.x[10] = uint64(insertBits(s.x[10], 0xa28e, 16, 16, 64))
	// 0x100235200: add x22, x8, x10
	s.x[22] = uint64((s.x[8] + s.x[10]))
	// 0x100235204: ldr w8, [sp, #0x2c8]
	value330, err := s.load(addOffset(s.sp, 712), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value330))
	// 0x100235208: eor w16, w8, w3
	s.x[16] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[3])))))
	// 0x10023520c: lsr w8, w16, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[16])), int(uint64(0x18)), 32)))
	// 0x100235210: ldr w8, [x22, w8, uxtw #2]
	value333, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value333))
	// 0x100235214: ldur x10, [x29, #-0xa0]
	value334, err := s.load(addOffset(s.x[29], -160), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value334)
	// 0x100235218: ldr w10, [x10]
	value335, err := s.load(s.x[10], 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value335))
	// 0x10023521c: eor w12, w9, w10
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235220: ldr w9, [sp, #0x36c]
	value337, err := s.load(addOffset(s.sp, 876), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value337))
	// 0x100235224: str w0, [sp, #0x3fc]
	if err := s.storeValue(addOffset(s.sp, 1020), uint64(uint32(s.x[0])), 4); err != nil {
		return err
	}
	// 0x100235228: eor w19, w9, w0
	s.x[19] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x10023522c: ldr w9, [sp, #0x370]
	value340, err := s.load(addOffset(s.sp, 880), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value340))
	// 0x100235230: eor w15, w9, w25
	s.x[15] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[25])))))
	// 0x100235234: ubfx w13, w15, #0x10, #8
	s.x[13] = uint64(uint32((uint64(uint32(s.x[15])) >> 16) & bitMask(8, 32)))
	// 0x100235238: mov w27, #0x7a55
	s.x[27] = uint64(uint32(uint64(0x7a55)))
	// 0x10023523c: movk w27, #0xbc9e, lsl #16
	s.x[27] = uint64(uint32(insertBits(uint64(uint32(s.x[27])), 0xbc9e, 16, 16, 32)))
	// 0x100235240: eor w9, w13, w27
	s.x[9] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[27])))))
	// 0x100235244: ubfx w11, w19, #8, #8
	s.x[11] = uint64(uint32((uint64(uint32(s.x[19])) >> 8) & bitMask(8, 32)))
	// 0x100235248: ldr w10, [sp, #0x360]
	value347, err := s.load(addOffset(s.sp, 864), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value347))
	// 0x10023524c: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100235250: sub w9, w13, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[13])) - uint64(uint32(s.x[9])))))
	// 0x100235254: mov w0, #0x95
	s.x[0] = uint64(uint32(uint64(0x95)))
	// 0x100235258: eor w14, w13, w0
	s.x[14] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[0])))))
	// 0x10023525c: mul w23, w12, w1
	s.x[23] = uint64(uint32((uint64(uint32(s.x[12])) * uint64(uint32(s.x[1])))))
	// 0x100235260: and x12, x23, #0xff
	s.x[12] = uint64((s.x[23] & uint64(0xff)))
	// 0x100235264: str x12, [sp, #0x410]
	if err := s.storeValue(addOffset(s.sp, 1040), s.x[12], 8); err != nil {
		return err
	}
	// 0x100235268: ldp x4, x13, [x29, #-0xd0]
	value355a, err := s.load(addOffset(s.x[29], -208), 8)
	if err != nil {
		return err
	}
	value355b, err := s.load((addOffset(s.x[29], -208))+8, 8)
	if err != nil {
		return err
	}
	s.x[4] = uint64(value355a)
	s.x[13] = uint64(value355b)
	// 0x10023526c: add x12, x13, x12
	s.x[12] = uint64((s.x[13] + s.x[12]))
	// 0x100235270: ldrb w12, [x12]
	value357, err := s.load(s.x[12], 1)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value357))
	// 0x100235274: mov w6, #0x17
	s.x[6] = uint64(uint32(uint64(0x17)))
	// 0x100235278: eor w12, w12, w6
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[6])))))
	// 0x10023527c: ldrb w12, [x4, w12, uxtw]
	value360, err := s.load((s.x[4] + uint64(uint32(uint64(uint32(s.x[12]))))), 1)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value360))
	// 0x100235280: eor w12, w23, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[23])) ^ uint64(uint32(s.x[12])))))
	// 0x100235284: and w12, w12, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x100235288: add w12, w12, #0xa89
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(0xa89))))
	// 0x10023528c: ldr x12, [x17, w12, uxtw #3]
	value364, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[12] = uint64(value364)
	// 0x100235290: mov x1, #-0x9f66
	s.x[1] = uint64(uint64(0xffffffffffff609a))
	// 0x100235294: movk x1, #0xaf03, lsl #16
	s.x[1] = uint64(insertBits(s.x[1], 0xaf03, 16, 16, 64))
	// 0x100235298: add x24, x12, x1
	s.x[24] = uint64((s.x[12] + s.x[1]))
	// 0x10023529c: ldr w12, [x24, w14, uxtw #2]
	value368, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value368))
	// 0x1002352a0: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x1002352a4: str x2, [sp, #0x418]
	if err := s.storeValue(addOffset(s.sp, 1048), s.x[2], 8); err != nil {
		return err
	}
	// 0x1002352a8: add x10, x13, x2
	s.x[10] = uint64((s.x[13] + s.x[2]))
	// 0x1002352ac: ldrb w10, [x10]
	value372, err := s.load(s.x[10], 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value372))
	// 0x1002352b0: mov w13, #0xb1
	s.x[13] = uint64(uint32(uint64(0xb1)))
	// 0x1002352b4: eor w10, w10, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x1002352b8: ldrb w10, [x4, w10, uxtw]
	value375, err := s.load((s.x[4] + uint64(uint32(uint64(uint32(s.x[10]))))), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value375))
	// 0x1002352bc: eor w8, w9, w8, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x1002352c0: eor w9, w20, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[20])) ^ uint64(uint32(s.x[10])))))
	// 0x1002352c4: and w9, w9, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x1002352c8: add w9, w9, #0xd3c
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(0xd3c))))
	// 0x1002352cc: ldr x9, [x17, w9, uxtw #3]
	value380, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value380)
	// 0x1002352d0: mov w13, #0x33
	s.x[13] = uint64(uint32(uint64(0x33)))
	// 0x1002352d4: eor w10, w11, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x1002352d8: mov x11, #-0x535b
	s.x[11] = uint64(uint64(0xffffffffffffaca5))
	// 0x1002352dc: movk x11, #0x8280, lsl #16
	s.x[11] = uint64(insertBits(s.x[11], 0x8280, 16, 16, 64))
	// 0x1002352e0: add x26, x9, x11
	s.x[26] = uint64((s.x[9] + s.x[11]))
	// 0x1002352e4: ldr w9, [x26, w10, uxtw #2]
	value386, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value386))
	// 0x1002352e8: eor w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x1002352ec: ldr w10, [sp, #0x388]
	value388, err := s.load(addOffset(s.sp, 904), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value388))
	// 0x1002352f0: eor w10, w30, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[30])) ^ uint64(uint32(s.x[10])))))
	// 0x1002352f4: and w10, w10, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0xff))))
	// 0x1002352f8: ldur x11, [x29, #-0xe8]
	value391, err := s.load(addOffset(s.x[29], -232), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value391)
	// 0x1002352fc: add x11, x11, x2
	s.x[11] = uint64((s.x[11] + s.x[2]))
	// 0x100235300: ldrb w11, [x11]
	value393, err := s.load(s.x[11], 1)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value393))
	// 0x100235304: mov w12, #0x29
	s.x[12] = uint64(uint32(uint64(0x29)))
	// 0x100235308: eor w11, w11, w12
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x10023530c: ldur x12, [x29, #-0xf0]
	value396, err := s.load(addOffset(s.x[29], -240), 8)
	if err != nil {
		return err
	}
	s.x[12] = uint64(value396)
	// 0x100235310: ldrb w11, [x12, w11, uxtw]
	value397, err := s.load((s.x[12] + uint64(uint32(uint64(uint32(s.x[11]))))), 1)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value397))
	// 0x100235314: eor w11, w20, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[20])) ^ uint64(uint32(s.x[11])))))
	// 0x100235318: and w11, w11, #0xff
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x10023531c: add w11, w11, #0xbbe
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(0xbbe))))
	// 0x100235320: ldr x11, [x17, w11, uxtw #3]
	value401, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value401)
	// 0x100235324: mov x12, #-0x9c76
	s.x[12] = uint64(uint64(0xffffffffffff638a))
	// 0x100235328: movk x12, #0xb4d7, lsl #16
	s.x[12] = uint64(insertBits(s.x[12], 0xb4d7, 16, 16, 64))
	// 0x10023532c: add x2, x11, x12
	s.x[2] = uint64((s.x[11] + s.x[12]))
	// 0x100235330: ldr w10, [x2, w10, uxtw #2]
	value405, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value405))
	// 0x100235334: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235338: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x10023533c: mov w4, #0x48a9
	s.x[4] = uint64(uint32(uint64(0x48a9)))
	// 0x100235340: movk w4, #0xaf, lsl #16
	s.x[4] = uint64(uint32(insertBits(uint64(uint32(s.x[4])), 0xaf, 16, 16, 32)))
	// 0x100235344: and w9, w4, w10, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[10])), 4, 32))))
	// 0x100235348: mov w10, #0x8bd8
	s.x[10] = uint64(uint32(uint64(0x8bd8)))
	// 0x10023534c: movk w10, #0x73a0, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x73a0, 16, 16, 32)))
	// 0x100235350: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235354: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100235358: ldr w9, [sp, #0x2c4]
	value415, err := s.load(addOffset(s.sp, 708), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value415))
	// 0x10023535c: str w30, [sp, #0x3f8]
	if err := s.storeValue(addOffset(s.sp, 1016), uint64(uint32(s.x[30])), 4); err != nil {
		return err
	}
	// 0x100235360: eor w9, w9, w30
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[30])))))
	// 0x100235364: ubfx w10, w19, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[19])) >> 16) & bitMask(8, 32)))
	// 0x100235368: eor w11, w10, w27
	s.x[11] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x10023536c: ubfx w12, w9, #8, #8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) >> 8) & bitMask(8, 32)))
	// 0x100235370: ldr w14, [sp, #0x3c8]
	value421, err := s.load(addOffset(s.sp, 968), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value421))
	// 0x100235374: eor w14, w14, w12
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[12])))))
	// 0x100235378: sub w11, w10, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[11])))))
	// 0x10023537c: eor w11, w11, w14
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[14])))))
	// 0x100235380: eor w10, w10, w0
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x100235384: ldr w10, [x24, w10, uxtw #2]
	value426, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value426))
	// 0x100235388: eor w10, w11, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[10])))))
	// 0x10023538c: ldr w11, [sp, #0x3d0]
	value428, err := s.load(addOffset(s.sp, 976), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value428))
	// 0x100235390: str w25, [sp, #0x400]
	if err := s.storeValue(addOffset(s.sp, 1024), uint64(uint32(s.x[25])), 4); err != nil {
		return err
	}
	// 0x100235394: eor w11, w25, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[11])))))
	// 0x100235398: lsr w11, w11, #0x18
	s.x[11] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x18)), 32)))
	// 0x10023539c: eor w11, w11, #0x3e
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(0x3e))))
	// 0x1002353a0: ldr w11, [x22, w11, uxtw #2]
	value433, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value433))
	// 0x1002353a4: eor w10, w10, w11, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ rotateRight(uint64(uint32(s.x[11])), 23, 32))))
	// 0x1002353a8: eor w11, w12, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x1002353ac: ldr w11, [x26, w11, uxtw #2]
	value436, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value436))
	// 0x1002353b0: ldr w12, [sp, #0x38c]
	value437, err := s.load(addOffset(s.sp, 908), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value437))
	// 0x1002353b4: str w3, [sp, #0x3f4]
	if err := s.storeValue(addOffset(s.sp, 1012), uint64(uint32(s.x[3])), 4); err != nil {
		return err
	}
	// 0x1002353b8: eor w12, w3, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[12])))))
	// 0x1002353bc: and w12, w12, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x1002353c0: eor w12, w12, w7
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[7])))))
	// 0x1002353c4: ldr w12, [x2, w12, uxtw #2]
	value442, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value442))
	// 0x1002353c8: eor w11, w11, w12
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x1002353cc: and w12, w4, w12, lsr #4
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[12])), 4, 32))))
	// 0x1002353d0: eor w11, w11, w12
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x1002353d4: eor w11, w10, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x1002353d8: lsr w10, w9, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[9])), int(uint64(0x18)), 32)))
	// 0x1002353dc: ldr w10, [x22, w10, uxtw #2]
	value448, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value448))
	// 0x1002353e0: ubfx w12, w16, #0x10, #8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x1002353e4: eor w14, w12, w27
	s.x[14] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[27])))))
	// 0x1002353e8: sub w14, w12, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[12])) - uint64(uint32(s.x[14])))))
	// 0x1002353ec: eor w12, w12, w0
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[0])))))
	// 0x1002353f0: ldr w12, [x24, w12, uxtw #2]
	value453, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value453))
	// 0x1002353f4: ldr w17, [sp, #0x35c]
	value454, err := s.load(addOffset(s.sp, 860), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value454))
	// 0x1002353f8: eor w14, w17, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[14])))))
	// 0x1002353fc: ubfx w3, w15, #8, #8
	s.x[3] = uint64(uint32((uint64(uint32(s.x[15])) >> 8) & bitMask(8, 32)))
	// 0x100235400: eor w14, w14, w3
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[3])))))
	// 0x100235404: eor w10, w14, w10, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ rotateRight(uint64(uint32(s.x[10])), 23, 32))))
	// 0x100235408: eor w14, w3, w13
	s.x[14] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[13])))))
	// 0x10023540c: ldr w14, [x26, w14, uxtw #2]
	value460, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value460))
	// 0x100235410: eor w14, w12, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100235414: lsr w3, w19, #0x18
	s.x[3] = uint64(uint32(shiftRight(uint64(uint32(s.x[19])), int(uint64(0x18)), 32)))
	// 0x100235418: and w12, w19, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[19])) & uint64(0xff))))
	// 0x10023541c: ldr w12, [x2, w12, uxtw #2]
	value464, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value464))
	// 0x100235420: ldr w7, [x22, w3, uxtw #2]
	value465, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[7] = uint64(uint32(value465))
	// 0x100235424: eor w14, w14, w12
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[12])))))
	// 0x100235428: eor w3, w10, w14
	s.x[3] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x10023542c: ubfx w9, w9, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) >> 16) & bitMask(8, 32)))
	// 0x100235430: ubfx w10, w16, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100235434: eor w14, w9, w27
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[27])))))
	// 0x100235438: ldr w16, [sp, #0x350]
	value471, err := s.load(addOffset(s.sp, 848), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value471))
	// 0x10023543c: eor w16, w16, w10
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[10])))))
	// 0x100235440: sub w14, w9, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[14])))))
	// 0x100235444: eor w14, w16, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[14])))))
	// 0x100235448: eor w14, w14, w7, ror #23
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ rotateRight(uint64(uint32(s.x[7])), 23, 32))))
	// 0x10023544c: eor w9, w9, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x100235450: ldr w9, [x24, w9, uxtw #2]
	value477, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value477))
	// 0x100235454: eor w10, w10, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x100235458: ldr w10, [x26, w10, uxtw #2]
	value479, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value479))
	// 0x10023545c: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235460: and w10, w15, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[15])) & uint64(0xff))))
	// 0x100235464: ldr w10, [x2, w10, uxtw #2]
	value482, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value482))
	// 0x100235468: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x10023546c: eor w16, w14, w9
	s.x[16] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[9])))))
	// 0x100235470: mov w9, #0x4120
	s.x[9] = uint64(uint32(uint64(0x4120)))
	// 0x100235474: movk w9, #0x1c84, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x1c84, 16, 16, 32)))
	// 0x100235478: and w9, w9, w8, lsl #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & shiftLeft(uint64(uint32(s.x[8])), 1, 32))))
	// 0x10023547c: sub w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[9])))))
	// 0x100235480: mov w9, #0x2090
	s.x[9] = uint64(uint32(uint64(0x2090)))
	// 0x100235484: movk w9, #0xe42, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0xe42, 16, 16, 32)))
	// 0x100235488: add w15, w8, w9
	s.x[15] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[9])))))
	// 0x10023548c: mov w5, #0xdd
	s.x[5] = uint64(uint32(uint64(0xdd)))
	// 0x100235490: eor w8, w5, w15, lsr #24
	s.x[8] = uint64(uint32((uint64(uint32(s.x[5])) ^ shiftRight(uint64(uint32(s.x[15])), 24, 32))))
	// 0x100235494: ldr w8, [x22, w8, uxtw #2]
	value494, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value494))
	// 0x100235498: ldr w9, [sp, #0x348]
	value495, err := s.load(addOffset(s.sp, 840), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value495))
	// 0x10023549c: eor w14, w9, w8, ror #23
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x1002354a0: mov w8, #0x38ab
	s.x[8] = uint64(uint32(uint64(0x38ab)))
	// 0x1002354a4: movk w8, #0x6a62, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x6a62, 16, 16, 32)))
	// 0x1002354a8: eor w8, w11, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[8])))))
	// 0x1002354ac: ubfx w25, w8, #0x10, #8
	s.x[25] = uint64(uint32((uint64(uint32(s.x[8])) >> 16) & bitMask(8, 32)))
	// 0x1002354b0: eor w9, w25, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[0])))))
	// 0x1002354b4: ldr w30, [x24, w9, uxtw #2]
	value502, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[30] = uint64(uint32(value502))
	// 0x1002354b8: mov w9, #0x731b
	s.x[9] = uint64(uint32(uint64(0x731b)))
	// 0x1002354bc: movk w9, #0x8fa0, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x8fa0, 16, 16, 32)))
	// 0x1002354c0: eor w9, w14, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[9])))))
	// 0x1002354c4: mov w17, #0xe2e6
	s.x[17] = uint64(uint32(uint64(0xe2e6)))
	// 0x1002354c8: movk w17, #0xd783, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0xd783, 16, 16, 32)))
	// 0x1002354cc: eor w7, w30, w17
	s.x[7] = uint64(uint32((uint64(uint32(s.x[30])) ^ uint64(uint32(s.x[17])))))
	// 0x1002354d0: and w7, w9, w7
	s.x[7] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(uint32(s.x[7])))))
	// 0x1002354d4: mov w9, #0x3a72
	s.x[9] = uint64(uint32(uint64(0x3a72)))
	// 0x1002354d8: movk w9, #0xfe09, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0xfe09, 16, 16, 32)))
	// 0x1002354dc: eor w9, w30, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[30])) ^ uint64(uint32(s.x[9])))))
	// 0x1002354e0: mov w17, #0x6471
	s.x[17] = uint64(uint32(uint64(0x6471)))
	// 0x1002354e4: movk w17, #0x403e, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x403e, 16, 16, 32)))
	// 0x1002354e8: eor w19, w14, w17
	s.x[19] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[17])))))
	// 0x1002354ec: and w9, w19, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[19])) & uint64(uint32(s.x[9])))))
	// 0x1002354f0: and w10, w4, w10, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[10])), 4, 32))))
	// 0x1002354f4: mov w17, #0xcb3e
	s.x[17] = uint64(uint32(uint64(0xcb3e)))
	// 0x1002354f8: movk w17, #0x3875, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x3875, 16, 16, 32)))
	// 0x1002354fc: eor w19, w16, w17
	s.x[19] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[17])))))
	// 0x100235500: eor w16, w19, w10
	s.x[16] = uint64(uint32((uint64(uint32(s.x[19])) ^ uint64(uint32(s.x[10])))))
	// 0x100235504: and w10, w16, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x100235508: ldr w10, [x2, w10, uxtw #2]
	value523, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value523))
	// 0x10023550c: lsr w1, w10, #4
	s.x[1] = uint64(uint32(shiftRight(uint64(uint32(s.x[10])), int(uint64(0x4)), 32)))
	// 0x100235510: mov w17, #0x8a9
	s.x[17] = uint64(uint32(uint64(0x8a9)))
	// 0x100235514: movk w17, #0x26, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x26, 16, 16, 32)))
	// 0x100235518: and w28, w1, w17
	s.x[28] = uint64(uint32((uint64(uint32(s.x[1])) & uint64(uint32(s.x[17])))))
	// 0x10023551c: mov w17, #0x18f9
	s.x[17] = uint64(uint32(uint64(0x18f9)))
	// 0x100235520: movk w17, #0x9936, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x9936, 16, 16, 32)))
	// 0x100235524: and w17, w10, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[17])))))
	// 0x100235528: eor w17, w28, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[28])) ^ uint64(uint32(s.x[17])))))
	// 0x10023552c: mov w28, #0x4000
	s.x[28] = uint64(uint32(uint64(0x4000)))
	// 0x100235530: movk w28, #0x89, lsl #16
	s.x[28] = uint64(uint32(insertBits(uint64(uint32(s.x[28])), 0x89, 16, 16, 32)))
	// 0x100235534: and w1, w1, w28
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) & uint64(uint32(s.x[28])))))
	// 0x100235538: mov w28, #0xe706
	s.x[28] = uint64(uint32(uint64(0xe706)))
	// 0x10023553c: movk w28, #0x66c9, lsl #16
	s.x[28] = uint64(uint32(insertBits(uint64(uint32(s.x[28])), 0x66c9, 16, 16, 32)))
	// 0x100235540: and w10, w10, w28
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[28])))))
	// 0x100235544: mov w28, #0x51a3
	s.x[28] = uint64(uint32(uint64(0x51a3)))
	// 0x100235548: movk w28, #0x9fd, lsl #16
	s.x[28] = uint64(uint32(insertBits(uint64(uint32(s.x[28])), 0x9fd, 16, 16, 32)))
	// 0x10023554c: eor w10, w10, w28
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[28])))))
	// 0x100235550: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x100235554: eor w1, w17, #0xffffff9f
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(0xffffff9f))))
	// 0x100235558: and w10, w1, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[1])) & uint64(uint32(s.x[10])))))
	// 0x10023555c: mov w1, #0x858
	s.x[1] = uint64(uint32(uint64(0x858)))
	// 0x100235560: movk w1, #0x9002, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x9002, 16, 16, 32)))
	// 0x100235564: and w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) & uint64(uint32(s.x[1])))))
	// 0x100235568: orr w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) | uint64(uint32(s.x[17])))))
	// 0x10023556c: ubfx w17, w16, #8, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100235570: eor w1, w17, w13
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[13])))))
	// 0x100235574: ldr w1, [x26, w1, uxtw #2]
	value550, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value550))
	// 0x100235578: mov w28, #0xe895
	s.x[28] = uint64(uint32(uint64(0xe895)))
	// 0x10023557c: movk w28, #0x3061, lsl #16
	s.x[28] = uint64(uint32(insertBits(uint64(uint32(s.x[28])), 0x3061, 16, 16, 32)))
	// 0x100235580: and w28, w30, w28
	s.x[28] = uint64(uint32((uint64(uint32(s.x[30])) & uint64(uint32(s.x[28])))))
	// 0x100235584: adrp x30, #0x10105b000
	s.x[30] = uint64(0x10105b000)
	// 0x100235588: add x30, x30, #0x6f0
	s.x[30] = uint64((s.x[30] + uint64(0x6f0)))
	// 0x10023558c: eor w1, w28, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[28])) ^ uint64(uint32(s.x[1])))))
	// 0x100235590: and w12, w4, w12, lsr #4
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[12])), 4, 32))))
	// 0x100235594: mov w28, #0x544b
	s.x[28] = uint64(uint32(uint64(0x544b)))
	// 0x100235598: movk w28, #0xdcc9, lsl #16
	s.x[28] = uint64(uint32(insertBits(uint64(uint32(s.x[28])), 0xdcc9, 16, 16, 32)))
	// 0x10023559c: eor w3, w3, w28
	s.x[3] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[28])))))
	// 0x1002355a0: eor w28, w3, w12
	s.x[28] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[12])))))
	// 0x1002355a4: mov w12, #0x276b
	s.x[12] = uint64(uint32(uint64(0x276b)))
	// 0x1002355a8: movk w12, #0xd675, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xd675, 16, 16, 32)))
	// 0x1002355ac: and w12, w14, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[14])) & uint64(uint32(s.x[12])))))
	// 0x1002355b0: and w14, w28, #0xff
	s.x[14] = uint64(uint32((uint64(uint32(s.x[28])) & uint64(0xff))))
	// 0x1002355b4: ldr w14, [x2, w14, uxtw #2]
	value566, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value566))
	// 0x1002355b8: eor w1, w1, w14
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[14])))))
	// 0x1002355bc: eor w12, w1, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[12])))))
	// 0x1002355c0: eor w12, w12, w7
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[7])))))
	// 0x1002355c4: and w14, w4, w14, lsr #4
	s.x[14] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[14])), 4, 32))))
	// 0x1002355c8: eor w9, w9, w14
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x1002355cc: eor w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x1002355d0: eor w12, w25, w27
	s.x[12] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[27])))))
	// 0x1002355d4: sub w12, w25, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[25])) - uint64(uint32(s.x[12])))))
	// 0x1002355d8: eor w12, w17, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[12])))))
	// 0x1002355dc: mov w14, #0x5bd4
	s.x[14] = uint64(uint32(uint64(0x5bd4)))
	// 0x1002355e0: movk w14, #0x3459, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x3459, 16, 16, 32)))
	// 0x1002355e4: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x1002355e8: eor w14, w9, w12
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x1002355ec: lsr w9, w3, #0x18
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[3])), int(uint64(0x18)), 32)))
	// 0x1002355f0: ldr w9, [x22, w9, uxtw #2]
	value581, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value581))
	// 0x1002355f4: ubfx w12, w15, #0x10, #8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[15])) >> 16) & bitMask(8, 32)))
	// 0x1002355f8: eor w17, w12, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[27])))))
	// 0x1002355fc: sub w17, w12, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[12])) - uint64(uint32(s.x[17])))))
	// 0x100235600: eor w12, w12, w0
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[0])))))
	// 0x100235604: ldr w12, [x24, w12, uxtw #2]
	value586, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value586))
	// 0x100235608: ldr w1, [sp, #0x3cc]
	value587, err := s.load(addOffset(s.sp, 972), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value587))
	// 0x10023560c: eor w17, w1, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[17])))))
	// 0x100235610: eor w12, w17, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[12])))))
	// 0x100235614: eor w9, w12, w9, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ rotateRight(uint64(uint32(s.x[9])), 23, 32))))
	// 0x100235618: ubfx w12, w8, #8, #8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[8])) >> 8) & bitMask(8, 32)))
	// 0x10023561c: eor w17, w12, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x100235620: ldr w17, [x26, w17, uxtw #2]
	value593, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value593))
	// 0x100235624: eor w12, w17, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[12])))))
	// 0x100235628: eor w10, w12, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x10023562c: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235630: ubfx w9, w28, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[28])) >> 16) & bitMask(8, 32)))
	// 0x100235634: eor w12, w9, w27
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[27])))))
	// 0x100235638: sub w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[12])))))
	// 0x10023563c: eor w9, w9, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x100235640: ldr w9, [x24, w9, uxtw #2]
	value601, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value601))
	// 0x100235644: ldr w17, [sp, #0x344]
	value602, err := s.load(addOffset(s.sp, 836), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value602))
	// 0x100235648: eor w12, w17, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[12])))))
	// 0x10023564c: ubfx w17, w15, #8, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[15])) >> 8) & bitMask(8, 32)))
	// 0x100235650: eor w12, w12, w17
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[17])))))
	// 0x100235654: eor w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x100235658: lsr w12, w19, #0x18
	s.x[12] = uint64(uint32(shiftRight(uint64(uint32(s.x[19])), int(uint64(0x18)), 32)))
	// 0x10023565c: ldr w12, [x22, w12, uxtw #2]
	value608, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value608))
	// 0x100235660: eor w12, w9, w12, ror #23
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ rotateRight(uint64(uint32(s.x[12])), 23, 32))))
	// 0x100235664: eor w9, w17, w13
	s.x[9] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[13])))))
	// 0x100235668: ldr w17, [x26, w9, uxtw #2]
	value611, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value611))
	// 0x10023566c: and w9, w11, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x100235670: mov w11, #0x93
	s.x[11] = uint64(uint32(uint64(0x93)))
	// 0x100235674: eor w9, w9, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100235678: ldr w9, [x2, w9, uxtw #2]
	value615, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value615))
	// 0x10023567c: eor w11, w12, w17
	s.x[11] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[17])))))
	// 0x100235680: mov w12, #0x12fd
	s.x[12] = uint64(uint32(uint64(0x12fd)))
	// 0x100235684: movk w12, #0xd84d, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xd84d, 16, 16, 32)))
	// 0x100235688: eor w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x10023568c: eor w12, w11, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x100235690: ubfx w11, w16, #0x10, #8
	s.x[11] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x100235694: ubfx w16, w28, #8, #8
	s.x[16] = uint64(uint32((uint64(uint32(s.x[28])) >> 8) & bitMask(8, 32)))
	// 0x100235698: eor w17, w11, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[27])))))
	// 0x10023569c: ldr w1, [sp, #0x340]
	value624, err := s.load(addOffset(s.sp, 832), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value624))
	// 0x1002356a0: eor w1, w1, w16
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[16])))))
	// 0x1002356a4: sub w17, w11, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[11])) - uint64(uint32(s.x[17])))))
	// 0x1002356a8: eor w17, w1, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[17])))))
	// 0x1002356ac: lsr w8, w8, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x18)), 32)))
	// 0x1002356b0: ldr w8, [x22, w8, uxtw #2]
	value629, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value629))
	// 0x1002356b4: eor w11, w11, w0
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[0])))))
	// 0x1002356b8: ldr w11, [x24, w11, uxtw #2]
	value631, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value631))
	// 0x1002356bc: eor w16, w16, w13
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[13])))))
	// 0x1002356c0: ldr w16, [x26, w16, uxtw #2]
	value633, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value633))
	// 0x1002356c4: eor w8, w17, w8, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x1002356c8: eor w11, w11, w16
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[16])))))
	// 0x1002356cc: eor w16, w8, w11
	s.x[16] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[11])))))
	// 0x1002356d0: mov w8, #0x2d0d
	s.x[8] = uint64(uint32(uint64(0x2d0d)))
	// 0x1002356d4: movk w8, #0x9fae, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x9fae, 16, 16, 32)))
	// 0x1002356d8: eor w8, w8, w14, ror #9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ rotateRight(uint64(uint32(s.x[14])), 9, 32))))
	// 0x1002356dc: mov w11, #0xc373
	s.x[11] = uint64(uint32(uint64(0xc373)))
	// 0x1002356e0: movk w11, #0x5fa4, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x5fa4, 16, 16, 32)))
	// 0x1002356e4: eor w11, w11, w8, ror #23
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x1002356e8: mov w8, #0x7ad0
	s.x[8] = uint64(uint32(uint64(0x7ad0)))
	// 0x1002356ec: movk w8, #0x11fe, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x11fe, 16, 16, 32)))
	// 0x1002356f0: eor w8, w10, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[8])))))
	// 0x1002356f4: lsr w10, w8, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x18)), 32)))
	// 0x1002356f8: ldr w10, [x22, w10, uxtw #2]
	value647, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value647))
	// 0x1002356fc: ldr w14, [sp, #0x33c]
	value648, err := s.load(addOffset(s.sp, 828), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value648))
	// 0x100235700: eor w10, w14, w10, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ rotateRight(uint64(uint32(s.x[10])), 23, 32))))
	// 0x100235704: ubfx w14, w11, #0x10, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[11])) >> 16) & bitMask(8, 32)))
	// 0x100235708: eor w17, w14, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[27])))))
	// 0x10023570c: sub w17, w14, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[14])) - uint64(uint32(s.x[17])))))
	// 0x100235710: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x100235714: and w15, w15, #0xff
	s.x[15] = uint64(uint32((uint64(uint32(s.x[15])) & uint64(0xff))))
	// 0x100235718: eor w15, w15, #0x38
	s.x[15] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(0x38))))
	// 0x10023571c: ldr w15, [x2, w15, uxtw #2]
	value656, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value656))
	// 0x100235720: mov w17, #0x8eb5
	s.x[17] = uint64(uint32(uint64(0x8eb5)))
	// 0x100235724: movk w17, #0xb886, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0xb886, 16, 16, 32)))
	// 0x100235728: eor w16, w16, w17
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[17])))))
	// 0x10023572c: eor w3, w16, w15
	s.x[3] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[15])))))
	// 0x100235730: and w15, w4, w15, lsr #4
	s.x[15] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[15])), 4, 32))))
	// 0x100235734: eor w14, w14, w0
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[0])))))
	// 0x100235738: ldr w14, [x24, w14, uxtw #2]
	value663, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value663))
	// 0x10023573c: eor w16, w3, w15
	s.x[16] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[15])))))
	// 0x100235740: mov w15, #0x6d78
	s.x[15] = uint64(uint32(uint64(0x6d78)))
	// 0x100235744: movk w15, #0xd85a, lsl #16
	s.x[15] = uint64(uint32(insertBits(uint64(uint32(s.x[15])), 0xd85a, 16, 16, 32)))
	// 0x100235748: eor w10, w10, w15
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[15])))))
	// 0x10023574c: ubfx w15, w16, #8, #8
	s.x[15] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100235750: eor w17, w15, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[13])))))
	// 0x100235754: ldr w17, [x26, w17, uxtw #2]
	value670, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value670))
	// 0x100235758: eor w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x10023575c: mov w14, #0xd4b1
	s.x[14] = uint64(uint32(uint64(0xd4b1)))
	// 0x100235760: movk w14, #0x91e3, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x91e3, 16, 16, 32)))
	// 0x100235764: eor w14, w15, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[14])))))
	// 0x100235768: eor w14, w17, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[14])))))
	// 0x10023576c: and w15, w14, w10
	s.x[15] = uint64(uint32((uint64(uint32(s.x[14])) & uint64(uint32(s.x[10])))))
	// 0x100235770: add w10, w14, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) + uint64(uint32(s.x[10])))))
	// 0x100235774: sub w15, w10, w15, lsl #1
	s.x[15] = uint64(uint32((uint64(uint32(s.x[10])) - shiftLeft(uint64(uint32(s.x[15])), 1, 32))))
	// 0x100235778: and w9, w4, w9, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[9])), 4, 32))))
	// 0x10023577c: eor w14, w12, w9
	s.x[14] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x100235780: lsr w9, w12, #0x18
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[12])), int(uint64(0x18)), 32)))
	// 0x100235784: ldr w9, [x22, w9, uxtw #2]
	value682, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value682))
	// 0x100235788: ubfx w10, w8, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[8])) >> 16) & bitMask(8, 32)))
	// 0x10023578c: eor w12, w10, w27
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x100235790: sub w12, w10, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[12])))))
	// 0x100235794: ldr w17, [sp, #0x338]
	value686, err := s.load(addOffset(s.sp, 824), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value686))
	// 0x100235798: eor w12, w17, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[12])))))
	// 0x10023579c: ubfx w17, w11, #8, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[11])) >> 8) & bitMask(8, 32)))
	// 0x1002357a0: eor w12, w12, w17
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[17])))))
	// 0x1002357a4: eor w9, w12, w9, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ rotateRight(uint64(uint32(s.x[9])), 23, 32))))
	// 0x1002357a8: eor w10, w10, w0
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x1002357ac: ldr w10, [x24, w10, uxtw #2]
	value692, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value692))
	// 0x1002357b0: and w12, w16, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x1002357b4: ldr w12, [x2, w12, uxtw #2]
	value694, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value694))
	// 0x1002357b8: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x1002357bc: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002357c0: eor w10, w17, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[13])))))
	// 0x1002357c4: ldr w10, [x26, w10, uxtw #2]
	value698, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value698))
	// 0x1002357c8: eor w25, w9, w10
	s.x[25] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002357cc: ubfx w9, w16, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x1002357d0: eor w10, w9, w0
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x1002357d4: ldr w10, [x24, w10, uxtw #2]
	value702, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value702))
	// 0x1002357d8: ubfx w16, w14, #8, #8
	s.x[16] = uint64(uint32((uint64(uint32(s.x[14])) >> 8) & bitMask(8, 32)))
	// 0x1002357dc: eor w17, w16, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[13])))))
	// 0x1002357e0: ldr w17, [x26, w17, uxtw #2]
	value705, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value705))
	// 0x1002357e4: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x1002357e8: and w17, w8, #0xff
	s.x[17] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x1002357ec: ldr w17, [x2, w17, uxtw #2]
	value708, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value708))
	// 0x1002357f0: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x1002357f4: and w17, w4, w17, lsr #4
	s.x[17] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[17])), 4, 32))))
	// 0x1002357f8: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x1002357fc: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x100235800: eor w16, w9, w27
	s.x[16] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[27])))))
	// 0x100235804: sub w9, w9, w16
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[16])))))
	// 0x100235808: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x10023580c: lsr w10, w11, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x18)), 32)))
	// 0x100235810: ldr w10, [x22, w10, uxtw #2]
	value717, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value717))
	// 0x100235814: ldr w16, [sp, #0x334]
	value718, err := s.load(addOffset(s.sp, 820), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value718))
	// 0x100235818: eor w10, w16, w10, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) ^ rotateRight(uint64(uint32(s.x[10])), 23, 32))))
	// 0x10023581c: mov w16, #0xd678
	s.x[16] = uint64(uint32(uint64(0xd678)))
	// 0x100235820: movk w16, #0x3923, lsl #16
	s.x[16] = uint64(uint32(insertBits(uint64(uint32(s.x[16])), 0x3923, 16, 16, 32)))
	// 0x100235824: eor w9, w9, w16
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[16])))))
	// 0x100235828: eor w19, w10, w9
	s.x[19] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x10023582c: and w9, w14, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) & uint64(0xff))))
	// 0x100235830: ldr w9, [x2, w9, uxtw #2]
	value725, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value725))
	// 0x100235834: and w10, w4, w9, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[9])), 4, 32))))
	// 0x100235838: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x10023583c: mov w10, #0xc9a0
	s.x[10] = uint64(uint32(uint64(0xc9a0)))
	// 0x100235840: movk w10, #0xf323, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xf323, 16, 16, 32)))
	// 0x100235844: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235848: eor w16, w9, w15
	s.x[16] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[15])))))
	// 0x10023584c: and w9, w4, w12, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[12])), 4, 32))))
	// 0x100235850: eor w15, w25, w9
	s.x[15] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[9])))))
	// 0x100235854: lsr w9, w19, #0x10
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[19])), int(uint64(0x10)), 32)))
	// 0x100235858: and w9, w9, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0x8))))
	// 0x10023585c: mov w10, #0xe4e1
	s.x[10] = uint64(uint32(uint64(0xe4e1)))
	// 0x100235860: movk w10, #0x6e17, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x6e17, 16, 16, 32)))
	// 0x100235864: eor w10, w15, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[10])))))
	// 0x100235868: lsr w10, w10, w9
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[10])), int(uint64(uint32(s.x[9]))), 32)))
	// 0x10023586c: mov w12, #0x9d0c
	s.x[12] = uint64(uint32(uint64(0x9d0c)))
	// 0x100235870: movk w12, #0xdadc, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xdadc, 16, 16, 32)))
	// 0x100235874: and w12, w12, w10, lsl #1
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & shiftLeft(uint64(uint32(s.x[10])), 1, 32))))
	// 0x100235878: sub w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[12])))))
	// 0x10023587c: mov w12, #0x4e86
	s.x[12] = uint64(uint32(uint64(0x4e86)))
	// 0x100235880: movk w12, #0xed6e, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xed6e, 16, 16, 32)))
	// 0x100235884: add w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[12])))))
	// 0x100235888: eor w9, w9, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(0x8))))
	// 0x10023588c: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100235890: lsr w12, w10, w9
	s.x[12] = uint64(uint32(shiftRight(uint64(uint32(s.x[10])), int(uint64(uint32(s.x[9]))), 32)))
	// 0x100235894: ubfx w9, w14, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) >> 16) & bitMask(8, 32)))
	// 0x100235898: mov w10, #0x7a55
	s.x[10] = uint64(uint32(uint64(0x7a55)))
	// 0x10023589c: movk w10, #0x3c9e, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x3c9e, 16, 16, 32)))
	// 0x1002358a0: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002358a4: sub w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[10])))))
	// 0x1002358a8: and w10, w10, #0x7fffffff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0x7fffffff))))
	// 0x1002358ac: ubfx w8, w8, #8, #8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) >> 8) & bitMask(8, 32)))
	// 0x1002358b0: ldr w14, [sp, #0x330]
	value757, err := s.load(addOffset(s.sp, 816), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value757))
	// 0x1002358b4: eor w14, w14, w8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[8])))))
	// 0x1002358b8: eor w10, w14, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[10])))))
	// 0x1002358bc: lsr w14, w3, #0x18
	s.x[14] = uint64(uint32(shiftRight(uint64(uint32(s.x[3])), int(uint64(0x18)), 32)))
	// 0x1002358c0: ldr w14, [x22, w14, uxtw #2]
	value761, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value761))
	// 0x1002358c4: eor w10, w10, w14, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ rotateRight(uint64(uint32(s.x[14])), 23, 32))))
	// 0x1002358c8: eor w9, w9, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x1002358cc: ldr w9, [x24, w9, uxtw #2]
	value764, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value764))
	// 0x1002358d0: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x1002358d4: eor w8, w8, w13
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[13])))))
	// 0x1002358d8: ldr w8, [x26, w8, uxtw #2]
	value767, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value767))
	// 0x1002358dc: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x1002358e0: and w9, w11, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x1002358e4: ldr w9, [x2, w9, uxtw #2]
	value770, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value770))
	// 0x1002358e8: mov w10, #0xc2bb
	s.x[10] = uint64(uint32(uint64(0xc2bb)))
	// 0x1002358ec: movk w10, #0x5c5d, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x5c5d, 16, 16, 32)))
	// 0x1002358f0: eor w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x1002358f4: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x1002358f8: lsr w10, w8, #0x1b
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x1b)), 32)))
	// 0x1002358fc: mov w11, #0x4925
	s.x[11] = uint64(uint32(uint64(0x4925)))
	// 0x100235900: movk w11, #0x2492, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x2492, 16, 16, 32)))
	// 0x100235904: umull x11, w10, w11
	s.x[11] = uint64(uint64(uint32(uint64(uint32(s.x[10])))) * uint64(uint32(uint64(uint32(s.x[11])))))
	// 0x100235908: lsr x11, x11, #0x20
	s.x[11] = uint64(shiftRight(s.x[11], int(uint64(0x20)), 64))
	// 0x10023590c: lsl w14, w11, #6
	s.x[14] = uint64(uint32(shiftLeft(uint64(uint32(s.x[11])), int(uint64(0x6)), 32)))
	// 0x100235910: sub w14, w14, w11, lsl #3
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) - shiftLeft(uint64(uint32(s.x[11])), 3, 32))))
	// 0x100235914: and w9, w4, w9, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[9])), 4, 32))))
	// 0x100235918: eor w11, w8, w9
	s.x[11] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x10023591c: lsr w8, w8, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x18)), 32)))
	// 0x100235920: mov w9, #0x25
	s.x[9] = uint64(uint32(uint64(0x25)))
	// 0x100235924: mul w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) * uint64(uint32(s.x[9])))))
	// 0x100235928: lsr w9, w9, #8
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[9])), int(uint64(0x8)), 32)))
	// 0x10023592c: mov w10, #0x38
	s.x[10] = uint64(uint32(uint64(0x38)))
	// 0x100235930: msub w8, w9, w10, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[9]))*uint64(uint32(s.x[10])))))
	// 0x100235934: and w9, w14, #0xf8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) & uint64(0xf8))))
	// 0x100235938: add w9, w9, w8, uxtb
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint8(uint64(uint32(s.x[8])))))))
	// 0x10023593c: ubfx w8, w16, #0x10, #8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x100235940: eor w10, w8, w27
	s.x[10] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[27])))))
	// 0x100235944: ubfx w14, w19, #8, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[19])) >> 8) & bitMask(8, 32)))
	// 0x100235948: ldr w17, [sp, #0x3e4]
	value795, err := s.load(addOffset(s.sp, 996), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value795))
	// 0x10023594c: eor w17, w14, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[17])))))
	// 0x100235950: sub w10, w8, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[10])))))
	// 0x100235954: eor w10, w17, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[10])))))
	// 0x100235958: mov w17, #0xb3
	s.x[17] = uint64(uint32(uint64(0xb3)))
	// 0x10023595c: eor w17, w17, w25, lsr #24
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ shiftRight(uint64(uint32(s.x[25])), 24, 32))))
	// 0x100235960: ldr w17, [x22, w17, uxtw #2]
	value801, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value801))
	// 0x100235964: eor w10, w10, w17, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ rotateRight(uint64(uint32(s.x[17])), 23, 32))))
	// 0x100235968: eor w14, w14, w13
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x10023596c: ldr w14, [x26, w14, uxtw #2]
	value804, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value804))
	// 0x100235970: eor w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100235974: eor w8, w8, w0
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[0])))))
	// 0x100235978: ldr w8, [x24, w8, uxtw #2]
	value807, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value807))
	// 0x10023597c: eor w3, w10, w8
	s.x[3] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[8])))))
	// 0x100235980: ubfx w10, w15, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[15])) >> 16) & bitMask(8, 32)))
	// 0x100235984: eor w8, w10, w6
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[6])))))
	// 0x100235988: mov w14, #0x7a42
	s.x[14] = uint64(uint32(uint64(0x7a42)))
	// 0x10023598c: movk w14, #0xbc9e, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0xbc9e, 16, 16, 32)))
	// 0x100235990: eor w14, w10, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100235994: sub w14, w8, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[14])))))
	// 0x100235998: lsr w8, w19, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[19])), int(uint64(0x18)), 32)))
	// 0x10023599c: ldr w8, [x22, w8, uxtw #2]
	value816, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value816))
	// 0x1002359a0: ubfx w17, w11, #0x10, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[11])) >> 16) & bitMask(8, 32)))
	// 0x1002359a4: eor w1, w17, w0
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[0])))))
	// 0x1002359a8: ldr w1, [x24, w1, uxtw #2]
	value819, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value819))
	// 0x1002359ac: and w7, w16, #0xff
	s.x[7] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x1002359b0: ldr w7, [x2, w7, uxtw #2]
	value821, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[7])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[7] = uint64(uint32(value821))
	// 0x1002359b4: ldr w6, [sp, #0x3dc]
	value822, err := s.load(addOffset(s.sp, 988), 4)
	if err != nil {
		return err
	}
	s.x[6] = uint64(uint32(value822))
	// 0x1002359b8: eor w8, w6, w8, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[6])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x1002359bc: eor w8, w8, w1
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[1])))))
	// 0x1002359c0: eor w8, w8, w7
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[7])))))
	// 0x1002359c4: and w1, w4, w7, lsr #4
	s.x[1] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[7])), 4, 32))))
	// 0x1002359c8: eor w8, w8, w1
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[1])))))
	// 0x1002359cc: and w12, w12, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x1002359d0: eor w8, w8, w12
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[12])))))
	// 0x1002359d4: eor w1, w17, w27
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[27])))))
	// 0x1002359d8: sub w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) - uint64(uint32(s.x[1])))))
	// 0x1002359dc: eor w8, w8, w17
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[17])))))
	// 0x1002359e0: eor w12, w12, w13
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x1002359e4: ldr w12, [x26, w12, uxtw #2]
	value834, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value834))
	// 0x1002359e8: mov w17, #0x2068
	s.x[17] = uint64(uint32(uint64(0x2068)))
	// 0x1002359ec: movk w17, #0x3da3, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x3da3, 16, 16, 32)))
	// 0x1002359f0: eor w8, w8, w17
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[17])))))
	// 0x1002359f4: eor w8, w8, w12
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[12])))))
	// 0x1002359f8: eor w9, w9, w5
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[5])))))
	// 0x1002359fc: ldr w9, [x22, w9, uxtw #2]
	value840, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value840))
	// 0x100235a00: ldr w12, [sp, #0x328]
	value841, err := s.load(addOffset(s.sp, 808), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value841))
	// 0x100235a04: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100235a08: ubfx w14, w16, #8, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100235a0c: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100235a10: eor w9, w12, w9, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ rotateRight(uint64(uint32(s.x[9])), 23, 32))))
	// 0x100235a14: mov w12, #0x82
	s.x[12] = uint64(uint32(uint64(0x82)))
	// 0x100235a18: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100235a1c: ldr w12, [x24, w10, uxtw #2]
	value848, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value848))
	// 0x100235a20: eor w10, w14, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x100235a24: ldr w14, [x26, w10, uxtw #2]
	value850, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value850))
	// 0x100235a28: and w10, w19, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[19])) & uint64(0xff))))
	// 0x100235a2c: ldr w10, [x2, w10, uxtw #2]
	value852, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value852))
	// 0x100235a30: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100235a34: eor w12, w12, w10
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100235a38: eor w25, w9, w12
	s.x[25] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x100235a3c: ubfx w9, w19, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[19])) >> 16) & bitMask(8, 32)))
	// 0x100235a40: eor w12, w9, w27
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[27])))))
	// 0x100235a44: sub w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[12])))))
	// 0x100235a48: eor w9, w9, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x100235a4c: ldr w9, [x24, w9, uxtw #2]
	value860, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value860))
	// 0x100235a50: ldr w14, [sp, #0x3bc]
	value861, err := s.load(addOffset(s.sp, 956), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value861))
	// 0x100235a54: eor w12, w14, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[12])))))
	// 0x100235a58: eor w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x100235a5c: lsr w12, w16, #0x18
	s.x[12] = uint64(uint32(shiftRight(uint64(uint32(s.x[16])), int(uint64(0x18)), 32)))
	// 0x100235a60: ldr w12, [x22, w12, uxtw #2]
	value865, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value865))
	// 0x100235a64: ubfx w14, w11, #8, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[11])) >> 8) & bitMask(8, 32)))
	// 0x100235a68: eor w14, w14, w13
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x100235a6c: ldr w14, [x26, w14, uxtw #2]
	value868, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value868))
	// 0x100235a70: eor w9, w9, w12, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ rotateRight(uint64(uint32(s.x[12])), 23, 32))))
	// 0x100235a74: and w12, w15, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[15])) & uint64(0xff))))
	// 0x100235a78: mov w6, #0xd9
	s.x[6] = uint64(uint32(uint64(0xd9)))
	// 0x100235a7c: eor w12, w12, w6
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[6])))))
	// 0x100235a80: ldr w12, [x2, w12, uxtw #2]
	value873, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value873))
	// 0x100235a84: eor w14, w14, w12
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[12])))))
	// 0x100235a88: mov w15, #0x2cfa
	s.x[15] = uint64(uint32(uint64(0x2cfa)))
	// 0x100235a8c: movk w15, #0x458d, lsl #16
	s.x[15] = uint64(uint32(insertBits(uint64(uint32(s.x[15])), 0x458d, 16, 16, 32)))
	// 0x100235a90: eor w14, w14, w15
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[15])))))
	// 0x100235a94: eor w9, w9, w14
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x100235a98: and w12, w4, w12, lsr #4
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[12])), 4, 32))))
	// 0x100235a9c: lsr w14, w9, #0x18
	s.x[14] = uint64(uint32(shiftRight(uint64(uint32(s.x[9])), int(uint64(0x18)), 32)))
	// 0x100235aa0: ldr w15, [x22, w14, uxtw #2]
	value881, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value881))
	// 0x100235aa4: eor w14, w9, w12
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x100235aa8: ubfx w9, w8, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) >> 16) & bitMask(8, 32)))
	// 0x100235aac: eor w12, w9, w27
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[27])))))
	// 0x100235ab0: sub w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[12])))))
	// 0x100235ab4: ldr w16, [sp, #0x320]
	value886, err := s.load(addOffset(s.sp, 800), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value886))
	// 0x100235ab8: eor w12, w16, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[12])))))
	// 0x100235abc: eor w12, w12, w15, ror #23
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ rotateRight(uint64(uint32(s.x[15])), 23, 32))))
	// 0x100235ac0: and w15, w11, #0xff
	s.x[15] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x100235ac4: ldr w15, [x2, w15, uxtw #2]
	value890, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value890))
	// 0x100235ac8: eor w9, w9, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x100235acc: ldr w9, [x24, w9, uxtw #2]
	value892, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value892))
	// 0x100235ad0: eor w12, w12, w9
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x100235ad4: eor w16, w3, w15
	s.x[16] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[15])))))
	// 0x100235ad8: and w9, w4, w15, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[15])), 4, 32))))
	// 0x100235adc: eor w9, w16, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[9])))))
	// 0x100235ae0: and w10, w4, w10, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[10])), 4, 32))))
	// 0x100235ae4: eor w3, w25, w10
	s.x[3] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[10])))))
	// 0x100235ae8: ubfx w10, w3, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[3])) >> 8) & bitMask(8, 32)))
	// 0x100235aec: eor w15, w10, #6
	s.x[15] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(0x6))))
	// 0x100235af0: ldr w15, [x26, w15, uxtw #2]
	value901, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value901))
	// 0x100235af4: and w17, w9, #0xff
	s.x[17] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x100235af8: mov w28, #0x88
	s.x[28] = uint64(uint32(uint64(0x88)))
	// 0x100235afc: eor w17, w17, w28
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[28])))))
	// 0x100235b00: ldr w17, [x2, w17, uxtw #2]
	value905, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value905))
	// 0x100235b04: eor w12, w12, w17
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[17])))))
	// 0x100235b08: eor w15, w12, w15
	s.x[15] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[15])))))
	// 0x100235b0c: and w12, w4, w17, lsr #4
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[17])), 4, 32))))
	// 0x100235b10: eor w12, w10, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100235b14: mov w10, #0xca
	s.x[10] = uint64(uint32(uint64(0xca)))
	// 0x100235b18: eor w10, w10, w16, lsr #24
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[16])), 24, 32))))
	// 0x100235b1c: ldr w10, [x22, w10, uxtw #2]
	value912, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value912))
	// 0x100235b20: ubfx w16, w14, #0x10, #8
	s.x[16] = uint64(uint32((uint64(uint32(s.x[14])) >> 16) & bitMask(8, 32)))
	// 0x100235b24: eor w17, w16, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[27])))))
	// 0x100235b28: sub w17, w16, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) - uint64(uint32(s.x[17])))))
	// 0x100235b2c: eor w16, w16, w0
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[0])))))
	// 0x100235b30: ldr w16, [x24, w16, uxtw #2]
	value917, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value917))
	// 0x100235b34: ldr w1, [sp, #0x318]
	value918, err := s.load(addOffset(s.sp, 792), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value918))
	// 0x100235b38: eor w17, w1, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[17])))))
	// 0x100235b3c: ubfx w1, w8, #8, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[8])) >> 8) & bitMask(8, 32)))
	// 0x100235b40: eor w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x100235b44: eor w10, w17, w10, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[10])), 23, 32))))
	// 0x100235b48: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x100235b4c: eor w16, w1, w13
	s.x[16] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[13])))))
	// 0x100235b50: ldr w16, [x26, w16, uxtw #2]
	value925, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value925))
	// 0x100235b54: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x100235b58: lsr w11, w11, #8
	s.x[11] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x8)), 32)))
	// 0x100235b5c: eor w11, w14, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[11])))))
	// 0x100235b60: ubfx w14, w14, #8, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) >> 8) & bitMask(8, 32)))
	// 0x100235b64: ubfx w16, w9, #0x10, #8
	s.x[16] = uint64(uint32((uint64(uint32(s.x[9])) >> 16) & bitMask(8, 32)))
	// 0x100235b68: mov w17, #0xd6
	s.x[17] = uint64(uint32(uint64(0xd6)))
	// 0x100235b6c: eor w17, w16, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[17])))))
	// 0x100235b70: mov w1, #0x7a83
	s.x[1] = uint64(uint32(uint64(0x7a83)))
	// 0x100235b74: movk w1, #0xbc9e, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0xbc9e, 16, 16, 32)))
	// 0x100235b78: eor w1, w16, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[1])))))
	// 0x100235b7c: ldr w5, [sp, #0x314]
	value936, err := s.load(addOffset(s.sp, 788), 4)
	if err != nil {
		return err
	}
	s.x[5] = uint64(uint32(value936))
	// 0x100235b80: eor w7, w5, w14
	s.x[7] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[14])))))
	// 0x100235b84: sub w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) - uint64(uint32(s.x[1])))))
	// 0x100235b88: eor w17, w7, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[17])))))
	// 0x100235b8c: mov w1, #0xa2
	s.x[1] = uint64(uint32(uint64(0xa2)))
	// 0x100235b90: eor w1, w1, w25, lsr #24
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) ^ shiftRight(uint64(uint32(s.x[25])), 24, 32))))
	// 0x100235b94: ldr w1, [x22, w1, uxtw #2]
	value942, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value942))
	// 0x100235b98: mov w5, #0x43
	s.x[5] = uint64(uint32(uint64(0x43)))
	// 0x100235b9c: eor w16, w16, w5
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[5])))))
	// 0x100235ba0: ldr w16, [x24, w16, uxtw #2]
	value945, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value945))
	// 0x100235ba4: eor w14, w14, w13
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x100235ba8: ldr w14, [x26, w14, uxtw #2]
	value947, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value947))
	// 0x100235bac: eor w17, w17, w1, ror #23
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[1])), 23, 32))))
	// 0x100235bb0: eor w14, w16, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[14])))))
	// 0x100235bb4: and w16, w8, #0xff
	s.x[16] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100235bb8: ldr w1, [x2, w16, uxtw #2]
	value951, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value951))
	// 0x100235bbc: eor w14, w14, w1
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[1])))))
	// 0x100235bc0: eor w16, w17, w14
	s.x[16] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[14])))))
	// 0x100235bc4: lsr w8, w8, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x18)), 32)))
	// 0x100235bc8: ldr w8, [x22, w8, uxtw #2]
	value955, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value955))
	// 0x100235bcc: ubfx w9, w9, #8, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) >> 8) & bitMask(8, 32)))
	// 0x100235bd0: mov w14, #0xaa
	s.x[14] = uint64(uint32(uint64(0xaa)))
	// 0x100235bd4: eor w14, w9, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x100235bd8: ldr w14, [x26, w14, uxtw #2]
	value959, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value959))
	// 0x100235bdc: ldr w17, [sp, #0x3b4]
	value960, err := s.load(addOffset(s.sp, 948), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value960))
	// 0x100235be0: eor w8, w17, w8, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x100235be4: eor w8, w8, w14
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[14])))))
	// 0x100235be8: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100235bec: ubfx w9, w3, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[3])) >> 16) & bitMask(8, 32)))
	// 0x100235bf0: mov w5, #0xed
	s.x[5] = uint64(uint32(uint64(0xed)))
	// 0x100235bf4: eor w14, w9, w5
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[5])))))
	// 0x100235bf8: ldr w14, [x24, w14, uxtw #2]
	value967, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value967))
	// 0x100235bfc: and w11, w11, #0xff
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x100235c00: ldr w11, [x2, w11, uxtw #2]
	value969, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value969))
	// 0x100235c04: eor w8, w8, w14
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[14])))))
	// 0x100235c08: and w14, w4, w11, lsr #4
	s.x[14] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[11])), 4, 32))))
	// 0x100235c0c: eor w11, w11, w14
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[14])))))
	// 0x100235c10: eor w14, w9, #0x78
	s.x[14] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(0x78))))
	// 0x100235c14: mov w17, #0x7a2d
	s.x[17] = uint64(uint32(uint64(0x7a2d)))
	// 0x100235c18: movk w17, #0xbc9e, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0xbc9e, 16, 16, 32)))
	// 0x100235c1c: eor w9, w9, w17
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[17])))))
	// 0x100235c20: sub w9, w14, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) - uint64(uint32(s.x[9])))))
	// 0x100235c24: eor w9, w11, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[9])))))
	// 0x100235c28: and w11, w3, #0xff
	s.x[11] = uint64(uint32((uint64(uint32(s.x[3])) & uint64(0xff))))
	// 0x100235c2c: eor w11, w11, w5
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[5])))))
	// 0x100235c30: ldr w11, [x2, w11, uxtw #2]
	value981, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value981))
	// 0x100235c34: mov w14, #0xe168
	s.x[14] = uint64(uint32(uint64(0xe168)))
	// 0x100235c38: movk w14, #0x2cec, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x2cec, 16, 16, 32)))
	// 0x100235c3c: eor w9, w9, w14
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x100235c40: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100235c44: eor w19, w10, w11
	s.x[19] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100235c48: and w9, w4, w11, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[11])), 4, 32))))
	// 0x100235c4c: mov w10, #0x7275
	s.x[10] = uint64(uint32(uint64(0x7275)))
	// 0x100235c50: movk w10, #0x499, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x499, 16, 16, 32)))
	// 0x100235c54: eor w10, w19, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[19])) ^ uint64(uint32(s.x[10])))))
	// 0x100235c58: eor w3, w10, w9
	s.x[3] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x100235c5c: and w9, w4, w1, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[1])), 4, 32))))
	// 0x100235c60: mov w10, #0xf6f2
	s.x[10] = uint64(uint32(uint64(0xf6f2)))
	// 0x100235c64: movk w10, #0x8e7c, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x8e7c, 16, 16, 32)))
	// 0x100235c68: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235c6c: eor w11, w16, w9
	s.x[11] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[9])))))
	// 0x100235c70: lsr w9, w8, #0x18
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x18)), 32)))
	// 0x100235c74: ldr w9, [x22, w9, uxtw #2]
	value998, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value998))
	// 0x100235c78: ubfx w10, w11, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) >> 16) & bitMask(8, 32)))
	// 0x100235c7c: eor w14, w10, w0
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x100235c80: ldr w14, [x24, w14, uxtw #2]
	value1001, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1001))
	// 0x100235c84: ldr w17, [sp, #0x3c0]
	value1002, err := s.load(addOffset(s.sp, 960), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1002))
	// 0x100235c88: eor w9, w17, w9, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[9])), 23, 32))))
	// 0x100235c8c: eor w9, w9, w14
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x100235c90: mov w14, #0xe801
	s.x[14] = uint64(uint32(uint64(0xe801)))
	// 0x100235c94: movk w14, #0xd50, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0xd50, 16, 16, 32)))
	// 0x100235c98: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x100235c9c: eor w12, w15, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[12])))))
	// 0x100235ca0: ubfx w14, w3, #8, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[3])) >> 8) & bitMask(8, 32)))
	// 0x100235ca4: eor w17, w14, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x100235ca8: ldr w17, [x26, w17, uxtw #2]
	value1011, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1011))
	// 0x100235cac: and w1, w12, #0xff
	s.x[1] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x100235cb0: ldr w1, [x2, w1, uxtw #2]
	value1013, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value1013))
	// 0x100235cb4: eor w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x100235cb8: eor w9, w9, w17
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[17])))))
	// 0x100235cbc: and w17, w4, w1, lsr #4
	s.x[17] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[1])), 4, 32))))
	// 0x100235cc0: eor w14, w17, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[14])))))
	// 0x100235cc4: eor w17, w10, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x100235cc8: sub w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[17])))))
	// 0x100235ccc: eor w10, w14, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[10])))))
	// 0x100235cd0: mov w14, #0xd0
	s.x[14] = uint64(uint32(uint64(0xd0)))
	// 0x100235cd4: eor w14, w14, w15, lsr #24
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ shiftRight(uint64(uint32(s.x[15])), 24, 32))))
	// 0x100235cd8: ldr w14, [x22, w14, uxtw #2]
	value1023, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1023))
	// 0x100235cdc: eor w15, w9, w10
	s.x[15] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235ce0: ubfx w9, w8, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) >> 16) & bitMask(8, 32)))
	// 0x100235ce4: eor w10, w9, w27
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[27])))))
	// 0x100235ce8: sub w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[10])))))
	// 0x100235cec: ldr w17, [sp, #0x308]
	value1028, err := s.load(addOffset(s.sp, 776), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1028))
	// 0x100235cf0: eor w10, w17, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[10])))))
	// 0x100235cf4: eor w10, w10, w14, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ rotateRight(uint64(uint32(s.x[14])), 23, 32))))
	// 0x100235cf8: eor w9, w9, w0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[0])))))
	// 0x100235cfc: ldr w9, [x24, w9, uxtw #2]
	value1032, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1032))
	// 0x100235d00: eor w10, w10, w9
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x100235d04: ubfx w9, w11, #8, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) >> 8) & bitMask(8, 32)))
	// 0x100235d08: eor w9, w9, w13
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[13])))))
	// 0x100235d0c: ldr w14, [x26, w9, uxtw #2]
	value1036, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1036))
	// 0x100235d10: and w9, w3, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[3])) & uint64(0xff))))
	// 0x100235d14: ldr w9, [x2, w9, uxtw #2]
	value1038, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1038))
	// 0x100235d18: eor w14, w14, w9
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[9])))))
	// 0x100235d1c: eor w14, w10, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100235d20: ubfx w10, w12, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) >> 16) & bitMask(8, 32)))
	// 0x100235d24: eor w17, w10, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x100235d28: ubfx w1, w8, #8, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[8])) >> 8) & bitMask(8, 32)))
	// 0x100235d2c: ldr w5, [sp, #0x3d8]
	value1044, err := s.load(addOffset(s.sp, 984), 4)
	if err != nil {
		return err
	}
	s.x[5] = uint64(uint32(value1044))
	// 0x100235d30: eor w7, w5, w1
	s.x[7] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[1])))))
	// 0x100235d34: sub w17, w10, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[17])))))
	// 0x100235d38: eor w17, w7, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[17])))))
	// 0x100235d3c: eor w10, w10, w0
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x100235d40: ldr w10, [x24, w10, uxtw #2]
	value1049, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1049))
	// 0x100235d44: eor w10, w17, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[10])))))
	// 0x100235d48: eor w17, w6, w19, lsr #24
	s.x[17] = uint64(uint32((uint64(uint32(s.x[6])) ^ shiftRight(uint64(uint32(s.x[19])), 24, 32))))
	// 0x100235d4c: ldr w17, [x22, w17, uxtw #2]
	value1052, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1052))
	// 0x100235d50: eor w10, w10, w17, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ rotateRight(uint64(uint32(s.x[17])), 23, 32))))
	// 0x100235d54: eor w17, w1, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[13])))))
	// 0x100235d58: ldr w17, [x26, w17, uxtw #2]
	value1055, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1055))
	// 0x100235d5c: and w1, w11, #0xff
	s.x[1] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x100235d60: ldr w1, [x2, w1, uxtw #2]
	value1057, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value1057))
	// 0x100235d64: eor w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x100235d68: mov w5, #0xddc4
	s.x[5] = uint64(uint32(uint64(0xddc4)))
	// 0x100235d6c: movk w5, #0x2c11, lsl #16
	s.x[5] = uint64(uint32(insertBits(uint64(uint32(s.x[5])), 0x2c11, 16, 16, 32)))
	// 0x100235d70: eor w17, w17, w5
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[5])))))
	// 0x100235d74: eor w25, w10, w17
	s.x[25] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x100235d78: ubfx w10, w3, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[3])) >> 16) & bitMask(8, 32)))
	// 0x100235d7c: ubfx w12, w12, #8, #8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) >> 8) & bitMask(8, 32)))
	// 0x100235d80: eor w17, w10, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x100235d84: ldr w3, [sp, #0x304]
	value1066, err := s.load(addOffset(s.sp, 772), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1066))
	// 0x100235d88: eor w3, w3, w12
	s.x[3] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[12])))))
	// 0x100235d8c: sub w17, w10, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[17])))))
	// 0x100235d90: eor w17, w3, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[17])))))
	// 0x100235d94: mov w3, #0x53
	s.x[3] = uint64(uint32(uint64(0x53)))
	// 0x100235d98: eor w16, w3, w16, lsr #24
	s.x[16] = uint64(uint32((uint64(uint32(s.x[3])) ^ shiftRight(uint64(uint32(s.x[16])), 24, 32))))
	// 0x100235d9c: ldr w16, [x22, w16, uxtw #2]
	value1072, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value1072))
	// 0x100235da0: eor w10, w10, w0
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x100235da4: ldr w10, [x24, w10, uxtw #2]
	value1074, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1074))
	// 0x100235da8: eor w16, w17, w16, ror #23
	s.x[16] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[16])), 23, 32))))
	// 0x100235dac: eor w12, w12, w13
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x100235db0: ldr w12, [x26, w12, uxtw #2]
	value1077, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value1077))
	// 0x100235db4: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100235db8: eor w10, w16, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[10])))))
	// 0x100235dbc: and w8, w8, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100235dc0: ldr w8, [x2, w8, uxtw #2]
	value1081, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1081))
	// 0x100235dc4: mov w12, #0xb409
	s.x[12] = uint64(uint32(uint64(0xb409)))
	// 0x100235dc8: movk w12, #0x1919, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x1919, 16, 16, 32)))
	// 0x100235dcc: eor w12, w8, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[12])))))
	// 0x100235dd0: eor w12, w10, w12
	old1085, restore1085, err := s.beforeFault(selected, 0x100235dd0)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	s.afterFault(selected, 0x100235dd0, old1085, restore1085)
	// 0x100235dd4: and w10, w4, w1, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[1])), 4, 32))))
	// 0x100235dd8: and w8, w4, w8, lsr #4
	s.x[8] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[8])), 4, 32))))
	// 0x100235ddc: eor w19, w12, w8
	s.x[19] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[8])))))
	// 0x100235de0: ubfx w8, w19, #0x10, #8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[19])) >> 16) & bitMask(8, 32)))
	// 0x100235de4: eor w16, w8, w0
	s.x[16] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[0])))))
	// 0x100235de8: ldr w17, [x24, w16, uxtw #2]
	value1091, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1091))
	// 0x100235dec: eor w16, w25, w10
	s.x[16] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[10])))))
	// 0x100235df0: ubfx w1, w16, #8, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100235df4: eor w10, w1, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[13])))))
	// 0x100235df8: ldr w10, [x26, w10, uxtw #2]
	value1095, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1095))
	// 0x100235dfc: eor w10, w17, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[10])))))
	// 0x100235e00: lsr w17, w15, #0x18
	s.x[17] = uint64(uint32(shiftRight(uint64(uint32(s.x[15])), int(uint64(0x18)), 32)))
	// 0x100235e04: eor w17, w17, #0x3e
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(0x3e))))
	// 0x100235e08: ldr w17, [x22, w17, uxtw #2]
	value1099, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1099))
	// 0x100235e0c: ldr w3, [sp, #0x300]
	value1100, err := s.load(addOffset(s.sp, 768), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1100))
	// 0x100235e10: eor w17, w3, w17, ror #23
	s.x[17] = uint64(uint32((uint64(uint32(s.x[3])) ^ rotateRight(uint64(uint32(s.x[17])), 23, 32))))
	// 0x100235e14: eor w17, w17, w10
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[10])))))
	// 0x100235e18: lsr w11, w11, #8
	s.x[11] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x8)), 32)))
	// 0x100235e1c: and w9, w4, w9, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[9])), 4, 32))))
	// 0x100235e20: mov w10, #0x5ce0
	s.x[10] = uint64(uint32(uint64(0x5ce0)))
	// 0x100235e24: movk w10, #0xfd27, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xfd27, 16, 16, 32)))
	// 0x100235e28: eor w3, w14, w10
	s.x[3] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[10])))))
	// 0x100235e2c: eor w10, w3, w9
	s.x[10] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[9])))))
	// 0x100235e30: eor w9, w10, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100235e34: and w9, w9, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x100235e38: ldr w9, [x2, w9, uxtw #2]
	value1111, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1111))
	// 0x100235e3c: eor w11, w9, w1
	s.x[11] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[1])))))
	// 0x100235e40: eor w11, w17, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[11])))))
	// 0x100235e44: and w9, w4, w9, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[9])), 4, 32))))
	// 0x100235e48: eor w14, w8, w27
	s.x[14] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[27])))))
	// 0x100235e4c: sub w8, w8, w14
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[14])))))
	// 0x100235e50: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100235e54: eor w11, w11, w8
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[8])))))
	// 0x100235e58: ubfx w7, w15, #0x10, #8
	s.x[7] = uint64(uint32((uint64(uint32(s.x[15])) >> 16) & bitMask(8, 32)))
	// 0x100235e5c: mov w6, #0x90
	s.x[6] = uint64(uint32(uint64(0x90)))
	// 0x100235e60: eor w8, w7, w6
	s.x[8] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[6])))))
	// 0x100235e64: mov w9, #0x7ac5
	s.x[9] = uint64(uint32(uint64(0x7ac5)))
	// 0x100235e68: movk w9, #0xbc9e, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0xbc9e, 16, 16, 32)))
	// 0x100235e6c: eor w9, w7, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[9])))))
	// 0x100235e70: sub w9, w8, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[9])))))
	// 0x100235e74: ubfx w8, w10, #0x10, #8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) >> 16) & bitMask(8, 32)))
	// 0x100235e78: eor w14, w8, w27
	s.x[14] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[27])))))
	// 0x100235e7c: ubfx w17, w15, #8, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[15])) >> 8) & bitMask(8, 32)))
	// 0x100235e80: ldr w1, [sp, #0x3e0]
	value1129, err := s.load(addOffset(s.sp, 992), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value1129))
	// 0x100235e84: eor w1, w17, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x100235e88: sub w14, w8, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[8])) - uint64(uint32(s.x[14])))))
	// 0x100235e8c: eor w14, w1, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[14])))))
	// 0x100235e90: eor w8, w8, w0
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[0])))))
	// 0x100235e94: ldr w8, [x24, w8, uxtw #2]
	value1134, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1134))
	// 0x100235e98: eor w8, w14, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[8])))))
	// 0x100235e9c: lsr w14, w25, #0x18
	s.x[14] = uint64(uint32(shiftRight(uint64(uint32(s.x[25])), int(uint64(0x18)), 32)))
	// 0x100235ea0: ldr w14, [x22, w14, uxtw #2]
	value1137, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1137))
	// 0x100235ea4: eor w8, w8, w14, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ rotateRight(uint64(uint32(s.x[14])), 23, 32))))
	// 0x100235ea8: eor w14, w17, w6
	s.x[14] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[6])))))
	// 0x100235eac: ldr w17, [x26, w14, uxtw #2]
	value1140, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1140))
	// 0x100235eb0: and w14, w19, #0xff
	s.x[14] = uint64(uint32((uint64(uint32(s.x[19])) & uint64(0xff))))
	// 0x100235eb4: ldr w14, [x2, w14, uxtw #2]
	value1142, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1142))
	// 0x100235eb8: eor w17, w17, w14
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[14])))))
	// 0x100235ebc: eor w8, w8, w17
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[17])))))
	// 0x100235ec0: ubfx w10, w10, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) >> 8) & bitMask(8, 32)))
	// 0x100235ec4: ubfx w17, w16, #0x10, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x100235ec8: eor w1, w17, w27
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[27])))))
	// 0x100235ecc: ldr w5, [sp, #0x2fc]
	value1148, err := s.load(addOffset(s.sp, 764), 4)
	if err != nil {
		return err
	}
	s.x[5] = uint64(uint32(value1148))
	// 0x100235ed0: eor w25, w5, w10
	s.x[25] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[10])))))
	// 0x100235ed4: sub w1, w17, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) - uint64(uint32(s.x[1])))))
	// 0x100235ed8: eor w1, w25, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[25])) ^ uint64(uint32(s.x[1])))))
	// 0x100235edc: lsr w12, w12, #0x18
	s.x[12] = uint64(uint32(shiftRight(uint64(uint32(s.x[12])), int(uint64(0x18)), 32)))
	// 0x100235ee0: ldr w12, [x22, w12, uxtw #2]
	value1153, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value1153))
	// 0x100235ee4: eor w12, w1, w12, ror #23
	s.x[12] = uint64(uint32((uint64(uint32(s.x[1])) ^ rotateRight(uint64(uint32(s.x[12])), 23, 32))))
	// 0x100235ee8: eor w17, w17, w0
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[0])))))
	// 0x100235eec: ldr w17, [x24, w17, uxtw #2]
	value1156, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1156))
	// 0x100235ef0: eor w12, w12, w17
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[17])))))
	// 0x100235ef4: eor w10, w10, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x100235ef8: ldr w10, [x26, w10, uxtw #2]
	value1159, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1159))
	// 0x100235efc: and w15, w15, #0xff
	s.x[15] = uint64(uint32((uint64(uint32(s.x[15])) & uint64(0xff))))
	// 0x100235f00: mov w17, #0x3b
	s.x[17] = uint64(uint32(uint64(0x3b)))
	// 0x100235f04: eor w15, w15, w17
	s.x[15] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[17])))))
	// 0x100235f08: ldr w15, [x2, w15, uxtw #2]
	value1163, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value1163))
	// 0x100235f0c: eor w10, w10, w15
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[15])))))
	// 0x100235f10: eor w10, w12, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100235f14: and w12, w4, w15, lsr #4
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[15])), 4, 32))))
	// 0x100235f18: eor w12, w10, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100235f1c: mov w10, #5
	s.x[10] = uint64(uint32(uint64(0x5)))
	// 0x100235f20: eor w10, w7, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[10])))))
	// 0x100235f24: ldr w10, [x24, w10, uxtw #2]
	value1170, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1170))
	// 0x100235f28: ldr w15, [sp, #0x2f8]
	value1171, err := s.load(addOffset(s.sp, 760), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value1171))
	// 0x100235f2c: eor w9, w15, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[9])))))
	// 0x100235f30: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235f34: lsr w10, w3, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[3])), int(uint64(0x18)), 32)))
	// 0x100235f38: ldr w10, [x22, w10, uxtw #2]
	value1175, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1175))
	// 0x100235f3c: ubfx w15, w19, #8, #8
	s.x[15] = uint64(uint32((uint64(uint32(s.x[19])) >> 8) & bitMask(8, 32)))
	// 0x100235f40: eor w17, w15, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[13])))))
	// 0x100235f44: ldr w17, [x26, w17, uxtw #2]
	value1178, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1178))
	// 0x100235f48: eor w9, w9, w17
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[17])))))
	// 0x100235f4c: ror w10, w10, #0x17
	s.x[10] = uint64(uint32(rotateRight(uint64(uint32(s.x[10])), int(uint64(0x17)), 32)))
	// 0x100235f50: mov w17, #0xb91e
	s.x[17] = uint64(uint32(uint64(0xb91e)))
	// 0x100235f54: movk w17, #0x6059, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x6059, 16, 16, 32)))
	// 0x100235f58: and w17, w10, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[17])))))
	// 0x100235f5c: eor w9, w9, w17
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[17])))))
	// 0x100235f60: mov w17, #0x5ffb
	s.x[17] = uint64(uint32(uint64(0x5ffb)))
	// 0x100235f64: movk w17, #0x4750, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x4750, 16, 16, 32)))
	// 0x100235f68: eor w17, w10, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x100235f6c: ldr w1, [sp, #0x384]
	value1188, err := s.load(addOffset(s.sp, 900), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value1188))
	// 0x100235f70: and w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) & uint64(uint32(s.x[1])))))
	// 0x100235f74: eor w9, w9, w17
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[17])))))
	// 0x100235f78: mov w17, #0x9c9d
	s.x[17] = uint64(uint32(uint64(0x9c9d)))
	// 0x100235f7c: movk w17, #0x25db, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x25db, 16, 16, 32)))
	// 0x100235f80: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x100235f84: and w16, w16, #0xff
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x100235f88: ldr w16, [x2, w16, uxtw #2]
	value1195, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value1195))
	// 0x100235f8c: ldr w17, [sp, #0x380]
	value1196, err := s.load(addOffset(s.sp, 896), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1196))
	// 0x100235f90: and w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[17])))))
	// 0x100235f94: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x100235f98: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100235f9c: and w10, w4, w16, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[16])), 4, 32))))
	// 0x100235fa0: eor w17, w15, w10
	s.x[17] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[10])))))
	// 0x100235fa4: mov w10, #0xc7c9
	s.x[10] = uint64(uint32(uint64(0xc7c9)))
	// 0x100235fa8: movk w10, #0x70bc, lsl #16
	old1203, restore1203, err := s.beforeFault(selected, 0x100235fa8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x70bc, 16, 16, 32)))
	s.afterFault(selected, 0x100235fa8, old1203, restore1203)
	// 0x100235fac: eor w15, w12, w10
	s.x[15] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100235fb0: ubfx w10, w15, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[15])) >> 16) & bitMask(8, 32)))
	// 0x100235fb4: eor w16, w10, w0
	s.x[16] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x100235fb8: ldr w16, [x24, w16, uxtw #2]
	value1207, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[16])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value1207))
	// 0x100235fbc: eor w1, w10, w27
	s.x[1] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x100235fc0: sub w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[1])))))
	// 0x100235fc4: eor w10, w16, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[10])))))
	// 0x100235fc8: mov w16, #0x50c7
	s.x[16] = uint64(uint32(uint64(0x50c7)))
	// 0x100235fcc: movk w16, #0x2a9d, lsl #16
	s.x[16] = uint64(uint32(insertBits(uint64(uint32(s.x[16])), 0x2a9d, 16, 16, 32)))
	// 0x100235fd0: eor w16, w11, w16
	s.x[16] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[16])))))
	// 0x100235fd4: lsr w11, w16, #0x18
	s.x[11] = uint64(uint32(shiftRight(uint64(uint32(s.x[16])), int(uint64(0x18)), 32)))
	// 0x100235fd8: ldr w11, [x22, w11, uxtw #2]
	value1215, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value1215))
	// 0x100235fdc: ldr w1, [sp, #0x2f4]
	value1216, err := s.load(addOffset(s.sp, 756), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value1216))
	// 0x100235fe0: eor w11, w1, w11, ror #23
	s.x[11] = uint64(uint32((uint64(uint32(s.x[1])) ^ rotateRight(uint64(uint32(s.x[11])), 23, 32))))
	// 0x100235fe4: mov w1, #0x61e7
	s.x[1] = uint64(uint32(uint64(0x61e7)))
	// 0x100235fe8: movk w1, #0x1205, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x1205, 16, 16, 32)))
	// 0x100235fec: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x100235ff0: eor w11, w11, w10
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[10])))))
	// 0x100235ff4: and w10, w4, w14, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[14])), 4, 32))))
	// 0x100235ff8: eor w19, w8, w10
	s.x[19] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x100235ffc: ubfx w10, w19, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[19])) >> 8) & bitMask(8, 32)))
	// 0x100236000: mov w14, #0x92
	s.x[14] = uint64(uint32(uint64(0x92)))
	// 0x100236004: eor w14, w10, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100236008: ldr w14, [x26, w14, uxtw #2]
	value1227, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1227))
	// 0x10023600c: mov w1, #0xd410
	s.x[1] = uint64(uint32(uint64(0xd410)))
	// 0x100236010: movk w1, #0x91e3, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x91e3, 16, 16, 32)))
	// 0x100236014: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x100236018: eor w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x10023601c: eor w14, w10, w11
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236020: sub w14, w11, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[11])) - uint64(uint32(s.x[14])))))
	// 0x100236024: neg w1, w10
	s.x[1] = uint64(uint32(-(uint64(uint32(s.x[10])))))
	// 0x100236028: eor w14, w1, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[14])))))
	// 0x10023602c: mov w1, #0xc416
	s.x[1] = uint64(uint32(uint64(0xc416)))
	// 0x100236030: movk w1, #0x56ee, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x56ee, 16, 16, 32)))
	// 0x100236034: and w1, w1, w10, lsl #1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) & shiftLeft(uint64(uint32(s.x[10])), 1, 32))))
	// 0x100236038: sub w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[1])))))
	// 0x10023603c: mov w6, #0x620b
	s.x[6] = uint64(uint32(uint64(0x620b)))
	// 0x100236040: movk w6, #0xab77, lsl #16
	s.x[6] = uint64(uint32(insertBits(uint64(uint32(s.x[6])), 0xab77, 16, 16, 32)))
	// 0x100236044: add w10, w10, w6
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[6])))))
	// 0x100236048: eor w10, w14, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[10])))))
	// 0x10023604c: mov w14, #0xe2b8
	s.x[14] = uint64(uint32(uint64(0xe2b8)))
	// 0x100236050: movk w14, #0x8e87, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x8e87, 16, 16, 32)))
	// 0x100236054: eor w9, w9, w14
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[14])))))
	// 0x100236058: eor w3, w9, w17
	s.x[3] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[17])))))
	// 0x10023605c: ubfx w14, w3, #0x10, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[3])) >> 16) & bitMask(8, 32)))
	// 0x100236060: eor w17, w14, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[27])))))
	// 0x100236064: ubfx w1, w16, #8, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100236068: ldr w5, [sp, #0x2f0]
	value1251, err := s.load(addOffset(s.sp, 752), 4)
	if err != nil {
		return err
	}
	s.x[5] = uint64(uint32(value1251))
	// 0x10023606c: eor w7, w5, w1
	s.x[7] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[1])))))
	// 0x100236070: sub w17, w14, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[14])) - uint64(uint32(s.x[17])))))
	// 0x100236074: eor w17, w7, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[17])))))
	// 0x100236078: eor w14, w14, w0
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[0])))))
	// 0x10023607c: ldr w14, [x24, w14, uxtw #2]
	value1256, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1256))
	// 0x100236080: eor w14, w17, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[14])))))
	// 0x100236084: mov w17, #0x8c
	s.x[17] = uint64(uint32(uint64(0x8c)))
	// 0x100236088: eor w8, w17, w8, lsr #24
	s.x[8] = uint64(uint32((uint64(uint32(s.x[17])) ^ shiftRight(uint64(uint32(s.x[8])), 24, 32))))
	// 0x10023608c: ldr w8, [x22, w8, uxtw #2]
	value1260, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1260))
	// 0x100236090: eor w17, w1, w13
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[13])))))
	// 0x100236094: ldr w17, [x26, w17, uxtw #2]
	value1262, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1262))
	// 0x100236098: eor w8, w14, w8, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[14])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x10023609c: and w12, w12, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x1002360a0: mov w14, #0xf1
	s.x[14] = uint64(uint32(uint64(0xf1)))
	// 0x1002360a4: eor w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x1002360a8: ldr w12, [x2, w12, uxtw #2]
	value1267, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value1267))
	// 0x1002360ac: eor w14, w17, w12
	s.x[14] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[12])))))
	// 0x1002360b0: eor w8, w8, w14
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[14])))))
	// 0x1002360b4: and w14, w3, #0xff
	s.x[14] = uint64(uint32((uint64(uint32(s.x[3])) & uint64(0xff))))
	// 0x1002360b8: ldr w14, [x2, w14, uxtw #2]
	value1271, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1271))
	// 0x1002360bc: and w17, w4, w14, lsr #4
	s.x[17] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[14])), 4, 32))))
	// 0x1002360c0: eor w14, w14, w17
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[17])))))
	// 0x1002360c4: eor w10, w10, w6
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[6])))))
	// 0x1002360c8: mov w17, #0xa7c8
	s.x[17] = uint64(uint32(uint64(0xa7c8)))
	// 0x1002360cc: movk w17, #0x19ea, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x19ea, 16, 16, 32)))
	// 0x1002360d0: eor w14, w14, w17
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[17])))))
	// 0x1002360d4: add w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[11])))))
	// 0x1002360d8: eor w11, w14, w10
	s.x[11] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[10])))))
	// 0x1002360dc: ubfx w10, w16, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x1002360e0: eor w14, w10, w0
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[0])))))
	// 0x1002360e4: ldr w14, [x24, w14, uxtw #2]
	value1282, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1282))
	// 0x1002360e8: eor w17, w10, w27
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x1002360ec: sub w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) - uint64(uint32(s.x[17])))))
	// 0x1002360f0: eor w10, w14, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[10])))))
	// 0x1002360f4: lsr w9, w9, #0x18
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[9])), int(uint64(0x18)), 32)))
	// 0x1002360f8: ldr w9, [x22, w9, uxtw #2]
	value1287, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1287))
	// 0x1002360fc: ldr w14, [sp, #0x2ec]
	value1288, err := s.load(addOffset(s.sp, 748), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1288))
	// 0x100236100: eor w9, w14, w9, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) ^ rotateRight(uint64(uint32(s.x[9])), 23, 32))))
	// 0x100236104: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100236108: ubfx w14, w15, #8, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[15])) >> 8) & bitMask(8, 32)))
	// 0x10023610c: eor w10, w14, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x100236110: ldr w10, [x26, w10, uxtw #2]
	value1293, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1293))
	// 0x100236114: and w17, w19, #0xff
	s.x[17] = uint64(uint32((uint64(uint32(s.x[19])) & uint64(0xff))))
	// 0x100236118: eor w17, w17, w28
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[28])))))
	// 0x10023611c: ldr w17, [x2, w17, uxtw #2]
	value1296, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1296))
	// 0x100236120: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x100236124: mov w1, #0x598d
	s.x[1] = uint64(uint32(uint64(0x598d)))
	// 0x100236128: movk w1, #0x847a, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x847a, 16, 16, 32)))
	// 0x10023612c: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x100236130: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100236134: and w9, w4, w17, lsr #4
	s.x[9] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[17])), 4, 32))))
	// 0x100236138: eor w14, w14, w9
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[9])))))
	// 0x10023613c: ubfx w9, w19, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[19])) >> 16) & bitMask(8, 32)))
	// 0x100236140: ubfx w17, w3, #8, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[3])) >> 8) & bitMask(8, 32)))
	// 0x100236144: mov w1, #0xaf
	s.x[1] = uint64(uint32(uint64(0xaf)))
	// 0x100236148: eor w1, w9, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[1])))))
	// 0x10023614c: mov w3, #0x7afa
	s.x[3] = uint64(uint32(uint64(0x7afa)))
	// 0x100236150: movk w3, #0xbc9e, lsl #16
	s.x[3] = uint64(uint32(insertBits(uint64(uint32(s.x[3])), 0xbc9e, 16, 16, 32)))
	// 0x100236154: eor w3, w9, w3
	s.x[3] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[3])))))
	// 0x100236158: ldr w5, [sp, #0x2e8]
	value1311, err := s.load(addOffset(s.sp, 744), 4)
	if err != nil {
		return err
	}
	s.x[5] = uint64(uint32(value1311))
	// 0x10023615c: eor w7, w5, w17
	s.x[7] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[17])))))
	// 0x100236160: sub w1, w1, w3
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) - uint64(uint32(s.x[3])))))
	// 0x100236164: eor w1, w7, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[7])) ^ uint64(uint32(s.x[1])))))
	// 0x100236168: lsr w15, w15, #0x18
	s.x[15] = uint64(uint32(shiftRight(uint64(uint32(s.x[15])), int(uint64(0x18)), 32)))
	// 0x10023616c: ldr w15, [x22, w15, uxtw #2]
	value1316, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value1316))
	// 0x100236170: mov w3, #0x3a
	s.x[3] = uint64(uint32(uint64(0x3a)))
	// 0x100236174: eor w9, w9, w3
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[3])))))
	// 0x100236178: ldr w9, [x24, w9, uxtw #2]
	value1319, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1319))
	// 0x10023617c: eor w15, w1, w15, ror #23
	s.x[15] = uint64(uint32((uint64(uint32(s.x[1])) ^ rotateRight(uint64(uint32(s.x[15])), 23, 32))))
	// 0x100236180: eor w9, w15, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[9])))))
	// 0x100236184: eor w15, w17, w13
	s.x[15] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[13])))))
	// 0x100236188: ldr w15, [x26, w15, uxtw #2]
	value1323, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value1323))
	// 0x10023618c: eor w9, w9, w15
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[15])))))
	// 0x100236190: and w15, w16, #0xff
	s.x[15] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x100236194: ldr w15, [x2, w15, uxtw #2]
	value1326, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[15])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32(value1326))
	// 0x100236198: mov w16, #0xc6ac
	s.x[16] = uint64(uint32(uint64(0xc6ac)))
	// 0x10023619c: movk w16, #0x7d18, lsl #16
	s.x[16] = uint64(uint32(insertBits(uint64(uint32(s.x[16])), 0x7d18, 16, 16, 32)))
	// 0x1002361a0: eor w16, w15, w16
	s.x[16] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[16])))))
	// 0x1002361a4: eor w9, w9, w16
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[16])))))
	// 0x1002361a8: and w12, w4, w12, lsr #4
	s.x[12] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[12])), 4, 32))))
	// 0x1002361ac: and w16, w4, w15, lsr #4
	s.x[16] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[15])), 4, 32))))
	// 0x1002361b0: mov w15, #0x8362
	s.x[15] = uint64(uint32(uint64(0x8362)))
	// 0x1002361b4: movk w15, #0x949c, lsl #16
	s.x[15] = uint64(uint32(insertBits(uint64(uint32(s.x[15])), 0x949c, 16, 16, 32)))
	// 0x1002361b8: eor w12, w12, w15
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[15])))))
	// 0x1002361bc: eor w15, w8, w12
	old1336, restore1336, err := s.beforeFault(selected, 0x1002361bc)
	if err != nil {
		return err
	}
	s.x[15] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[12])))))
	s.afterFault(selected, 0x1002361bc, old1336, restore1336)
	// 0x1002361c0: eor w12, w9, w16
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[16])))))
	// 0x1002361c4: ubfx w16, w12, #0x10, #8
	s.x[16] = uint64(uint32((uint64(uint32(s.x[12])) >> 16) & bitMask(8, 32)))
	// 0x1002361c8: eor w17, w16, w0
	s.x[17] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[0])))))
	// 0x1002361cc: ldr w17, [x24, w17, uxtw #2]
	value1340, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1340))
	// 0x1002361d0: ubfx w1, w15, #8, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[15])) >> 8) & bitMask(8, 32)))
	// 0x1002361d4: eor w3, w1, w13
	s.x[3] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[13])))))
	// 0x1002361d8: ldr w3, [x26, w3, uxtw #2]
	value1343, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1343))
	// 0x1002361dc: eor w17, w17, w3
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[3])))))
	// 0x1002361e0: eor w14, w10, w14
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x1002361e4: and w3, w14, #0xff
	s.x[3] = uint64(uint32((uint64(uint32(s.x[14])) & uint64(0xff))))
	// 0x1002361e8: ldr w3, [x2, w3, uxtw #2]
	value1347, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1347))
	// 0x1002361ec: eor w17, w17, w3
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[3])))))
	// 0x1002361f0: eor w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x1002361f4: and w1, w4, w3, lsr #4
	s.x[1] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[3])), 4, 32))))
	// 0x1002361f8: eor w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x1002361fc: lsr w1, w11, #0x18
	s.x[1] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x18)), 32)))
	// 0x100236200: ldr w1, [x22, w1, uxtw #2]
	value1353, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[1] = uint64(uint32(value1353))
	// 0x100236204: ldr w3, [sp, #0x2e4]
	value1354, err := s.load(addOffset(s.sp, 740), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1354))
	// 0x100236208: eor w1, w3, w1, ror #23
	s.x[1] = uint64(uint32((uint64(uint32(s.x[3])) ^ rotateRight(uint64(uint32(s.x[1])), 23, 32))))
	// 0x10023620c: eor w17, w1, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[17])))))
	// 0x100236210: eor w1, w16, w27
	s.x[1] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[27])))))
	// 0x100236214: sub w16, w16, w1
	s.x[16] = uint64(uint32((uint64(uint32(s.x[16])) - uint64(uint32(s.x[1])))))
	// 0x100236218: eor w16, w17, w16
	s.x[16] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[16])))))
	// 0x10023621c: lsr w10, w10, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[10])), int(uint64(0x18)), 32)))
	// 0x100236220: ldr w10, [x22, w10, uxtw #2]
	value1361, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1361))
	// 0x100236224: ldr w17, [sp, #0x2e0]
	value1362, err := s.load(addOffset(s.sp, 736), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1362))
	// 0x100236228: eor w10, w17, w10, ror #23
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) ^ rotateRight(uint64(uint32(s.x[10])), 23, 32))))
	// 0x10023622c: ubfx w17, w11, #0x10, #8
	s.x[17] = uint64(uint32((uint64(uint32(s.x[11])) >> 16) & bitMask(8, 32)))
	// 0x100236230: eor w1, w17, w27
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[27])))))
	// 0x100236234: sub w1, w17, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[17])) - uint64(uint32(s.x[1])))))
	// 0x100236238: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x10023623c: ubfx w1, w12, #8, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[12])) >> 8) & bitMask(8, 32)))
	// 0x100236240: eor w3, w1, w13
	s.x[3] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[13])))))
	// 0x100236244: ldr w3, [x26, w3, uxtw #2]
	value1370, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1370))
	// 0x100236248: eor w10, w10, w3
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[3])))))
	// 0x10023624c: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x100236250: eor w17, w17, w0
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[0])))))
	// 0x100236254: ldr w17, [x24, w17, uxtw #2]
	value1374, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1374))
	// 0x100236258: mov w1, #0xdeed
	s.x[1] = uint64(uint32(uint64(0xdeed)))
	// 0x10023625c: movk w1, #0xb99f, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0xb99f, 16, 16, 32)))
	// 0x100236260: eor w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[1])))))
	// 0x100236264: eor w10, w10, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[17])))))
	// 0x100236268: mov w17, #0x49fc
	s.x[17] = uint64(uint32(uint64(0x49fc)))
	// 0x10023626c: movk w17, #0x404, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0x404, 16, 16, 32)))
	// 0x100236270: and w17, w10, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[17])))))
	// 0x100236274: mov w1, #0xa872
	s.x[1] = uint64(uint32(uint64(0xa872)))
	// 0x100236278: movk w1, #0x9cf1, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x9cf1, 16, 16, 32)))
	// 0x10023627c: eor w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[1])))))
	// 0x100236280: mov w1, #0xb603
	s.x[1] = uint64(uint32(uint64(0xb603)))
	// 0x100236284: movk w1, #0xfbfb, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0xfbfb, 16, 16, 32)))
	// 0x100236288: and w1, w10, w1
	s.x[1] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[1])))))
	// 0x10023628c: mov w3, #0xdbff
	s.x[3] = uint64(uint32(uint64(0xdbff)))
	// 0x100236290: movk w3, #0x8c3c, lsl #16
	s.x[3] = uint64(uint32(insertBits(uint64(uint32(s.x[3])), 0x8c3c, 16, 16, 32)))
	// 0x100236294: eor w1, w1, w3
	s.x[1] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[3])))))
	// 0x100236298: and w17, w17, w1
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) & uint64(uint32(s.x[1])))))
	// 0x10023629c: mov w1, #0x1601
	s.x[1] = uint64(uint32(uint64(0x1601)))
	// 0x1002362a0: movk w1, #0x630a, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x630a, 16, 16, 32)))
	// 0x1002362a4: and w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[1])))))
	// 0x1002362a8: orr w10, w17, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[17])) | uint64(uint32(s.x[10])))))
	// 0x1002362ac: and w17, w15, #0xff
	s.x[17] = uint64(uint32((uint64(uint32(s.x[15])) & uint64(0xff))))
	// 0x1002362b0: ldr w17, [x2, w17, uxtw #2]
	value1397, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[17])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1397))
	// 0x1002362b4: and w1, w4, w17, lsr #4
	s.x[1] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[17])), 4, 32))))
	// 0x1002362b8: eor w17, w1, w17
	s.x[17] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[17])))))
	// 0x1002362bc: lsr w9, w9, #0x18
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[9])), int(uint64(0x18)), 32)))
	// 0x1002362c0: mov w1, #0x49
	s.x[1] = uint64(uint32(uint64(0x49)))
	// 0x1002362c4: eor w8, w1, w8, lsr #24
	s.x[8] = uint64(uint32((uint64(uint32(s.x[1])) ^ shiftRight(uint64(uint32(s.x[8])), 24, 32))))
	// 0x1002362c8: ldr w8, [x22, w8, uxtw #2]
	value1403, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1403))
	// 0x1002362cc: ldr w9, [x22, w9, uxtw #2]
	value1404, err := s.load((s.x[22] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1404))
	// 0x1002362d0: ubfx w1, w14, #0x10, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[14])) >> 16) & bitMask(8, 32)))
	// 0x1002362d4: eor w3, w1, w0
	s.x[3] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[0])))))
	// 0x1002362d8: ldr w3, [x24, w3, uxtw #2]
	value1407, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[3] = uint64(uint32(value1407))
	// 0x1002362dc: ubfx w15, w15, #0x10, #8
	s.x[15] = uint64(uint32((uint64(uint32(s.x[15])) >> 16) & bitMask(8, 32)))
	// 0x1002362e0: eor w7, w15, w0
	s.x[7] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[0])))))
	// 0x1002362e4: ldr w7, [x24, w7, uxtw #2]
	value1410, err := s.load((s.x[24] + shiftLeft(uint64(uint32(uint64(uint32(s.x[7])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[7] = uint64(uint32(value1410))
	// 0x1002362e8: ubfx w22, w11, #8, #8
	s.x[22] = uint64(uint32((uint64(uint32(s.x[11])) >> 8) & bitMask(8, 32)))
	// 0x1002362ec: eor w19, w22, w13
	s.x[19] = uint64(uint32((uint64(uint32(s.x[22])) ^ uint64(uint32(s.x[13])))))
	// 0x1002362f0: ldr w24, [x26, w19, uxtw #2]
	value1413, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[19])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[24] = uint64(uint32(value1413))
	// 0x1002362f4: eor w19, w17, w10
	s.x[19] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[10])))))
	// 0x1002362f8: ubfx w10, w14, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) >> 8) & bitMask(8, 32)))
	// 0x1002362fc: eor w14, w10, w13
	s.x[14] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x100236300: ldr w14, [x26, w14, uxtw #2]
	value1417, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1417))
	// 0x100236304: and w12, w12, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x100236308: ldr w12, [x2, w12, uxtw #2]
	value1419, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value1419))
	// 0x10023630c: and w11, w11, #0xff
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x100236310: ldr w17, [x2, w11, uxtw #2]
	value1421, err := s.load((s.x[2] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1421))
	// 0x100236314: eor w11, w1, w27
	s.x[11] = uint64(uint32((uint64(uint32(s.x[1])) ^ uint64(uint32(s.x[27])))))
	// 0x100236318: sub w11, w1, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[1])) - uint64(uint32(s.x[11])))))
	// 0x10023631c: ldr w13, [sp, #0x2dc]
	value1424, err := s.load(addOffset(s.sp, 732), 4)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1424))
	// 0x100236320: eor w11, w13, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[11])))))
	// 0x100236324: eor w11, w11, w22
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[22])))))
	// 0x100236328: eor w8, w11, w8, ror #23
	s.x[8] = uint64(uint32((uint64(uint32(s.x[11])) ^ rotateRight(uint64(uint32(s.x[8])), 23, 32))))
	// 0x10023632c: eor w8, w8, w3
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[3])))))
	// 0x100236330: eor w8, w8, w12
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[12])))))
	// 0x100236334: eor w8, w8, w24
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[24])))))
	// 0x100236338: ldr w11, [sp, #0x3b8]
	value1431, err := s.load(addOffset(s.sp, 952), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value1431))
	// 0x10023633c: eor w10, w11, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[10])))))
	// 0x100236340: eor w11, w15, w27
	s.x[11] = uint64(uint32((uint64(uint32(s.x[15])) ^ uint64(uint32(s.x[27])))))
	// 0x100236344: sub w11, w15, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[15])) - uint64(uint32(s.x[11])))))
	// 0x100236348: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x10023634c: eor w10, w10, w7
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[7])))))
	// 0x100236350: eor w9, w10, w9, ror #23
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ rotateRight(uint64(uint32(s.x[9])), 23, 32))))
	// 0x100236354: eor w10, w14, w17
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[17])))))
	// 0x100236358: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x10023635c: ldr x10, [sp, #0x410]
	value1440, err := s.load(addOffset(s.sp, 1040), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1440)
	// 0x100236360: ldur x11, [x29, #-0xe8]
	value1441, err := s.load(addOffset(s.x[29], -232), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value1441)
	// 0x100236364: add x10, x11, x10
	s.x[10] = uint64((s.x[11] + s.x[10]))
	// 0x100236368: ldrb w10, [x10]
	value1443, err := s.load(s.x[10], 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1443))
	// 0x10023636c: mov w11, #0x29
	s.x[11] = uint64(uint32(uint64(0x29)))
	// 0x100236370: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236374: ldur x11, [x29, #-0xf0]
	value1446, err := s.load(addOffset(s.x[29], -240), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value1446)
	// 0x100236378: ldrb w10, [x11, w10, uxtw]
	value1447, err := s.load((s.x[11] + uint64(uint32(uint64(uint32(s.x[10]))))), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1447))
	// 0x10023637c: eor w13, w23, w10
	s.x[13] = uint64(uint32((uint64(uint32(s.x[23])) ^ uint64(uint32(s.x[10])))))
	// 0x100236380: ldr w10, [sp, #0x424]
	value1449, err := s.load(addOffset(s.sp, 1060), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1449))
	// 0x100236384: add w11, w10, w21
	s.x[11] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[21])))))
	// 0x100236388: and w10, w4, w12, lsr #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[12])), 4, 32))))
	// 0x10023638c: and w14, w4, w17, lsr #4
	s.x[14] = uint64(uint32((uint64(uint32(s.x[4])) & shiftRight(uint64(uint32(s.x[17])), 4, 32))))
	// 0x100236390: mov w12, #0xf28e
	s.x[12] = uint64(uint32(uint64(0xf28e)))
	// 0x100236394: movk w12, #0xf722, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xf722, 16, 16, 32)))
	// 0x100236398: eor w12, w8, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[12])))))
	// 0x10023639c: eor w8, w12, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x1002363a0: lsr w10, w12, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[12])), int(uint64(0x18)), 32)))
	// 0x1002363a4: mov w12, #0xc930
	s.x[12] = uint64(uint32(uint64(0xc930)))
	// 0x1002363a8: movk w12, #0xc66a, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xc66a, 16, 16, 32)))
	// 0x1002363ac: eor w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x1002363b0: and w9, w13, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(0xff))))
	// 0x1002363b4: add w9, w9, #0x82a
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(0x82a))))
	// 0x1002363b8: mov x26, x30
	s.x[26] = uint64(s.x[30])
	// 0x1002363bc: ldr x9, [x30, w9, uxtw #3]
	value1464, err := s.load((s.x[30] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1464)
	// 0x1002363c0: mov x13, #-0x690a
	s.x[13] = uint64(uint64(0xffffffffffff96f6))
	// 0x1002363c4: movk x13, #0xccb9, lsl #16
	s.x[13] = uint64(insertBits(s.x[13], 0xccb9, 16, 16, 64))
	// 0x1002363c8: add x9, x9, x13
	s.x[9] = uint64((s.x[9] + s.x[13]))
	// 0x1002363cc: mov w0, #0xa3
	s.x[0] = uint64(uint32(uint64(0xa3)))
	// 0x1002363d0: eor w13, w0, w16, lsr #24
	s.x[13] = uint64(uint32((uint64(uint32(s.x[0])) ^ shiftRight(uint64(uint32(s.x[16])), 24, 32))))
	// 0x1002363d4: ldr w30, [x9, w13, uxtw #2]
	value1470, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[13])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[30] = uint64(uint32(value1470))
	// 0x1002363d8: eor w24, w12, w14
	s.x[24] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[14])))))
	// 0x1002363dc: mov w13, #0x84
	s.x[13] = uint64(uint32(uint64(0x84)))
	// 0x1002363e0: eor w13, w13, w19, lsr #24
	s.x[13] = uint64(uint32((uint64(uint32(s.x[13])) ^ shiftRight(uint64(uint32(s.x[19])), 24, 32))))
	// 0x1002363e4: ldr w25, [x9, w13, uxtw #2]
	value1474, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[13])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[25] = uint64(uint32(value1474))
	// 0x1002363e8: ldr w10, [x9, w10, uxtw #2]
	value1475, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1475))
	// 0x1002363ec: str w10, [sp, #0x424]
	if err := s.storeValue(addOffset(s.sp, 1060), uint64(uint32(s.x[10])), 4); err != nil {
		return err
	}
	// 0x1002363f0: lsr w10, w12, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[12])), int(uint64(0x18)), 32)))
	// 0x1002363f4: ldr w9, [x9, w10, uxtw #2]
	value1478, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1478))
	// 0x1002363f8: str w9, [sp, #0x410]
	if err := s.storeValue(addOffset(s.sp, 1040), uint64(uint32(s.x[9])), 4); err != nil {
		return err
	}
	// 0x1002363fc: mov w9, #0xdd5d
	s.x[9] = uint64(uint32(uint64(0xdd5d)))
	// 0x100236400: movk w9, #0x2a2a, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x2a2a, 16, 16, 32)))
	// 0x100236404: eor w10, w19, w9
	s.x[10] = uint64(uint32((uint64(uint32(s.x[19])) ^ uint64(uint32(s.x[9])))))
	// 0x100236408: mov w27, #0xa6
	s.x[27] = uint64(uint32(uint64(0xa6)))
	// 0x10023640c: eor w9, w11, w27
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[27])))))
	// 0x100236410: mov w11, #0xd4cf
	s.x[11] = uint64(uint32(uint64(0xd4cf)))
	// 0x100236414: movk w11, #0xa5c, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0xa5c, 16, 16, 32)))
	// 0x100236418: mul w12, w9, w11
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) * uint64(uint32(s.x[11])))))
	// 0x10023641c: ldur x9, [x29, #-0xb8]
	value1488, err := s.load(addOffset(s.x[29], -184), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1488)
	// 0x100236420: add x9, x9, w12, uxtb
	s.x[9] = uint64((s.x[9] + uint64(uint8(uint64(uint32(s.x[12]))))))
	// 0x100236424: ldrb w17, [x9]
	value1490, err := s.load(s.x[9], 1)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1490))
	// 0x100236428: mov w9, #0x5d
	s.x[9] = uint64(uint32(uint64(0x5d)))
	// 0x10023642c: eor w9, w17, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(uint32(s.x[9])))))
	// 0x100236430: ldur x11, [x29, #-0xa8]
	value1493, err := s.load(addOffset(s.x[29], -168), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value1493)
	// 0x100236434: ldrb w9, [x11, w9, uxtw]
	value1494, err := s.load((s.x[11] + uint64(uint32(uint64(uint32(s.x[9]))))), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1494))
	// 0x100236438: eor w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x10023643c: and w9, w9, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x100236440: add w9, w9, #0x547
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(0x547))))
	// 0x100236444: ldr x9, [x26, w9, uxtw #3]
	value1498, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1498)
	// 0x100236448: mov x11, #-0x8563
	s.x[11] = uint64(uint64(0xffffffffffff7a9d))
	// 0x10023644c: movk x11, #0xd7f8, lsl #16
	s.x[11] = uint64(insertBits(s.x[11], 0xd7f8, 16, 16, 64))
	// 0x100236450: add x9, x9, x11
	s.x[9] = uint64((s.x[9] + s.x[11]))
	// 0x100236454: ubfx w11, w24, #0x10, #8
	s.x[11] = uint64(uint32((uint64(uint32(s.x[24])) >> 16) & bitMask(8, 32)))
	// 0x100236458: ldr w2, [x9, w11, uxtw #2]
	value1503, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[11])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[2] = uint64(uint32(value1503))
	// 0x10023645c: ubfx w14, w16, #0x10, #8
	s.x[14] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x100236460: mov w13, #0xd9
	s.x[13] = uint64(uint32(uint64(0xd9)))
	// 0x100236464: eor w14, w14, w13
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[13])))))
	// 0x100236468: ldr w14, [x9, w14, uxtw #2]
	value1507, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[14])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[14] = uint64(uint32(value1507))
	// 0x10023646c: ubfx w1, w10, #0x10, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[10])) >> 16) & bitMask(8, 32)))
	// 0x100236470: ldr w5, [x9, w1, uxtw #2]
	value1509, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[5] = uint64(uint32(value1509))
	// 0x100236474: ubfx w1, w8, #0x10, #8
	s.x[1] = uint64(uint32((uint64(uint32(s.x[8])) >> 16) & bitMask(8, 32)))
	// 0x100236478: ldr w23, [x9, w1, uxtw #2]
	value1511, err := s.load((s.x[9] + shiftLeft(uint64(uint32(uint64(uint32(s.x[1])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[23] = uint64(uint32(value1511))
	// 0x10023647c: ldur x7, [x29, #-0x100]
	value1512, err := s.load(addOffset(s.x[29], -256), 8)
	if err != nil {
		return err
	}
	s.x[7] = uint64(value1512)
	// 0x100236480: ldr x13, [sp, #0x418]
	value1513, err := s.load(addOffset(s.sp, 1048), 8)
	if err != nil {
		return err
	}
	s.x[13] = uint64(value1513)
	// 0x100236484: add x9, x7, x13
	s.x[9] = uint64((s.x[7] + s.x[13]))
	// 0x100236488: ldrb w9, [x9]
	value1515, err := s.load(s.x[9], 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1515))
	// 0x10023648c: mov w11, #0xfb
	s.x[11] = uint64(uint32(uint64(0xfb)))
	// 0x100236490: eor w9, w9, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100236494: ldur x28, [x29, #-0xc0]
	value1518, err := s.load(addOffset(s.x[29], -192), 8)
	if err != nil {
		return err
	}
	s.x[28] = uint64(value1518)
	// 0x100236498: ldrb w9, [x28, w9, uxtw]
	value1519, err := s.load((s.x[28] + uint64(uint32(uint64(uint32(s.x[9]))))), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1519))
	// 0x10023649c: eor w9, w20, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[20])) ^ uint64(uint32(s.x[9])))))
	// 0x1002364a0: and w9, w9, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x1002364a4: add w9, w9, #0x27
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(0x27))))
	// 0x1002364a8: ldr x9, [x26, w9, uxtw #3]
	value1523, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1523)
	// 0x1002364ac: mov x1, #-0x97bf
	s.x[1] = uint64(uint64(0xffffffffffff6841))
	// 0x1002364b0: movk x1, #0x81ae, lsl #16
	s.x[1] = uint64(insertBits(s.x[1], 0x81ae, 16, 16, 64))
	// 0x1002364b4: add x1, x9, x1
	s.x[1] = uint64((s.x[9] + s.x[1]))
	// 0x1002364b8: ubfx w9, w8, #8, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) >> 8) & bitMask(8, 32)))
	// 0x1002364bc: ldr w19, [x1, w9, uxtw #2]
	value1528, err := s.load((s.x[1] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[19] = uint64(uint32(value1528))
	// 0x1002364c0: ubfx w9, w24, #8, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[24])) >> 8) & bitMask(8, 32)))
	// 0x1002364c4: ldr w9, [x1, w9, uxtw #2]
	value1530, err := s.load((s.x[1] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1530))
	// 0x1002364c8: ubfx w3, w16, #8, #8
	s.x[3] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x1002364cc: eor w3, w3, w0
	s.x[3] = uint64(uint32((uint64(uint32(s.x[3])) ^ uint64(uint32(s.x[0])))))
	// 0x1002364d0: ldr w6, [x1, w3, uxtw #2]
	value1533, err := s.load((s.x[1] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[6] = uint64(uint32(value1533))
	// 0x1002364d4: ubfx w3, w10, #8, #8
	s.x[3] = uint64(uint32((uint64(uint32(s.x[10])) >> 8) & bitMask(8, 32)))
	// 0x1002364d8: ldr w22, [x1, w3, uxtw #2]
	value1535, err := s.load((s.x[1] + shiftLeft(uint64(uint32(uint64(uint32(s.x[3])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[22] = uint64(uint32(value1535))
	// 0x1002364dc: eor w17, w17, #4
	s.x[17] = uint64(uint32((uint64(uint32(s.x[17])) ^ uint64(0x4))))
	// 0x1002364e0: ldur x1, [x29, #-0xa8]
	value1537, err := s.load(addOffset(s.x[29], -168), 8)
	if err != nil {
		return err
	}
	s.x[1] = uint64(value1537)
	// 0x1002364e4: ldrb w17, [x1, w17, uxtw]
	value1538, err := s.load((s.x[1] + uint64(uint32(uint64(uint32(s.x[17]))))), 1)
	if err != nil {
		return err
	}
	s.x[17] = uint64(uint32(value1538))
	// 0x1002364e8: eor w12, w12, w17
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[17])))))
	// 0x1002364ec: and w10, w10, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0xff))))
	// 0x1002364f0: and w12, w12, #0xff
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(0xff))))
	// 0x1002364f4: add w12, w12, #0xaa8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(0xaa8))))
	// 0x1002364f8: ldr x12, [x26, w12, uxtw #3]
	value1543, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[12])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[12] = uint64(value1543)
	// 0x1002364fc: mov x17, #-0xefa6
	s.x[17] = uint64(uint64(0xffffffffffff105a))
	// 0x100236500: movk x17, #0xcc12, lsl #16
	s.x[17] = uint64(insertBits(s.x[17], 0xcc12, 16, 16, 64))
	// 0x100236504: add x17, x12, x17
	s.x[17] = uint64((s.x[12] + s.x[17]))
	// 0x100236508: ldr w21, [x17, w10, uxtw #2]
	value1547, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[21] = uint64(uint32(value1547))
	// 0x10023650c: and w8, w8, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100236510: ldr w8, [x17, w8, uxtw #2]
	value1549, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1549))
	// 0x100236514: and w10, w24, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[24])) & uint64(0xff))))
	// 0x100236518: ldr w24, [x17, w10, uxtw #2]
	value1551, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[24] = uint64(uint32(value1551))
	// 0x10023651c: and w10, w16, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x100236520: mov w16, #0xe3
	s.x[16] = uint64(uint32(uint64(0xe3)))
	// 0x100236524: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x100236528: ldr w10, [x17, w10, uxtw #2]
	value1555, err := s.load((s.x[17] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 2, 64)), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1555))
	// 0x10023652c: str w10, [sp, #0x408]
	if err := s.storeValue(addOffset(s.sp, 1032), uint64(uint32(s.x[10])), 4); err != nil {
		return err
	}
	// 0x100236530: ldr w10, [sp, #0x2cc]
	value1557, err := s.load(addOffset(s.sp, 716), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1557))
	// 0x100236534: ldr w16, [sp, #0x4b4]
	value1558, err := s.load(addOffset(s.sp, 1204), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value1558))
	// 0x100236538: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x10023653c: ldr w16, [sp, #0x2d4]
	value1560, err := s.load(addOffset(s.sp, 724), 4)
	if err != nil {
		return err
	}
	s.x[16] = uint64(uint32(value1560))
	// 0x100236540: eor w10, w16, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) ^ uint64(uint32(s.x[10])))))
	// 0x100236544: eor w10, w10, w9
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x100236548: mov w17, #0x7a0d
	s.x[17] = uint64(uint32(uint64(0x7a0d)))
	// 0x10023654c: movk w17, #0xab36, lsl #16
	s.x[17] = uint64(uint32(insertBits(uint64(uint32(s.x[17])), 0xab36, 16, 16, 32)))
	// 0x100236550: add w16, w25, w17
	s.x[16] = uint64(uint32((uint64(uint32(s.x[25])) + uint64(uint32(s.x[17])))))
	// 0x100236554: adrp x25, #0x101075000
	s.x[25] = uint64(0x101075000)
	// 0x100236558: eor w10, w10, w16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[16])))))
	// 0x10023655c: eor w10, w10, w9, lsr #2
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[9])), 2, 32))))
	// 0x100236560: eor w9, w10, w9, lsr #3
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[9])), 3, 32))))
	// 0x100236564: mov w1, #0x1edc
	s.x[1] = uint64(uint32(uint64(0x1edc)))
	// 0x100236568: movk w1, #0x7a2, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x7a2, 16, 16, 32)))
	// 0x10023656c: and w10, w1, w14, lsl #1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[1])) & shiftLeft(uint64(uint32(s.x[14])), 1, 32))))
	// 0x100236570: mov w3, #0xc54
	s.x[3] = uint64(uint32(uint64(0xc54)))
	// 0x100236574: movk w3, #0x382, lsl #16
	s.x[3] = uint64(uint32(insertBits(uint64(uint32(s.x[3])), 0x382, 16, 16, 32)))
	// 0x100236578: eor w10, w10, w3
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[3])))))
	// 0x10023657c: mov w4, #0xf954
	s.x[4] = uint64(uint32(uint64(0xf954)))
	// 0x100236580: movk w4, #0x461a, lsl #16
	s.x[4] = uint64(uint32(insertBits(uint64(uint32(s.x[4])), 0x461a, 16, 16, 32)))
	// 0x100236584: eor w14, w14, w4
	s.x[14] = uint64(uint32((uint64(uint32(s.x[14])) ^ uint64(uint32(s.x[4])))))
	// 0x100236588: add w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[14])))))
	// 0x10023658c: eor w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x100236590: mov w14, #0x663
	s.x[14] = uint64(uint32(uint64(0x663)))
	// 0x100236594: movk w14, #0x5cb0, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x5cb0, 16, 16, 32)))
	// 0x100236598: and w10, w14, w10, lsr #1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) & shiftRight(uint64(uint32(s.x[10])), 1, 32))))
	// 0x10023659c: eor w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x1002365a0: eor w16, w9, w8
	s.x[16] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x1002365a4: and w8, w16, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[16])) & uint64(0xff))))
	// 0x1002365a8: eor w9, w8, #0x60
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0x60))))
	// 0x1002365ac: mov w10, #0x34
	s.x[10] = uint64(uint32(uint64(0x34)))
	// 0x1002365b0: eor w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x1002365b4: sub w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) - uint64(uint32(s.x[8])))))
	// 0x1002365b8: eor w8, w8, #0xfffffff8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0xfffffff8))))
	// 0x1002365bc: add w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[9])))))
	// 0x1002365c0: ldur x9, [x29, #-0xf8]
	value1593, err := s.load(addOffset(s.x[29], -248), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1593)
	// 0x1002365c4: add x9, x9, x13
	s.x[9] = uint64((s.x[9] + s.x[13]))
	// 0x1002365c8: ldrb w9, [x9]
	value1595, err := s.load(s.x[9], 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1595))
	// 0x1002365cc: mov w10, #0xb5
	s.x[10] = uint64(uint32(uint64(0xb5)))
	// 0x1002365d0: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002365d4: ldr x10, [sp, #0x4c8]
	value1598, err := s.load(addOffset(s.sp, 1224), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1598)
	// 0x1002365d8: ldrb w9, [x10, w9, uxtw]
	value1599, err := s.load((s.x[10] + uint64(uint32(uint64(uint32(s.x[9]))))), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1599))
	// 0x1002365dc: eor w9, w20, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[20])) ^ uint64(uint32(s.x[9])))))
	// 0x1002365e0: and w9, w9, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x1002365e4: add w9, w9, #0xe94
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(0xe94))))
	// 0x1002365e8: ldr x9, [x26, w9, uxtw #3]
	value1603, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[9])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1603)
	// 0x1002365ec: mov x10, #-0x693f
	s.x[10] = uint64(uint64(0xffffffffffff96c1))
	// 0x1002365f0: movk x10, #0xec5a, lsl #16
	s.x[10] = uint64(insertBits(s.x[10], 0xec5a, 16, 16, 64))
	// 0x1002365f4: add x0, x9, x10
	s.x[0] = uint64((s.x[9] + s.x[10]))
	// 0x1002365f8: ldrb w8, [x0, w8, uxtw]
	value1607, err := s.load((s.x[0] + uint64(uint32(uint64(uint32(s.x[8]))))), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1607))
	// 0x1002365fc: lsr w9, w8, #3
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x3)), 32)))
	// 0x100236600: orr w8, w9, w8, lsl #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) | shiftLeft(uint64(uint32(s.x[8])), 5, 32))))
	// 0x100236604: mov w12, #0x3b
	s.x[12] = uint64(uint32(uint64(0x3b)))
	// 0x100236608: and w9, w12, w8, lsr #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) & shiftRight(uint64(uint32(s.x[8])), 1, 32))))
	// 0x10023660c: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100236610: eor w8, w8, #0xffffff81
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0xffffff81))))
	// 0x100236614: ldur x9, [x29, #-0xb0]
	value1614, err := s.load(addOffset(s.x[29], -176), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1614)
	// 0x100236618: ldr x10, [sp, #0x428]
	value1615, err := s.load(addOffset(s.sp, 1064), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1615)
	// 0x10023661c: strb w8, [x9, x10]
	if err := s.storeValue((s.x[9] + s.x[10]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x100236620: ldur x15, [x29, #-0xa0]
	value1617, err := s.load(addOffset(s.x[29], -160), 8)
	if err != nil {
		return err
	}
	s.x[15] = uint64(value1617)
	// 0x100236624: ldr w8, [x15]
	value1618, err := s.load(s.x[15], 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1618))
	// 0x100236628: eor w8, w8, w27
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[27])))))
	// 0x10023662c: ldr w9, [x25, #0x588]
	value1620, err := s.load(addOffset(s.x[25], 1416), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1620))
	// 0x100236630: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100236634: mov w13, #0xd4cf
	s.x[13] = uint64(uint32(uint64(0xd4cf)))
	// 0x100236638: movk w13, #0xa5c, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0xa5c, 16, 16, 32)))
	// 0x10023663c: mul w8, w8, w13
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) * uint64(uint32(s.x[13])))))
	// 0x100236640: ldur x9, [x29, #-0xd8]
	value1625, err := s.load(addOffset(s.x[29], -216), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1625)
	// 0x100236644: add x9, x9, w8, uxtb
	s.x[9] = uint64((s.x[9] + uint64(uint8(uint64(uint32(s.x[8]))))))
	// 0x100236648: ldrb w9, [x9]
	value1627, err := s.load(s.x[9], 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1627))
	// 0x10023664c: mov w11, #0x84
	s.x[11] = uint64(uint32(uint64(0x84)))
	// 0x100236650: eor w9, w9, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100236654: ldr x10, [sp, #0x3e8]
	value1630, err := s.load(addOffset(s.sp, 1000), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1630)
	// 0x100236658: ldrb w9, [x10, w9, uxtw]
	value1631, err := s.load((s.x[10] + uint64(uint32(uint64(uint32(s.x[9]))))), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1631))
	// 0x10023665c: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100236660: mov w9, #0x1292
	s.x[9] = uint64(uint32(uint64(0x1292)))
	// 0x100236664: add w8, w9, w8, uxtb
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint8(uint64(uint32(s.x[8])))))))
	// 0x100236668: ldr x8, [x26, w8, uxtw #3]
	value1635, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[8] = uint64(value1635)
	// 0x10023666c: lsr w9, w16, #0x18
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[16])), int(uint64(0x18)), 32)))
	// 0x100236670: eor x9, x9, #8
	s.x[9] = uint64((s.x[9] ^ uint64(0x8)))
	// 0x100236674: mov x10, #-0x26b2
	s.x[10] = uint64(uint64(0xffffffffffffd94e))
	// 0x100236678: movk x10, #0xf7ae, lsl #16
	s.x[10] = uint64(insertBits(s.x[10], 0xf7ae, 16, 16, 64))
	// 0x10023667c: add x20, x8, x10
	s.x[20] = uint64((s.x[8] + s.x[10]))
	// 0x100236680: ldrb w8, [x20, x9]
	value1641, err := s.load((s.x[20] + s.x[9]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1641))
	// 0x100236684: lsr w9, w8, #3
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x3)), 32)))
	// 0x100236688: orr w8, w9, w8, lsl #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) | shiftLeft(uint64(uint32(s.x[8])), 5, 32))))
	// 0x10023668c: mov w9, #0x68
	s.x[9] = uint64(uint32(uint64(0x68)))
	// 0x100236690: bfxil w9, w8, #5, #3
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), uint64(uint32(s.x[8]))>>5, 0, 3, 32)))
	// 0x100236694: and w10, w8, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100236698: eor w8, w8, w10, lsr #1
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[10])), 1, 32))))
	// 0x10023669c: mov w10, #0x43
	s.x[10] = uint64(uint32(uint64(0x43)))
	// 0x1002366a0: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002366a4: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x1002366a8: ldur x9, [x29, #-0xb0]
	value1651, err := s.load(addOffset(s.x[29], -176), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1651)
	// 0x1002366ac: ldr x10, [sp, #0x448]
	value1652, err := s.load(addOffset(s.sp, 1096), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1652)
	// 0x1002366b0: strb w8, [x9, x10]
	if err := s.storeValue((s.x[9] + s.x[10]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x1002366b4: ldr w8, [sp, #0x4b8]
	value1654, err := s.load(addOffset(s.sp, 1208), 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1654))
	// 0x1002366b8: ldr w9, [sp, #0x2d0]
	value1655, err := s.load(addOffset(s.sp, 720), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1655))
	// 0x1002366bc: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x1002366c0: ldr w9, [sp, #0x2d8]
	value1657, err := s.load(addOffset(s.sp, 728), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1657))
	// 0x1002366c4: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x1002366c8: add w9, w30, w17
	s.x[9] = uint64(uint32((uint64(uint32(s.x[30])) + uint64(uint32(s.x[17])))))
	// 0x1002366cc: ldur x30, [x29, #-0xb8]
	value1660, err := s.load(addOffset(s.x[29], -184), 8)
	if err != nil {
		return err
	}
	s.x[30] = uint64(value1660)
	// 0x1002366d0: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x1002366d4: and w9, w1, w2, lsl #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[1])) & shiftLeft(uint64(uint32(s.x[2])), 1, 32))))
	// 0x1002366d8: eor w9, w9, w3
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[3])))))
	// 0x1002366dc: eor w10, w2, w4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[2])) ^ uint64(uint32(s.x[4])))))
	// 0x1002366e0: add w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[10])))))
	// 0x1002366e4: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x1002366e8: and w9, w14, w9, lsr #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) & shiftRight(uint64(uint32(s.x[9])), 1, 32))))
	// 0x1002366ec: eor w8, w8, w19
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[19])))))
	// 0x1002366f0: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x1002366f4: eor w8, w8, w19, lsr #2
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[19])), 2, 32))))
	// 0x1002366f8: eor w8, w8, w19, lsr #3
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[19])), 3, 32))))
	// 0x1002366fc: eor w21, w8, w21
	s.x[21] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[21])))))
	// 0x100236700: lsr w8, w21, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[21])), int(uint64(0x18)), 32)))
	// 0x100236704: eor x8, x8, #0x1c
	s.x[8] = uint64((s.x[8] ^ uint64(0x1c)))
	// 0x100236708: ldrb w8, [x20, x8]
	value1675, err := s.load((s.x[20] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1675))
	// 0x10023670c: lsr w9, w8, #3
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x3)), 32)))
	// 0x100236710: orr w8, w9, w8, lsl #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) | shiftLeft(uint64(uint32(s.x[8])), 5, 32))))
	// 0x100236714: and w9, w8, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100236718: eor w8, w8, w9, lsr #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[9])), 5, 32))))
	// 0x10023671c: eor w8, w8, w9, lsr #1
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[9])), 1, 32))))
	// 0x100236720: eor w8, w8, #0xaaaaaaaa
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0xaaaaaaaa))))
	// 0x100236724: ldp x9, x4, [x29, #-0xb0]
	value1682a, err := s.load(addOffset(s.x[29], -176), 8)
	if err != nil {
		return err
	}
	value1682b, err := s.load((addOffset(s.x[29], -176))+8, 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1682a)
	s.x[4] = uint64(value1682b)
	// 0x100236728: ldr x10, [sp, #0x440]
	value1683, err := s.load(addOffset(s.sp, 1088), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1683)
	// 0x10023672c: strb w8, [x9, x10]
	if err := s.storeValue((s.x[9] + s.x[10]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x100236730: and w8, w21, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[21])) & uint64(0xff))))
	// 0x100236734: eor x8, x8, x11
	s.x[8] = uint64((s.x[8] ^ s.x[11]))
	// 0x100236738: mov w2, #0x84
	s.x[2] = uint64(uint32(uint64(0x84)))
	// 0x10023673c: ldrb w8, [x0, x8]
	value1688, err := s.load((s.x[0] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1688))
	// 0x100236740: lsr w9, w8, #3
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x3)), 32)))
	// 0x100236744: orr w8, w9, w8, lsl #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) | shiftLeft(uint64(uint32(s.x[8])), 5, 32))))
	// 0x100236748: and w9, w12, w8, lsr #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) & shiftRight(uint64(uint32(s.x[8])), 1, 32))))
	// 0x10023674c: mov w3, #0x3b
	s.x[3] = uint64(uint32(uint64(0x3b)))
	// 0x100236750: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100236754: eor w8, w8, #0x70
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0x70))))
	// 0x100236758: ldur x9, [x29, #-0xb0]
	value1695, err := s.load(addOffset(s.x[29], -176), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1695)
	// 0x10023675c: ldr x10, [sp, #0x430]
	value1696, err := s.load(addOffset(s.sp, 1072), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1696)
	// 0x100236760: strb w8, [x9, x10]
	if err := s.storeValue((s.x[9] + s.x[10]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x100236764: ldr w8, [x15]
	value1698, err := s.load(s.x[15], 4)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1698))
	// 0x100236768: eor w8, w8, w27
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[27])))))
	// 0x10023676c: ldr w9, [x25, #0x588]
	value1700, err := s.load(addOffset(s.x[25], 1416), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1700))
	// 0x100236770: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100236774: mul w8, w8, w13
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) * uint64(uint32(s.x[13])))))
	// 0x100236778: mov w12, #0xd4cf
	s.x[12] = uint64(uint32(uint64(0xd4cf)))
	// 0x10023677c: movk w12, #0xa5c, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xa5c, 16, 16, 32)))
	// 0x100236780: mov x19, x30
	s.x[19] = uint64(s.x[30])
	// 0x100236784: add x9, x30, w8, uxtb
	s.x[9] = uint64((s.x[30] + uint64(uint8(uint64(uint32(s.x[8]))))))
	// 0x100236788: ldrb w9, [x9]
	value1707, err := s.load(s.x[9], 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1707))
	// 0x10023678c: mov w10, #0x5d
	s.x[10] = uint64(uint32(uint64(0x5d)))
	// 0x100236790: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100236794: ldrb w9, [x4, w9, uxtw]
	value1710, err := s.load((s.x[4] + uint64(uint32(uint64(uint32(s.x[9]))))), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1710))
	// 0x100236798: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x10023679c: ubfx w9, w16, #0x10, #8
	s.x[9] = uint64(uint32((uint64(uint32(s.x[16])) >> 16) & bitMask(8, 32)))
	// 0x1002367a0: mov w10, #0x37
	s.x[10] = uint64(uint32(uint64(0x37)))
	// 0x1002367a4: eor x9, x9, x10
	s.x[9] = uint64((s.x[9] ^ s.x[10]))
	// 0x1002367a8: and w8, w8, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x1002367ac: add w8, w8, #0x3e
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(0x3e))))
	// 0x1002367b0: ldr x8, [x26, w8, uxtw #3]
	value1717, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[8])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[8] = uint64(value1717)
	// 0x1002367b4: mov x10, #-0xb9aa
	s.x[10] = uint64(uint64(0xffffffffffff4656))
	// 0x1002367b8: movk x10, #0xf734, lsl #16
	s.x[10] = uint64(insertBits(s.x[10], 0xf734, 16, 16, 64))
	// 0x1002367bc: add x8, x8, x10
	s.x[8] = uint64((s.x[8] + s.x[10]))
	// 0x1002367c0: ldrb w9, [x8, x9]
	value1721, err := s.load((s.x[8] + s.x[9]), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1721))
	// 0x1002367c4: mov w10, #0x54
	s.x[10] = uint64(uint32(uint64(0x54)))
	// 0x1002367c8: eor w10, w10, w16, lsr #16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[16])), 16, 32))))
	// 0x1002367cc: add w10, w10, #0x68
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(0x68))))
	// 0x1002367d0: mov w11, #0x59
	s.x[11] = uint64(uint32(uint64(0x59)))
	// 0x1002367d4: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x1002367d8: eor w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[9])))))
	// 0x1002367dc: ldur x10, [x29, #-0xb0]
	value1728, err := s.load(addOffset(s.x[29], -176), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1728)
	// 0x1002367e0: ldr x11, [sp, #0x438]
	value1729, err := s.load(addOffset(s.sp, 1080), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value1729)
	// 0x1002367e4: strb w9, [x10, x11]
	if err := s.storeValue((s.x[10] + s.x[11]), uint64(uint32(s.x[9])), 1); err != nil {
		return err
	}
	// 0x1002367e8: lsr w9, w21, #4
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[21])), int(uint64(0x4)), 32)))
	// 0x1002367ec: and w9, w9, #0xf0
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xf0))))
	// 0x1002367f0: ubfx w10, w21, #0xc, #4
	s.x[10] = uint64(uint32((uint64(uint32(s.x[21])) >> 12) & bitMask(4, 32)))
	// 0x1002367f4: mov w11, #0xf6
	s.x[11] = uint64(uint32(uint64(0xf6)))
	// 0x1002367f8: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x1002367fc: mov w11, #0x5f
	s.x[11] = uint64(uint32(uint64(0x5f)))
	// 0x100236800: eor w9, w9, w11
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100236804: and w9, w10, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(uint32(s.x[9])))))
	// 0x100236808: eor w9, w9, #0xfffffffd
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(0xfffffffd))))
	// 0x10023680c: lsl w10, w21, #0x14
	s.x[10] = uint64(uint32(shiftLeft(uint64(uint32(s.x[21])), int(uint64(0x14)), 32)))
	// 0x100236810: eor w10, w10, #0x80000000
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(0x80000000))))
	// 0x100236814: extr w9, w9, w10, #0x1c
	s.x[9] = uint64(uint32(extractPair(uint64(uint32(s.x[9])), uint64(uint32(s.x[10])), 28, 32)))
	// 0x100236818: ldr w10, [x25, #0x588]
	value1743, err := s.load(addOffset(s.x[25], 1416), 4)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1743))
	// 0x10023681c: ldr w11, [x15]
	value1744, err := s.load(s.x[15], 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value1744))
	// 0x100236820: sub w10, w11, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) - uint64(uint32(s.x[10])))))
	// 0x100236824: eor w10, w10, w27
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[27])))))
	// 0x100236828: mov x30, x7
	s.x[30] = uint64(s.x[7])
	// 0x10023682c: mul w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) * uint64(uint32(s.x[12])))))
	// 0x100236830: add x11, x7, w10, uxtb
	s.x[11] = uint64((s.x[7] + uint64(uint8(uint64(uint32(s.x[10]))))))
	// 0x100236834: ldrb w11, [x11]
	value1750, err := s.load(s.x[11], 1)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value1750))
	// 0x100236838: mov w12, #0xfb
	s.x[12] = uint64(uint32(uint64(0xfb)))
	// 0x10023683c: eor w11, w11, w12
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x100236840: ldrb w11, [x28, w11, uxtw]
	value1753, err := s.load((s.x[28] + uint64(uint32(uint64(uint32(s.x[11]))))), 1)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value1753))
	// 0x100236844: ldur x28, [x29, #-0xb0]
	value1754, err := s.load(addOffset(s.x[29], -176), 8)
	if err != nil {
		return err
	}
	s.x[28] = uint64(value1754)
	// 0x100236848: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x10023684c: and x9, x9, #0xff
	s.x[9] = uint64((s.x[9] & uint64(0xff)))
	// 0x100236850: mov w11, #0x2a
	s.x[11] = uint64(uint32(uint64(0x2a)))
	// 0x100236854: eor x9, x9, x11
	s.x[9] = uint64((s.x[9] ^ s.x[11]))
	// 0x100236858: and w10, w10, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0xff))))
	// 0x10023685c: add w10, w10, #0xf1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(0xf1))))
	// 0x100236860: ldr x10, [x26, w10, uxtw #3]
	value1761, err := s.load((s.x[26] + shiftLeft(uint64(uint32(uint64(uint32(s.x[10])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1761)
	// 0x100236864: mov x11, #-0xf277
	s.x[11] = uint64(uint64(0xffffffffffff0d89))
	// 0x100236868: movk x11, #0xa9f8, lsl #16
	s.x[11] = uint64(insertBits(s.x[11], 0xa9f8, 16, 16, 64))
	// 0x10023686c: add x12, x10, x11
	s.x[12] = uint64((s.x[10] + s.x[11]))
	// 0x100236870: ldrb w9, [x12, x9]
	value1765, err := s.load((s.x[12] + s.x[9]), 1)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1765))
	// 0x100236874: eor w9, w9, #0x3c
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(0x3c))))
	// 0x100236878: ldr x10, [sp, #0x478]
	value1767, err := s.load(addOffset(s.sp, 1144), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1767)
	// 0x10023687c: strb w9, [x28, x10]
	if err := s.storeValue((s.x[28] + s.x[10]), uint64(uint32(s.x[9])), 1); err != nil {
		return err
	}
	// 0x100236880: mov w9, #0x9a46
	s.x[9] = uint64(uint32(uint64(0x9a46)))
	// 0x100236884: movk w9, #0x7bd6, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x7bd6, 16, 16, 32)))
	// 0x100236888: eor w9, w5, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[9])))))
	// 0x10023688c: mov w10, #0x65ba
	s.x[10] = uint64(uint32(uint64(0x65ba)))
	// 0x100236890: movk w10, #0x8429, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x8429, 16, 16, 32)))
	// 0x100236894: add w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[10])))))
	// 0x100236898: mov w10, #0x62c3
	s.x[10] = uint64(uint32(uint64(0x62c3)))
	// 0x10023689c: movk w10, #0x3f8a, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x3f8a, 16, 16, 32)))
	// 0x1002368a0: eor w10, w5, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[10])))))
	// 0x1002368a4: mov w11, #0x9d3d
	s.x[11] = uint64(uint32(uint64(0x9d3d)))
	// 0x1002368a8: movk w11, #0xc075, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0xc075, 16, 16, 32)))
	// 0x1002368ac: add w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[11])))))
	// 0x1002368b0: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002368b4: mov w10, #0xebf
	s.x[10] = uint64(uint32(uint64(0xebf)))
	// 0x1002368b8: movk w10, #0x8197, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x8197, 16, 16, 32)))
	// 0x1002368bc: eor w10, w5, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[5])) ^ uint64(uint32(s.x[10])))))
	// 0x1002368c0: mov w11, #0xf141
	s.x[11] = uint64(uint32(uint64(0xf141)))
	// 0x1002368c4: movk w11, #0x7e68, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x7e68, 16, 16, 32)))
	// 0x1002368c8: add w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[11])))))
	// 0x1002368cc: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002368d0: mov w10, #0x8e19
	s.x[10] = uint64(uint32(uint64(0x8e19)))
	// 0x1002368d4: movk w10, #0x2ee0, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x2ee0, 16, 16, 32)))
	// 0x1002368d8: eor w10, w23, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[23])) ^ uint64(uint32(s.x[10])))))
	// 0x1002368dc: mov w11, #0x71e7
	s.x[11] = uint64(uint32(uint64(0x71e7)))
	// 0x1002368e0: movk w11, #0xd11f, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0xd11f, 16, 16, 32)))
	// 0x1002368e4: add w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[11])))))
	// 0x1002368e8: mov w11, #0xa300
	s.x[11] = uint64(uint32(uint64(0xa300)))
	// 0x1002368ec: movk w11, #0x745f, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x745f, 16, 16, 32)))
	// 0x1002368f0: eor w11, w23, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[23])) ^ uint64(uint32(s.x[11])))))
	// 0x1002368f4: mov w13, #0x5d00
	s.x[13] = uint64(uint32(uint64(0x5d00)))
	// 0x1002368f8: movk w13, #0x8ba0, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x8ba0, 16, 16, 32)))
	// 0x1002368fc: add w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[13])))))
	// 0x100236900: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236904: mov w11, #0xdb23
	s.x[11] = uint64(uint32(uint64(0xdb23)))
	// 0x100236908: movk w11, #0x9f74, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x9f74, 16, 16, 32)))
	// 0x10023690c: eor w11, w23, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[23])) ^ uint64(uint32(s.x[11])))))
	// 0x100236910: mov w13, #0x24dd
	s.x[13] = uint64(uint32(uint64(0x24dd)))
	// 0x100236914: movk w13, #0x608b, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x608b, 16, 16, 32)))
	// 0x100236918: add w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[13])))))
	// 0x10023691c: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236920: ldr w11, [sp, #0x3c4]
	value1809, err := s.load(addOffset(s.sp, 964), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value1809))
	// 0x100236924: ldr w13, [sp, #0x4bc]
	value1810, err := s.load(addOffset(s.sp, 1212), 4)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1810))
	// 0x100236928: eor w11, w13, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[11])))))
	// 0x10023692c: ldr w13, [sp, #0x424]
	value1812, err := s.load(addOffset(s.sp, 1060), 4)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1812))
	// 0x100236930: add w13, w13, w17
	s.x[13] = uint64(uint32((uint64(uint32(s.x[13])) + uint64(uint32(s.x[17])))))
	// 0x100236934: eor w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236938: eor w11, w11, w6
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[6])))))
	// 0x10023693c: eor w11, w11, w6, lsr #2
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ shiftRight(uint64(uint32(s.x[6])), 2, 32))))
	// 0x100236940: eor w11, w11, w6, lsr #3
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ shiftRight(uint64(uint32(s.x[6])), 3, 32))))
	// 0x100236944: eor w11, w11, w24
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[24])))))
	// 0x100236948: mov w1, #0x5a8
	s.x[1] = uint64(uint32(uint64(0x5a8)))
	// 0x10023694c: movk w1, #0x499d, lsl #16
	s.x[1] = uint64(uint32(insertBits(uint64(uint32(s.x[1])), 0x499d, 16, 16, 32)))
	// 0x100236950: add w9, w9, w1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[1])))))
	// 0x100236954: eor w11, w11, w9
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[9])))))
	// 0x100236958: and w9, w14, w9, lsr #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[14])) & shiftRight(uint64(uint32(s.x[9])), 1, 32))))
	// 0x10023695c: eor w11, w11, w9
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[9])))))
	// 0x100236960: ldr w9, [sp, #0x3d4]
	value1825, err := s.load(addOffset(s.sp, 980), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value1825))
	// 0x100236964: ldr w13, [sp, #0x4c0]
	value1826, err := s.load(addOffset(s.sp, 1216), 4)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1826))
	// 0x100236968: eor w9, w13, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[9])))))
	// 0x10023696c: ldr w13, [sp, #0x410]
	value1828, err := s.load(addOffset(s.sp, 1040), 4)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1828))
	// 0x100236970: add w13, w13, w17
	s.x[13] = uint64(uint32((uint64(uint32(s.x[13])) + uint64(uint32(s.x[17])))))
	// 0x100236974: eor w9, w9, w13
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[13])))))
	// 0x100236978: eor w9, w9, w22
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[22])))))
	// 0x10023697c: eor w9, w9, w22, lsr #2
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ shiftRight(uint64(uint32(s.x[22])), 2, 32))))
	// 0x100236980: eor w9, w9, w22, lsr #3
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ shiftRight(uint64(uint32(s.x[22])), 3, 32))))
	// 0x100236984: add w10, w10, w1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[1])))))
	// 0x100236988: ldr w13, [sp, #0x408]
	value1835, err := s.load(addOffset(s.sp, 1032), 4)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1835))
	// 0x10023698c: eor w13, w13, w10
	s.x[13] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[10])))))
	// 0x100236990: and w10, w14, w10, lsr #1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[14])) & shiftRight(uint64(uint32(s.x[10])), 1, 32))))
	// 0x100236994: eor w10, w13, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[10])))))
	// 0x100236998: ubfx w13, w11, #8, #8
	s.x[13] = uint64(uint32((uint64(uint32(s.x[11])) >> 8) & bitMask(8, 32)))
	// 0x10023699c: eor x13, x13, #0xc
	s.x[13] = uint64((s.x[13] ^ uint64(0xc)))
	// 0x1002369a0: ldrb w13, [x12, x13]
	value1841, err := s.load((s.x[12] + s.x[13]), 1)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1841))
	// 0x1002369a4: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x1002369a8: eor w10, w13, #0x3c
	s.x[10] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(0x3c))))
	// 0x1002369ac: ldr x13, [sp, #0x488]
	value1844, err := s.load(addOffset(s.sp, 1160), 8)
	if err != nil {
		return err
	}
	s.x[13] = uint64(value1844)
	// 0x1002369b0: strb w10, [x28, x13]
	if err := s.storeValue((s.x[28] + s.x[13]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x1002369b4: and w10, w9, #0xff
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(0xff))))
	// 0x1002369b8: mov w13, #0xcf
	s.x[13] = uint64(uint32(uint64(0xcf)))
	// 0x1002369bc: eor x10, x10, x13
	s.x[10] = uint64((s.x[10] ^ s.x[13]))
	// 0x1002369c0: ldrb w10, [x0, x10]
	value1849, err := s.load((s.x[0] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1849))
	// 0x1002369c4: lsr w13, w10, #3
	s.x[13] = uint64(uint32(shiftRight(uint64(uint32(s.x[10])), int(uint64(0x3)), 32)))
	// 0x1002369c8: orr w10, w13, w10, lsl #5
	s.x[10] = uint64(uint32((uint64(uint32(s.x[13])) | shiftLeft(uint64(uint32(s.x[10])), 5, 32))))
	// 0x1002369cc: and w13, w3, w10, lsr #1
	s.x[13] = uint64(uint32((uint64(uint32(s.x[3])) & shiftRight(uint64(uint32(s.x[10])), 1, 32))))
	// 0x1002369d0: mov w14, #0x23
	s.x[14] = uint64(uint32(uint64(0x23)))
	// 0x1002369d4: eor w13, w13, w14
	s.x[13] = uint64(uint32((uint64(uint32(s.x[13])) ^ uint64(uint32(s.x[14])))))
	// 0x1002369d8: mov w14, #0x55
	s.x[14] = uint64(uint32(uint64(0x55)))
	// 0x1002369dc: eor w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x1002369e0: and w14, w13, w10
	s.x[14] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(uint32(s.x[10])))))
	// 0x1002369e4: add w10, w13, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[13])) + uint64(uint32(s.x[10])))))
	// 0x1002369e8: sub w10, w10, w14, lsl #1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) - shiftLeft(uint64(uint32(s.x[14])), 1, 32))))
	// 0x1002369ec: ldr x13, [sp, #0x498]
	value1860, err := s.load(addOffset(s.sp, 1176), 8)
	if err != nil {
		return err
	}
	s.x[13] = uint64(value1860)
	// 0x1002369f0: strb w10, [x28, x13]
	if err := s.storeValue((s.x[28] + s.x[13]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x1002369f4: lsr w10, w11, #0x18
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x18)), 32)))
	// 0x1002369f8: mov w13, #0x9d
	s.x[13] = uint64(uint32(uint64(0x9d)))
	// 0x1002369fc: eor x10, x10, x13
	s.x[10] = uint64((s.x[10] ^ s.x[13]))
	// 0x100236a00: ldrb w10, [x20, x10]
	value1865, err := s.load((s.x[20] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1865))
	// 0x100236a04: lsr w13, w10, #3
	s.x[13] = uint64(uint32(shiftRight(uint64(uint32(s.x[10])), int(uint64(0x3)), 32)))
	// 0x100236a08: orr w10, w13, w10, lsl #5
	s.x[10] = uint64(uint32((uint64(uint32(s.x[13])) | shiftLeft(uint64(uint32(s.x[10])), 5, 32))))
	// 0x100236a0c: and w13, w10, #0xff
	s.x[13] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0xff))))
	// 0x100236a10: eor w10, w10, w13, lsr #5
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[13])), 5, 32))))
	// 0x100236a14: eor w10, w10, w13, lsr #1
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[13])), 1, 32))))
	// 0x100236a18: mov w13, #0xca
	s.x[13] = uint64(uint32(uint64(0xca)))
	// 0x100236a1c: eor w10, w10, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x100236a20: ldr x13, [sp, #0x480]
	value1873, err := s.load(addOffset(s.sp, 1152), 8)
	if err != nil {
		return err
	}
	s.x[13] = uint64(value1873)
	// 0x100236a24: strb w10, [x28, x13]
	if err := s.storeValue((s.x[28] + s.x[13]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x100236a28: lsr w10, w11, #0x10
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[11])), int(uint64(0x10)), 32)))
	// 0x100236a2c: ubfx w13, w11, #0x10, #8
	s.x[13] = uint64(uint32((uint64(uint32(s.x[11])) >> 16) & bitMask(8, 32)))
	// 0x100236a30: mov w14, #0x64
	s.x[14] = uint64(uint32(uint64(0x64)))
	// 0x100236a34: eor x13, x13, x14
	s.x[13] = uint64((s.x[13] ^ s.x[14]))
	// 0x100236a38: ldrb w13, [x8, x13]
	value1879, err := s.load((s.x[8] + s.x[13]), 1)
	if err != nil {
		return err
	}
	s.x[13] = uint64(uint32(value1879))
	// 0x100236a3c: eor w10, w10, #7
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(0x7))))
	// 0x100236a40: add w10, w10, #0x68
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(0x68))))
	// 0x100236a44: mov w14, #0xab
	s.x[14] = uint64(uint32(uint64(0xab)))
	// 0x100236a48: eor w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100236a4c: eor w10, w10, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x100236a50: ldr x13, [sp, #0x468]
	value1885, err := s.load(addOffset(s.sp, 1128), 8)
	if err != nil {
		return err
	}
	s.x[13] = uint64(value1885)
	// 0x100236a54: strb w10, [x28, x13]
	if err := s.storeValue((s.x[28] + s.x[13]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x100236a58: ubfx w10, w16, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[16])) >> 8) & bitMask(8, 32)))
	// 0x100236a5c: mov w13, #0xa
	s.x[13] = uint64(uint32(uint64(0xa)))
	// 0x100236a60: eor x10, x10, x13
	s.x[10] = uint64((s.x[10] ^ s.x[13]))
	// 0x100236a64: ldrb w10, [x12, x10]
	value1890, err := s.load((s.x[12] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1890))
	// 0x100236a68: eor w10, w10, #0x7c
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(0x7c))))
	// 0x100236a6c: ldr x13, [sp, #0x458]
	value1892, err := s.load(addOffset(s.sp, 1112), 8)
	if err != nil {
		return err
	}
	s.x[13] = uint64(value1892)
	// 0x100236a70: strb w10, [x28, x13]
	if err := s.storeValue((s.x[28] + s.x[13]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x100236a74: ubfx w10, w9, #8, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) >> 8) & bitMask(8, 32)))
	// 0x100236a78: mov w13, #0x32
	s.x[13] = uint64(uint32(uint64(0x32)))
	// 0x100236a7c: eor x10, x10, x13
	s.x[10] = uint64((s.x[10] ^ s.x[13]))
	// 0x100236a80: ldrb w10, [x12, x10]
	value1897, err := s.load((s.x[12] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1897))
	// 0x100236a84: eor w10, w10, #0x88888888
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(0x88888888))))
	// 0x100236a88: ldr x12, [sp, #0x470]
	value1899, err := s.load(addOffset(s.sp, 1136), 8)
	if err != nil {
		return err
	}
	s.x[12] = uint64(value1899)
	// 0x100236a8c: strb w10, [x28, x12]
	if err := s.storeValue((s.x[28] + s.x[12]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x100236a90: ubfx w10, w9, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) >> 16) & bitMask(8, 32)))
	// 0x100236a94: mov w12, #0xc1
	s.x[12] = uint64(uint32(uint64(0xc1)))
	// 0x100236a98: eor x10, x10, x12
	s.x[10] = uint64((s.x[10] ^ s.x[12]))
	// 0x100236a9c: ldrb w10, [x8, x10]
	value1904, err := s.load((s.x[8] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[10] = uint64(uint32(value1904))
	// 0x100236aa0: mov w12, #0xa2
	s.x[12] = uint64(uint32(uint64(0xa2)))
	// 0x100236aa4: eor w12, w12, w9, lsr #16
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ shiftRight(uint64(uint32(s.x[9])), 16, 32))))
	// 0x100236aa8: add w12, w12, #0x68
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) + uint64(0x68))))
	// 0x100236aac: mov w13, #0xf4
	s.x[13] = uint64(uint32(uint64(0xf4)))
	// 0x100236ab0: eor w12, w12, w13
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x100236ab4: eor w10, w12, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100236ab8: ldr x12, [sp, #0x4a0]
	value1911, err := s.load(addOffset(s.sp, 1184), 8)
	if err != nil {
		return err
	}
	s.x[12] = uint64(value1911)
	// 0x100236abc: strb w10, [x28, x12]
	if err := s.storeValue((s.x[28] + s.x[12]), uint64(uint32(s.x[10])), 1); err != nil {
		return err
	}
	// 0x100236ac0: ubfx w10, w21, #0x10, #8
	s.x[10] = uint64(uint32((uint64(uint32(s.x[21])) >> 16) & bitMask(8, 32)))
	// 0x100236ac4: mov w12, #0x6a
	s.x[12] = uint64(uint32(uint64(0x6a)))
	// 0x100236ac8: eor x10, x10, x12
	s.x[10] = uint64((s.x[10] ^ s.x[12]))
	// 0x100236acc: ldrb w8, [x8, x10]
	value1916, err := s.load((s.x[8] + s.x[10]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1916))
	// 0x100236ad0: mov w10, #9
	s.x[10] = uint64(uint32(uint64(0x9)))
	// 0x100236ad4: eor w10, w10, w21, lsr #16
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ shiftRight(uint64(uint32(s.x[21])), 16, 32))))
	// 0x100236ad8: add w10, w10, #0x68
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(0x68))))
	// 0x100236adc: eor w8, w10, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[8])))))
	// 0x100236ae0: eor w8, w8, #0xfffffffd
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0xfffffffd))))
	// 0x100236ae4: ldr x10, [sp, #0x450]
	value1922, err := s.load(addOffset(s.sp, 1104), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value1922)
	// 0x100236ae8: strb w8, [x28, x10]
	if err := s.storeValue((s.x[28] + s.x[10]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x100236aec: lsr w8, w9, #0x18
	s.x[8] = uint64(uint32(shiftRight(uint64(uint32(s.x[9])), int(uint64(0x18)), 32)))
	// 0x100236af0: mov w9, #0xac
	s.x[9] = uint64(uint32(uint64(0xac)))
	// 0x100236af4: eor x8, x8, x9
	s.x[8] = uint64((s.x[8] ^ s.x[9]))
	// 0x100236af8: ldrb w8, [x20, x8]
	value1927, err := s.load((s.x[20] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1927))
	// 0x100236afc: lsr w9, w8, #3
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x3)), 32)))
	// 0x100236b00: orr w8, w9, w8, lsl #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) | shiftLeft(uint64(uint32(s.x[8])), 5, 32))))
	// 0x100236b04: and w9, w8, #0xff
	s.x[9] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(0xff))))
	// 0x100236b08: eor w8, w8, w9, lsr #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[9])), 5, 32))))
	// 0x100236b0c: eor w8, w8, w9, lsr #1
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ shiftRight(uint64(uint32(s.x[9])), 1, 32))))
	// 0x100236b10: mov w9, #5
	s.x[9] = uint64(uint32(uint64(0x5)))
	// 0x100236b14: eor w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[9])))))
	// 0x100236b18: ldr x9, [sp, #0x490]
	value1935, err := s.load(addOffset(s.sp, 1168), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value1935)
	// 0x100236b1c: strb w8, [x28, x9]
	if err := s.storeValue((s.x[28] + s.x[9]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x100236b20: and w8, w11, #0xff
	s.x[8] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(0xff))))
	// 0x100236b24: mov w9, #0xbf
	s.x[9] = uint64(uint32(uint64(0xbf)))
	// 0x100236b28: eor x8, x8, x9
	s.x[8] = uint64((s.x[8] ^ s.x[9]))
	// 0x100236b2c: ldrb w8, [x0, x8]
	value1940, err := s.load((s.x[0] + s.x[8]), 1)
	if err != nil {
		return err
	}
	s.x[8] = uint64(uint32(value1940))
	// 0x100236b30: lsr w9, w8, #3
	s.x[9] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x3)), 32)))
	// 0x100236b34: orr w8, w9, w8, lsl #5
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) | shiftLeft(uint64(uint32(s.x[8])), 5, 32))))
	// 0x100236b38: mov w9, #0x5110
	s.x[9] = uint64(uint32(uint64(0x5110)))
	// 0x100236b3c: movk w9, #0x7d57, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x7d57, 16, 16, 32)))
	// 0x100236b40: ldr w12, [sp, #0x464]
	value1945, err := s.load(addOffset(s.sp, 1124), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value1945))
	// 0x100236b44: eor w9, w12, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[9])))))
	// 0x100236b48: mov w10, #0xaef0
	s.x[10] = uint64(uint32(uint64(0xaef0)))
	// 0x100236b4c: movk w10, #0x82a8, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x82a8, 16, 16, 32)))
	// 0x100236b50: add w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[10])))))
	// 0x100236b54: mov w10, #0xb5c3
	s.x[10] = uint64(uint32(uint64(0xb5c3)))
	// 0x100236b58: movk w10, #0xccee, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xccee, 16, 16, 32)))
	// 0x100236b5c: eor w10, w12, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100236b60: mov w11, #0x4a3d
	s.x[11] = uint64(uint32(uint64(0x4a3d)))
	// 0x100236b64: movk w11, #0x3311, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x3311, 16, 16, 32)))
	// 0x100236b68: add w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[11])))))
	// 0x100236b6c: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100236b70: mov w10, #0x75cf
	s.x[10] = uint64(uint32(uint64(0x75cf)))
	// 0x100236b74: movk w10, #0xed1e, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xed1e, 16, 16, 32)))
	// 0x100236b78: eor w10, w12, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100236b7c: mov w11, #0x8a31
	s.x[11] = uint64(uint32(uint64(0x8a31)))
	// 0x100236b80: movk w11, #0x12e1, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x12e1, 16, 16, 32)))
	// 0x100236b84: add w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) + uint64(uint32(s.x[11])))))
	// 0x100236b88: eor w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100236b8c: mov w10, #0x145f
	s.x[10] = uint64(uint32(uint64(0x145f)))
	// 0x100236b90: movk w10, #0xd162, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xd162, 16, 16, 32)))
	// 0x100236b94: add w9, w9, w10
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) + uint64(uint32(s.x[10])))))
	// 0x100236b98: mov w10, #0xc9d7
	s.x[10] = uint64(uint32(uint64(0xc9d7)))
	// 0x100236b9c: movk w10, #0xb691, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0xb691, 16, 16, 32)))
	// 0x100236ba0: eor w10, w9, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[10])))))
	// 0x100236ba4: mov w11, #0x7ccd
	s.x[11] = uint64(uint32(uint64(0x7ccd)))
	// 0x100236ba8: movk w11, #0x8b45, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x8b45, 16, 16, 32)))
	// 0x100236bac: and w11, w9, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[9])) & uint64(uint32(s.x[11])))))
	// 0x100236bb0: mov w12, #0x78cd
	s.x[12] = uint64(uint32(uint64(0x78cd)))
	// 0x100236bb4: movk w12, #0xa211, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0xa211, 16, 16, 32)))
	// 0x100236bb8: eor w12, w9, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[12])))))
	// 0x100236bbc: and w12, w12, w11, lsl #1
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & shiftLeft(uint64(uint32(s.x[11])), 1, 32))))
	// 0x100236bc0: eor w11, w12, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[11])))))
	// 0x100236bc4: lsl w12, w10, #1
	s.x[12] = uint64(uint32(shiftLeft(uint64(uint32(s.x[10])), int(uint64(0x1)), 32)))
	// 0x100236bc8: mov w13, #0x6a34
	s.x[13] = uint64(uint32(uint64(0x6a34)))
	// 0x100236bcc: movk w13, #0x7ba9, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x7ba9, 16, 16, 32)))
	// 0x100236bd0: eor w13, w12, w13
	s.x[13] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x100236bd4: and w10, w13, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(uint32(s.x[10])))))
	// 0x100236bd8: mov w14, #0xb51a
	s.x[14] = uint64(uint32(uint64(0xb51a)))
	// 0x100236bdc: movk w14, #0x3dd4, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x3dd4, 16, 16, 32)))
	// 0x100236be0: and w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[14])))))
	// 0x100236be4: eor w10, w10, w12
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100236be8: mov w12, #0x950a
	s.x[12] = uint64(uint32(uint64(0x950a)))
	// 0x100236bec: movk w12, #0x454, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x454, 16, 16, 32)))
	// 0x100236bf0: eor w12, w10, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[12])))))
	// 0x100236bf4: mov w13, #0x2010
	s.x[13] = uint64(uint32(uint64(0x2010)))
	// 0x100236bf8: movk w13, #0x3900, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x3900, 16, 16, 32)))
	// 0x100236bfc: eor w10, w10, w13
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[13])))))
	// 0x100236c00: and w10, w10, w11, lsl #2
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & shiftLeft(uint64(uint32(s.x[11])), 2, 32))))
	// 0x100236c04: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236c08: lsl w11, w12, #2
	s.x[11] = uint64(uint32(shiftLeft(uint64(uint32(s.x[12])), int(uint64(0x2)), 32)))
	// 0x100236c0c: mov w13, #0xd468
	s.x[13] = uint64(uint32(uint64(0xd468)))
	// 0x100236c10: movk w13, #0xf752, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0xf752, 16, 16, 32)))
	// 0x100236c14: eor w13, w11, w13
	s.x[13] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236c18: and w12, w13, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(uint32(s.x[12])))))
	// 0x100236c1c: mov w13, #0xb518
	s.x[13] = uint64(uint32(uint64(0xb518)))
	// 0x100236c20: movk w13, #0x3dd4, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x3dd4, 16, 16, 32)))
	// 0x100236c24: and w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(uint32(s.x[13])))))
	// 0x100236c28: eor w11, w12, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[11])))))
	// 0x100236c2c: mov w12, #0x2112
	s.x[12] = uint64(uint32(uint64(0x2112)))
	// 0x100236c30: movk w12, #0x884, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x884, 16, 16, 32)))
	// 0x100236c34: eor w12, w11, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x100236c38: mov w13, #0x9400
	s.x[13] = uint64(uint32(uint64(0x9400)))
	// 0x100236c3c: movk w13, #0x3550, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x3550, 16, 16, 32)))
	// 0x100236c40: eor w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236c44: and w11, w11, w10, lsl #4
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & shiftLeft(uint64(uint32(s.x[10])), 4, 32))))
	// 0x100236c48: eor w10, w11, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[10])))))
	// 0x100236c4c: lsl w11, w12, #4
	s.x[11] = uint64(uint32(shiftLeft(uint64(uint32(s.x[12])), int(uint64(0x4)), 32)))
	// 0x100236c50: mov w13, #0x51a0
	s.x[13] = uint64(uint32(uint64(0x51a0)))
	// 0x100236c54: movk w13, #0xdd4b, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0xdd4b, 16, 16, 32)))
	// 0x100236c58: eor w13, w11, w13
	s.x[13] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236c5c: and w12, w13, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(uint32(s.x[12])))))
	// 0x100236c60: mov w13, #0xb500
	s.x[13] = uint64(uint32(uint64(0xb500)))
	// 0x100236c64: movk w13, #0x3dd4, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x3dd4, 16, 16, 32)))
	// 0x100236c68: and w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(uint32(s.x[13])))))
	// 0x100236c6c: eor w11, w12, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[11])))))
	// 0x100236c70: mov w12, #0xa41a
	s.x[12] = uint64(uint32(uint64(0xa41a)))
	// 0x100236c74: movk w12, #0x2094, lsl #16
	s.x[12] = uint64(uint32(insertBits(uint64(uint32(s.x[12])), 0x2094, 16, 16, 32)))
	// 0x100236c78: eor w12, w11, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x100236c7c: mov w13, #0x1100
	s.x[13] = uint64(uint32(uint64(0x1100)))
	// 0x100236c80: movk w13, #0x1d40, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0x1d40, 16, 16, 32)))
	// 0x100236c84: eor w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236c88: and w11, w11, w10, lsl #8
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & shiftLeft(uint64(uint32(s.x[10])), 8, 32))))
	// 0x100236c8c: eor w10, w10, w14
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[14])))))
	// 0x100236c90: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236c94: lsl w11, w12, #8
	s.x[11] = uint64(uint32(shiftLeft(uint64(uint32(s.x[12])), int(uint64(0x8)), 32)))
	// 0x100236c98: mov w13, #0x54b50000
	s.x[13] = uint64(uint32(uint64(0x54b50000)))
	// 0x100236c9c: eor w13, w11, w13
	s.x[13] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236ca0: and w12, w13, w12
	s.x[12] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(uint32(s.x[12])))))
	// 0x100236ca4: mov w14, #0x3dd40000
	s.x[14] = uint64(uint32(uint64(0x3dd40000)))
	// 0x100236ca8: and w11, w11, w14
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) & uint64(uint32(s.x[14])))))
	// 0x100236cac: mov w13, #0x29400000
	s.x[13] = uint64(uint32(uint64(0x29400000)))
	// 0x100236cb0: eor w11, w11, w13
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[13])))))
	// 0x100236cb4: eor w11, w11, w12
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[12])))))
	// 0x100236cb8: lsl w12, w10, #0x10
	s.x[12] = uint64(uint32(shiftLeft(uint64(uint32(s.x[10])), int(uint64(0x10)), 32)))
	// 0x100236cbc: mov w13, #0x351a0000
	s.x[13] = uint64(uint32(uint64(0x351a0000)))
	// 0x100236cc0: eor w13, w12, w13
	s.x[13] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[13])))))
	// 0x100236cc4: and w11, w13, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[13])) & uint64(uint32(s.x[11])))))
	// 0x100236cc8: and w12, w12, w14
	s.x[12] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[14])))))
	// 0x100236ccc: eor w10, w12, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[12])) ^ uint64(uint32(s.x[10])))))
	// 0x100236cd0: eor w10, w10, w11
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236cd4: ldr w12, [sp, #0x378]
	value2046, err := s.load(addOffset(s.sp, 888), 4)
	if err != nil {
		return err
	}
	s.x[12] = uint64(uint32(value2046))
	// 0x100236cd8: mov w13, #0xf1e1
	s.x[13] = uint64(uint32(uint64(0xf1e1)))
	// 0x100236cdc: movk w13, #0xb41e, lsl #16
	s.x[13] = uint64(uint32(insertBits(uint64(uint32(s.x[13])), 0xb41e, 16, 16, 32)))
	// 0x100236ce0: cmp w12, w13
	s.compare32(uint32(uint64(uint32(s.x[12]))), uint32(uint64(uint32(s.x[13]))))
	// 0x100236ce4: eor w9, w9, w10, lsl #1
	s.x[9] = uint64(uint32((uint64(uint32(s.x[9])) ^ shiftLeft(uint64(uint32(s.x[10])), 1, 32))))
	// 0x100236ce8: lsr w10, w8, #1
	s.x[10] = uint64(uint32(shiftRight(uint64(uint32(s.x[8])), int(uint64(0x1)), 32)))
	// 0x100236cec: and w10, w10, #0x3f
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) & uint64(0x3f))))
	// 0x100236cf0: orr w10, w10, w2
	s.x[10] = uint64(uint32((uint64(uint32(s.x[10])) | uint64(uint32(s.x[2])))))
	// 0x100236cf4: eor w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[10])))))
	// 0x100236cf8: cset w10, lo
	s.x[10] = uint64(uint32(boolValue(s.condition("lo"))))
	// 0x100236cfc: eor w8, w8, #0xfffffffb
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(0xfffffffb))))
	// 0x100236d00: ldr x11, [sp, #0x4a8]
	value2057, err := s.load(addOffset(s.sp, 1192), 8)
	if err != nil {
		return err
	}
	s.x[11] = uint64(value2057)
	// 0x100236d04: strb w8, [x28, x11]
	if err := s.storeValue((s.x[28] + s.x[11]), uint64(uint32(s.x[8])), 1); err != nil {
		return err
	}
	// 0x100236d08: mov w8, #0x2611
	s.x[8] = uint64(uint32(uint64(0x2611)))
	// 0x100236d0c: movk w8, #0x903b, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x903b, 16, 16, 32)))
	// 0x100236d10: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100236d14: mov w11, #0x5e0c
	s.x[11] = uint64(uint32(uint64(0x5e0c)))
	// 0x100236d18: movk w11, #0xa9af, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0xa9af, 16, 16, 32)))
	// 0x100236d1c: add w8, w8, w11
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[11])))))
	// 0x100236d20: mov w11, #0xfb95
	s.x[11] = uint64(uint32(uint64(0xfb95)))
	// 0x100236d24: movk w11, #0x1a88, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x1a88, 16, 16, 32)))
	// 0x100236d28: eor w11, w9, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100236d2c: mov w14, #0x8390
	s.x[14] = uint64(uint32(uint64(0x8390)))
	// 0x100236d30: movk w14, #0x231c, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x231c, 16, 16, 32)))
	// 0x100236d34: add w11, w11, w14
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[14])))))
	// 0x100236d38: eor w8, w8, w11
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[11])))))
	// 0x100236d3c: mov w11, #0xcb7d
	s.x[11] = uint64(uint32(uint64(0xcb7d)))
	// 0x100236d40: movk w11, #0x107f, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x107f, 16, 16, 32)))
	// 0x100236d44: eor w11, w9, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[11])))))
	// 0x100236d48: mov w14, #0xb368
	s.x[14] = uint64(uint32(uint64(0xb368)))
	// 0x100236d4c: movk w14, #0x29eb, lsl #16
	s.x[14] = uint64(uint32(insertBits(uint64(uint32(s.x[14])), 0x29eb, 16, 16, 32)))
	// 0x100236d50: add w11, w11, w14
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[14])))))
	// 0x100236d54: eor w8, w8, w11
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[11])))))
	// 0x100236d58: mov w11, #0x82fd
	s.x[11] = uint64(uint32(uint64(0x82fd)))
	// 0x100236d5c: movk w11, #0x10c6, lsl #16
	s.x[11] = uint64(uint32(insertBits(uint64(uint32(s.x[11])), 0x10c6, 16, 16, 32)))
	// 0x100236d60: add w8, w8, w11
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) + uint64(uint32(s.x[11])))))
	// 0x100236d64: cmp w8, w13
	s.compare32(uint32(uint64(uint32(s.x[8]))), uint32(uint64(uint32(s.x[13]))))
	// 0x100236d68: cset w11, lo
	s.x[11] = uint64(uint32(boolValue(s.condition("lo"))))
	// 0x100236d6c: eor w11, w10, w11
	s.x[11] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[11])))))
	// 0x100236d70: cmp w8, w12
	s.compare32(uint32(uint64(uint32(s.x[8]))), uint32(uint64(uint32(s.x[12]))))
	// 0x100236d74: cset w8, lo
	s.x[8] = uint64(uint32(boolValue(s.condition("lo"))))
	// 0x100236d78: cmp w11, #0
	s.compare32(uint32(uint64(uint32(s.x[11]))), uint32(uint64(0x0)))
	// 0x100236d7c: csel w8, w10, w8, ne
	s.x[8] = uint64(uint32(selectValue(s.condition("ne"), uint64(uint32(s.x[10])), uint64(uint32(s.x[8])))))
	// 0x100236d80: mov w10, #0x7f56
	s.x[10] = uint64(uint32(uint64(0x7f56)))
	// 0x100236d84: mul w8, w8, w10
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) * uint64(uint32(s.x[10])))))
	// 0x100236d88: ldr w11, [sp, #0x4c4]
	value2091, err := s.load(addOffset(s.sp, 1220), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value2091))
	// 0x100236d8c: eor w8, w8, w11
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) ^ uint64(uint32(s.x[11])))))
	// 0x100236d90: mov w10, #0x9315
	s.x[10] = uint64(uint32(uint64(0x9315)))
	// 0x100236d94: eor w11, w11, w10
	s.x[11] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[10])))))
	// 0x100236d98: ldur x10, [x29, #-0xe0]
	value2095, err := s.load(addOffset(s.x[29], -224), 8)
	if err != nil {
		return err
	}
	s.x[10] = uint64(value2095)
	// 0x100236d9c: ldr x8, [x10, w8, sxtw #3]
	value2096, err := s.load((s.x[10] + shiftLeft(signExtend32(uint32(uint64(uint32(s.x[8])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[8] = uint64(value2096)
	// 0x100236da0: mov x17, #0xe6c7
	s.x[17] = uint64(uint64(0xe6c7))
	// 0x100236da4: braa x8, x17
	// 0x100128818: mov w8, #0xd844
	s.x[8] = uint64(uint32(uint64(0xd844)))
	// 0x10012881c: movk w8, #0xad60, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0xad60, 16, 16, 32)))
	// 0x100128820: ldr w11, [sp, #0x404]
	value2101, err := s.load(addOffset(s.sp, 1028), 4)
	if err != nil {
		return err
	}
	s.x[11] = uint64(uint32(value2101))
	// 0x100128824: add w8, w11, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[11])) + uint64(uint32(s.x[8])))))
	// 0x100128828: mov w10, #0xfe8f
	s.x[10] = uint64(uint32(uint64(0xfe8f)))
	// 0x10012882c: movk w10, #0x28f1, lsl #16
	s.x[10] = uint64(uint32(insertBits(uint64(uint32(s.x[10])), 0x28f1, 16, 16, 32)))
	// 0x100128830: and w10, w8, w10
	s.x[10] = uint64(uint32((uint64(uint32(s.x[8])) & uint64(uint32(s.x[10])))))
	// 0x100128834: mov w8, #0x87e5
	s.x[8] = uint64(uint32(uint64(0x87e5)))
	// 0x100128838: movk w8, #0xc66b, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0xc66b, 16, 16, 32)))
	// 0x10012883c: eor w12, w9, w8
	s.x[12] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100128840: mov w8, #0x81d6
	s.x[8] = uint64(uint32(uint64(0x81d6)))
	// 0x100128844: movk w8, #0x4296, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x4296, 16, 16, 32)))
	// 0x100128848: eor w8, w10, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[8])))))
	// 0x10012884c: ldr w9, [sp, #0x3f8]
	value2112, err := s.load(addOffset(s.sp, 1016), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value2112))
	// 0x100128850: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100128854: str w8, [sp, #0x4b4]
	if err := s.storeValue(addOffset(s.sp, 1204), uint64(uint32(s.x[8])), 4); err != nil {
		return err
	}
	// 0x100128858: mov w8, #0x9cfd
	s.x[8] = uint64(uint32(uint64(0x9cfd)))
	// 0x10012885c: movk w8, #0xa099, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0xa099, 16, 16, 32)))
	// 0x100128860: ldr w9, [sp, #0x3f4]
	value2117, err := s.load(addOffset(s.sp, 1012), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value2117))
	// 0x100128864: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100128868: str w8, [sp, #0x4b8]
	if err := s.storeValue(addOffset(s.sp, 1208), uint64(uint32(s.x[8])), 4); err != nil {
		return err
	}
	// 0x10012886c: mov w8, #0x8d51
	s.x[8] = uint64(uint32(uint64(0x8d51)))
	// 0x100128870: movk w8, #0xb9f8, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0xb9f8, 16, 16, 32)))
	// 0x100128874: ldr w9, [sp, #0x3fc]
	value2122, err := s.load(addOffset(s.sp, 1020), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value2122))
	// 0x100128878: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x10012887c: str w8, [sp, #0x4bc]
	if err := s.storeValue(addOffset(s.sp, 1212), uint64(uint32(s.x[8])), 4); err != nil {
		return err
	}
	// 0x100128880: mov w8, #0x8ccb
	s.x[8] = uint64(uint32(uint64(0x8ccb)))
	// 0x100128884: movk w8, #0x1e5d, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x1e5d, 16, 16, 32)))
	// 0x100128888: ldr w9, [sp, #0x400]
	value2127, err := s.load(addOffset(s.sp, 1024), 4)
	if err != nil {
		return err
	}
	s.x[9] = uint64(uint32(value2127))
	// 0x10012888c: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x100128890: str w8, [sp, #0x4c0]
	if err := s.storeValue(addOffset(s.sp, 1216), uint64(uint32(s.x[8])), 4); err != nil {
		return err
	}
	// 0x100128894: mov w8, #0x2b41
	s.x[8] = uint64(uint32(uint64(0x2b41)))
	// 0x100128898: movk w8, #0x468b, lsl #16
	s.x[8] = uint64(uint32(insertBits(uint64(uint32(s.x[8])), 0x468b, 16, 16, 32)))
	// 0x10012889c: cmp w11, w8
	s.compare32(uint32(uint64(uint32(s.x[11]))), uint32(uint64(uint32(s.x[8]))))
	// 0x1001288a0: cset w8, hi
	s.x[8] = uint64(uint32(boolValue(s.condition("hi"))))
	// 0x1001288a4: mov w9, #0xa7ad
	s.x[9] = uint64(uint32(uint64(0xa7ad)))
	// 0x1001288a8: mul w8, w8, w9
	s.x[8] = uint64(uint32((uint64(uint32(s.x[8])) * uint64(uint32(s.x[9])))))
	// 0x1001288ac: mov w9, #0x872e
	s.x[9] = uint64(uint32(uint64(0x872e)))
	// 0x1001288b0: movk w9, #0x29ad, lsl #16
	s.x[9] = uint64(uint32(insertBits(uint64(uint32(s.x[9])), 0x29ad, 16, 16, 32)))
	// 0x1001288b4: eor w9, w11, w9
	s.x[9] = uint64(uint32((uint64(uint32(s.x[11])) ^ uint64(uint32(s.x[9])))))
	// 0x1001288b8: eor w8, w9, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[9])) ^ uint64(uint32(s.x[8])))))
	// 0x1001288bc: ldur x9, [x29, #-0xe0]
	value2140, err := s.load(addOffset(s.x[29], -224), 8)
	if err != nil {
		return err
	}
	s.x[9] = uint64(value2140)
	// 0x1001288c0: ldr x8, [x9, w8, sxtw #3]
	value2141, err := s.load((s.x[9] + shiftLeft(signExtend32(uint32(uint64(uint32(s.x[8])))), 3, 64)), 8)
	if err != nil {
		return err
	}
	s.x[8] = uint64(value2141)
	// 0x1001288c4: mov x17, #0x33ea
	s.x[17] = uint64(uint64(0x33ea))
	// 0x1001288c8: braa x8, x17
	// 0x100234cb8: str w10, [sp, #0x4c4]
	if err := s.storeValue(addOffset(s.sp, 1220), uint64(uint32(s.x[10])), 4); err != nil {
		return err
	}
	// 0x100234cbc: str wzr, [sp, #0x3f0]
	if err := s.storeValue(addOffset(s.sp, 1008), uint64(0), 4); err != nil {
		return err
	}
	// 0x100234cc0: mov w8, #-0xbc82
	s.x[8] = uint64(uint32(uint64(0xffff437e)))
	// 0x100234cc4: eor w8, w10, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[10])) ^ uint64(uint32(s.x[8])))))
	// 0x100234cc8: and w8, w12, w8
	s.x[8] = uint64(uint32((uint64(uint32(s.x[12])) & uint64(uint32(s.x[8])))))
	// 0x100234ccc: mov w27, #0x911f
	s.x[27] = uint64(uint32(uint64(0x911f)))
	// 0x100234cd0: movk w27, #0x5ca7, lsl #16
	s.x[27] = uint64(uint32(insertBits(uint64(uint32(s.x[27])), 0x5ca7, 16, 16, 32)))
	// 0x100234cd4: eor x8, x8, x27
	s.x[8] = uint64((s.x[8] ^ s.x[27]))
	// 0x100234cd8: str x8, [sp, #0x498]
	if err := s.storeValue(addOffset(s.sp, 1176), s.x[8], 8); err != nil {
		return err
	}
	return nil
}
