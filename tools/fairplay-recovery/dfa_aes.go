// This file is a Go adaptation of the Apache-2.0 DarkPhoenix AES helpers.
// See LICENSE-DARKPHOENIX.txt and the notices in the upstream DarkPhoenix work.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

var (
	dpShift    = [16]byte{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}
	dpInvShift = [16]byte{0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3}
	dpSbox     [256]byte
	dpInvSbox  [256]byte
	dpRcon     [32]byte
)

func init() {
	for index := 0; index < 256; index++ {
		inverse := dpGFInv(byte(index))
		rotated, value := inverse, inverse
		for range 4 {
			rotated = rotated<<1 | rotated>>7
			value ^= rotated
		}
		dpSbox[index] = value ^ 0x63
	}
	for index, value := range dpSbox {
		dpInvSbox[value] = byte(index)
	}
	dpRcon[1] = 1
	for index := 2; index < len(dpRcon); index++ {
		dpRcon[index] = dpXTime(dpRcon[index-1])
	}
}

func dpXTime(value byte) byte {
	result := value << 1
	if value&0x80 != 0 {
		result ^= 0x1b
	}
	return result
}

func dpGMul(left, right byte) byte {
	var result byte
	for right != 0 {
		if right&1 != 0 {
			result ^= left
		}
		left = dpXTime(left)
		right >>= 1
	}
	return result
}

func dpGFInv(value byte) byte {
	if value == 0 {
		return 0
	}
	result, base, exponent := byte(1), value, 254
	for exponent != 0 {
		if exponent&1 != 0 {
			result = dpGMul(result, base)
		}
		base = dpGMul(base, base)
		exponent >>= 1
	}
	return result
}

func dpShiftRows(input [16]byte) (output [16]byte) {
	for index, source := range dpShift {
		output[index] = input[source]
	}
	return
}

func dpInvShiftRows(input [16]byte) (output [16]byte) {
	for index, source := range dpInvShift {
		output[index] = input[source]
	}
	return
}

func dpSubBytes(input [16]byte) (output [16]byte) {
	for index, value := range input {
		output[index] = dpSbox[value]
	}
	return
}

func dpInvSubBytes(input [16]byte) (output [16]byte) {
	for index, value := range input {
		output[index] = dpInvSbox[value]
	}
	return
}

func dpXOR(left, right [16]byte) (output [16]byte) {
	for index := range output {
		output[index] = left[index] ^ right[index]
	}
	return
}

func dpMixColumns(input [16]byte) (output [16]byte) {
	for column := 0; column < 4; column++ {
		i := column * 4
		a, b, c, d := input[i], input[i+1], input[i+2], input[i+3]
		output[i] = dpGMul(2, a) ^ dpGMul(3, b) ^ c ^ d
		output[i+1] = a ^ dpGMul(2, b) ^ dpGMul(3, c) ^ d
		output[i+2] = a ^ b ^ dpGMul(2, c) ^ dpGMul(3, d)
		output[i+3] = dpGMul(3, a) ^ b ^ c ^ dpGMul(2, d)
	}
	return
}

func dpInvMixColumns(input [16]byte) (output [16]byte) {
	for column := 0; column < 4; column++ {
		i := column * 4
		a, b, c, d := input[i], input[i+1], input[i+2], input[i+3]
		output[i] = dpGMul(14, a) ^ dpGMul(11, b) ^ dpGMul(13, c) ^ dpGMul(9, d)
		output[i+1] = dpGMul(9, a) ^ dpGMul(14, b) ^ dpGMul(11, c) ^ dpGMul(13, d)
		output[i+2] = dpGMul(13, a) ^ dpGMul(9, b) ^ dpGMul(14, c) ^ dpGMul(11, d)
		output[i+3] = dpGMul(11, a) ^ dpGMul(13, b) ^ dpGMul(9, c) ^ dpGMul(14, d)
	}
	return
}

func dpExpandKey(key [16]byte) []byte {
	extended := append([]byte(nil), key[:]...)
	for word := 4; word < 44; word++ {
		t := append([]byte(nil), extended[(word-1)*4:word*4]...)
		if word%4 == 0 {
			t = []byte{dpSbox[t[1]], dpSbox[t[2]], dpSbox[t[3]], dpSbox[t[0]]}
			t[0] ^= dpRcon[word/4]
		}
		base := (word - 4) * 4
		for index := range 4 {
			extended = append(extended, t[index]^extended[base+index])
		}
	}
	return extended
}

func dpRoundKey(expanded []byte, round int) (result [16]byte) {
	copy(result[:], expanded[round*16:(round+1)*16])
	return
}

func dpRevertAES128RoundKey(roundKey [16]byte, round int) [16]byte {
	current := roundKey
	for round > 0 {
		var previous [16]byte
		for word := 3; word >= 1; word-- {
			for index := range 4 {
				previous[word*4+index] = current[word*4+index] ^ current[(word-1)*4+index]
			}
		}
		t := [4]byte{dpSbox[previous[13]], dpSbox[previous[14]], dpSbox[previous[15]], dpSbox[previous[12]]}
		t[0] ^= dpRcon[round]
		for index := range 4 {
			previous[index] = current[index] ^ t[index]
		}
		current = previous
		round--
	}
	return current
}

func dpAESEncrypt(block [16]byte, expanded []byte) [16]byte {
	state := dpXOR(block, dpRoundKey(expanded, 0))
	for round := 1; round < 10; round++ {
		state = dpXOR(dpMixColumns(dpShiftRows(dpSubBytes(state))), dpRoundKey(expanded, round))
	}
	return dpXOR(dpShiftRows(dpSubBytes(state)), dpRoundKey(expanded, 10))
}

func dpAESDecrypt(block [16]byte, expanded []byte) [16]byte {
	state := dpXOR(block, dpRoundKey(expanded, 10))
	for round := 9; round > 0; round-- {
		state = dpInvMixColumns(dpXOR(dpInvSubBytes(dpInvShiftRows(state)), dpRoundKey(expanded, round)))
	}
	return dpXOR(dpInvSubBytes(dpInvShiftRows(state)), dpRoundKey(expanded, 0))
}

type dpEncoding [16][256]byte

func dpIdentityEncoding() (result dpEncoding) {
	for position := range 16 {
		for value := range 256 {
			result[position][value] = byte(value)
		}
	}
	return
}

func dpAffineEncoding(alpha, beta [16]byte) (result dpEncoding) {
	for position := range 16 {
		for value := range 256 {
			result[position][value] = dpGMul(alpha[position], byte(value)) ^ beta[position]
		}
	}
	return
}

func (encoding dpEncoding) encode(input [16]byte) (output [16]byte) {
	for position, value := range input {
		output[position] = encoding[position][value]
	}
	return
}

func (encoding dpEncoding) inverse() (result dpEncoding) {
	for position, table := range encoding {
		for source, target := range table {
			result[position][target] = byte(source)
		}
	}
	return
}

// combine returns encoding ∘ other.
func (encoding dpEncoding) combine(other dpEncoding) (result dpEncoding) {
	for position := range 16 {
		for value := range 256 {
			result[position][value] = encoding[position][other[position][value]]
		}
	}
	return
}

func dpPostShift(input [16]byte) [16]byte { return dpShiftRows(input) }

func dpAttackView(raw [16]byte, output []dpEncoding, reverseMC bool) [16]byte {
	data := dpPostShift(raw)
	for index, encoding := range output {
		data = encoding.encode(data)
		if reverseMC || index < len(output)-1 {
			data = dpShiftRows(dpMixColumns(data))
		}
	}
	return data
}

type dpTarget struct {
	server *oracleServer
}

func (target *dpTarget) evalJobs(items []job) ([][16]byte, error) {
	return target.server.evaluateBatch(items)
}

func (target *dpTarget) apply(block [16]byte) ([16]byte, error) {
	values, err := target.evalJobs([]job{{block: block, meta: 0xFFFF}})
	if err != nil {
		return [16]byte{}, err
	}
	return values[0], nil
}

func (target *dpTarget) applyFault(block [16]byte, round, position int, xor byte) ([16]byte, error) {
	meta := uint32(round) | uint32(position)<<16 | uint32(xor)<<24
	values, err := target.evalJobs([]job{{block: block, meta: meta}})
	if err != nil {
		return [16]byte{}, err
	}
	return values[0], nil
}

func (target *dpTarget) randomInput(index int) [16]byte {
	return deterministicInput(uint32(index))
}

type dpRecovery struct {
	Key            [16]byte   `json:"-"`
	InputEncoding  dpEncoding `json:"-"`
	OutputEncoding dpEncoding `json:"-"`
	Milliseconds   float64    `json:"milliseconds"`
}

type dpModelJSON struct {
	Schema         string       `json:"schema"`
	KeyHex         string       `json:"key_hex"`
	InputEncoding  [16][256]int `json:"input_encoding"`
	OutputEncoding [16][256]int `json:"output_encoding"`
}

func (recovery dpRecovery) modelJSON() dpModelJSON {
	result := dpModelJSON{Schema: "darkphoenix.external-encoding-model.v1", KeyHex: hex.EncodeToString(recovery.Key[:])}
	for position := range 16 {
		for value := range 256 {
			result.InputEncoding[position][value] = int(recovery.InputEncoding[position][value])
			result.OutputEncoding[position][value] = int(recovery.OutputEncoding[position][value])
		}
	}
	return result
}

func dpDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func dpCheckPermutation(encoding dpEncoding) error {
	for position, table := range encoding {
		var seen [256]bool
		for _, value := range table {
			if seen[value] {
				return fmt.Errorf("encoding %d is not bijective", position)
			}
			seen[value] = true
		}
	}
	return nil
}
