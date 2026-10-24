// Go adaptation of DarkPhoenix's Apache-2.0 GF(2) linear solver.
package main

import "fmt"

type dpMat8 [8]byte

func dpIdentityMat() (result dpMat8) {
	for index := range 8 {
		result[index] = 1 << index
	}
	return
}

func (left dpMat8) mul(right dpMat8) (result dpMat8) {
	for row := range 8 {
		bits := left[row]
		for column := 0; bits != 0; column++ {
			if bits&1 != 0 {
				result[row] ^= right[column]
			}
			bits >>= 1
		}
	}
	return
}

func (matrix dpMat8) transpose() (result dpMat8) {
	for row := range 8 {
		for column := range 8 {
			if matrix[row]>>column&1 != 0 {
				result[column] |= 1 << row
			}
		}
	}
	return
}

func (matrix dpMat8) inverse() (dpMat8, bool) {
	left, right := matrix, dpIdentityMat()
	for column := range 8 {
		pivot := -1
		for row := column; row < 8; row++ {
			if left[row]>>column&1 != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			return dpMat8{}, false
		}
		left[column], left[pivot] = left[pivot], left[column]
		right[column], right[pivot] = right[pivot], right[column]
		for row := range 8 {
			if row != column && left[row]>>column&1 != 0 {
				left[row] ^= left[column]
				right[row] ^= right[column]
			}
		}
	}
	return right, true
}

func dpMulMat(value byte) (result dpMat8) {
	for index := range 8 {
		result[index] = dpGMul(value, 1<<index)
	}
	return
}

func dpApplyMat(value byte, matrix dpMat8) (result byte) {
	for index := 0; value != 0; index++ {
		if value&1 != 0 {
			result ^= matrix[index]
		}
		value >>= 1
	}
	return
}

func dpTableFromMat(matrix dpMat8) (result [256]byte) {
	for value := range 256 {
		result[value] = dpApplyMat(byte(value), matrix)
	}
	return
}

func dpMatFromMap(table [256]byte) (result dpMat8) {
	for index := range 8 {
		result[index] = table[1<<index]
	}
	return
}

func dpNullspace(input []uint64) []uint64 {
	rows := make([]uint64, 64)
	copy(rows, input)
	pivot := [64]int{}
	for index := range pivot {
		pivot[index] = -1
	}
	row := 0
	for column := range 64 {
		selected := -1
		for index := row; index < 64; index++ {
			if rows[index]>>column&1 != 0 {
				selected = index
				break
			}
		}
		if selected < 0 {
			continue
		}
		rows[row], rows[selected] = rows[selected], rows[row]
		pivot[column] = row
		for index := range 64 {
			if index != row && rows[index]>>column&1 != 0 {
				rows[index] ^= rows[row]
			}
		}
		row++
		if row == 64 {
			break
		}
	}
	result := []uint64{}
	for free := range 64 {
		if pivot[free] >= 0 {
			continue
		}
		value := uint64(1) << free
		for column := range 64 {
			selected := pivot[column]
			if selected >= 0 && rows[selected]>>free&1 != 0 {
				value |= uint64(1) << column
			}
		}
		result = append(result, value)
	}
	return result
}

func dpIntertwinerSystem(left, right dpMat8) []uint64 {
	equations := make([]uint64, 64)
	for row := range 8 {
		for column := range 8 {
			var coefficient uint64
			for k := range 8 {
				if left[k]>>column&1 != 0 {
					coefficient ^= uint64(1) << (row*8 + k)
				}
				if right[row]>>k&1 != 0 {
					coefficient ^= uint64(1) << (k*8 + column)
				}
			}
			equations[row*8+column] = coefficient
		}
	}
	return equations
}

func dpMatFromBits(bits uint64) (result dpMat8) {
	for row := range 8 {
		for column := range 8 {
			if bits>>(row*8+column)&1 != 0 {
				result[row] |= 1 << column
			}
		}
	}
	return
}

func dpIntertwinerBasis(left, right dpMat8) []uint64 {
	return dpNullspace(dpIntertwinerSystem(left, right))
}

func dpInvertibleFromBasis(basis []uint64, limit int) []dpMat8 {
	if len(basis) == 0 || len(basis) > 16 {
		return nil
	}
	count := 1 << min(len(basis), 12)
	result := []dpMat8{}
	for mask := 1; mask < count; mask++ {
		var bits uint64
		for index := range basis {
			if mask>>index&1 != 0 {
				bits ^= basis[index]
			}
		}
		matrix := dpMatFromBits(bits)
		if _, ok := matrix.inverse(); ok {
			result = append(result, matrix)
			if len(result) == limit {
				break
			}
		}
	}
	return result
}

type dpMatrixCandidate struct {
	name   string
	matrix dpMat8
}

func dpDecryptCandidates() []dpMatrixCandidate {
	m9, m11, m13, m14 := dpMulMat(9), dpMulMat(11), dpMulMat(13), dpMulMat(14)
	i9, _ := m9.inverse()
	i11, _ := m11.inverse()
	i13, _ := m13.inverse()
	i14, _ := m14.inverse()
	return []dpMatrixCandidate{
		{"9*11*13^(-2)", m9.mul(m11).mul(i13).mul(i13)},
		{"9*11*14^(-2)", m9.mul(m11).mul(i14).mul(i14)},
		{"9*11^(-1)*13*14^(-1)", m9.mul(i11).mul(m13).mul(i14)},
		{"9*11^(-1)*13^(-1)*14", m9.mul(i11).mul(i13).mul(m14)},
		{"9^(-1)*11*13*14^(-1)", i9.mul(m11).mul(m13).mul(i14)},
		{"9^(-1)*11*13^(-1)*14", i9.mul(m11).mul(i13).mul(m14)},
		{"9^(-1)*11^(-1)*13^(2)", i9.mul(i11).mul(m13).mul(m13)},
		{"9^(-1)*11^(-1)*14^(2)", i9.mul(i11).mul(m14).mul(m14)},
		{"9^(-2)*13*14", i9.mul(i9).mul(m13).mul(m14)},
		{"9^(2)*13^(-1)*14^(-1)", m9.mul(m9).mul(i13).mul(i14)},
		{"11^(-2)*13*14", i11.mul(i11).mul(m13).mul(m14)},
		{"11^(2)*13^(-1)*14^(-1)", m11.mul(m11).mul(i13).mul(i14)},
	}
}

type dpPair struct{ left, right int }

func dpAssociation(name string, p0, p1 int) (dpPair, bool) {
	tables := map[string][][4]int{
		"9*11*14^(-2)":           {{0, 1, 0, 1}, {1, 0, 1, 0}, {2, 3, 2, 3}, {3, 2, 3, 2}},
		"9^(-1)*11^(-1)*14^(2)":  {{1, 0, 0, 1}, {0, 1, 1, 0}, {3, 2, 2, 3}, {2, 3, 3, 2}},
		"9*11*13^(-2)":           {{2, 3, 0, 1}, {3, 2, 1, 0}, {0, 1, 2, 3}, {1, 0, 3, 2}},
		"9^(-1)*11^(-1)*13^(2)":  {{3, 2, 0, 1}, {2, 3, 1, 0}, {1, 0, 2, 3}, {0, 1, 3, 2}},
		"9*11^(-1)*13*14^(-1)":   {{0, 1, 0, 2}, {3, 2, 0, 2}, {1, 0, 2, 0}, {2, 3, 2, 0}},
		"9^(-1)*11*13^(-1)*14":   {{1, 0, 0, 2}, {2, 3, 0, 2}, {0, 1, 2, 0}, {3, 2, 2, 0}},
		"9^(2)*13^(-1)*14^(-1)":  {{0, 1, 0, 3}, {3, 2, 1, 2}, {2, 3, 2, 1}, {1, 0, 3, 0}},
		"9^(-2)*13*14":           {{1, 0, 0, 3}, {2, 3, 1, 2}, {3, 2, 2, 1}, {0, 1, 3, 0}},
		"11^(2)*13^(-1)*14^(-1)": {{2, 3, 0, 3}, {1, 0, 1, 2}, {0, 1, 2, 1}, {3, 2, 3, 0}},
		"11^(-2)*13*14":          {{3, 2, 0, 3}, {0, 1, 1, 2}, {1, 0, 2, 1}, {2, 3, 3, 0}},
		"9*11^(-1)*13^(-1)*14":   {{0, 1, 1, 3}, {3, 2, 1, 3}, {1, 0, 3, 1}, {2, 3, 3, 1}},
		"9^(-1)*11*13*14^(-1)":   {{1, 0, 1, 3}, {2, 3, 1, 3}, {0, 1, 3, 1}, {3, 2, 3, 1}},
	}
	for _, row := range tables[name] {
		if row[0] == p0 && row[1] == p1 {
			return dpPair{row[2], row[3]}, true
		}
	}
	return dpPair{}, false
}

func dpInverseTable(table [256]byte) (result [256]byte) {
	for source, target := range table {
		result[target] = byte(source)
	}
	return
}

func dpCCoef(row int) byte {
	switch row {
	case 1:
		return dpGMul(9, dpGFInv(14))
	case 2:
		return dpGMul(13, dpGFInv(14))
	default:
		return dpGMul(11, dpGFInv(14))
	}
}

func dpCValue(g0, gb [256]byte, words [256][4]byte, row int, coefficient byte) (byte, bool) {
	var found byte
	have := false
	for fault := range 256 {
		ti := gb[words[0][row]^words[fault][row]]
		t0 := g0[words[0][0]^words[fault][0]]
		if ti == 0 {
			continue
		}
		value := dpGMul(dpGFInv(ti), dpGMul(t0, coefficient))
		if have && found != value {
			return 0, false
		}
		found, have = value, true
	}
	return found, have
}

func dpLinearSelfTest() error {
	matrix := dpMulMat(2)
	inverse, ok := matrix.inverse()
	if !ok || matrix.mul(inverse) != dpIdentityMat() {
		return fmt.Errorf("GF(2) matrix inverse failed")
	}
	if len(dpIntertwinerBasis(matrix, matrix)) != 8 {
		return fmt.Errorf("GF(2) commutant dimension mismatch")
	}
	return nil
}
