// Go adaptation of the Apache-2.0 DarkPhoenix partial AES-128 attack.
package main

import (
	"fmt"
	"time"
)

var dpRSPairs = [3][4]int{{0, 1, 2, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}}

func dpCounter(value uint64) (result [16]byte) {
	for index := 0; index < 8; index++ {
		result[15-index] = byte(value)
		value >>= 8
	}
	return
}

func dpClaim(flags []bool, inputs []byte, position, pair, value int, input [16]byte) {
	slot := (position*3+pair)*256 + value
	if flags[slot] {
		return
	}
	flags[slot] = true
	copy(inputs[slot*16:(slot+1)*16], input[:])
}

func dpConsiderStep1(value, input, reference [16]byte, flags []bool, inputs []byte) {
	for column := range 4 {
		for pairIndex, pair := range dpRSPairs {
			a1, a2 := column*4+pair[0], column*4+pair[1]
			b1, b2 := column*4+pair[2], column*4+pair[3]
			if value[a1] == reference[a1] {
				dpClaim(flags, inputs, b1, pairIndex, int(value[b1]), input)
			}
			if value[a2] == reference[a2] {
				dpClaim(flags, inputs, b2, pairIndex, int(value[b2]), input)
			}
			if value[b1] == reference[b1] {
				dpClaim(flags, inputs, a1, pairIndex, int(value[a1]), input)
			}
			if value[b2] == reference[b2] {
				dpClaim(flags, inputs, a2, pairIndex, int(value[a2]), input)
			}
		}
	}
}

func dpStep1Done(flags []bool) bool {
	for position := range 16 {
		complete := false
		for pair := range 3 {
			base, count := (position*3+pair)*256, 0
			for value := range 256 {
				if flags[base+value] {
					count++
				}
			}
			if count == 256 {
				complete = true
				break
			}
		}
		if !complete {
			return false
		}
	}
	return true
}

func dpSearchStep1(target *dpTarget, referenceInput, referenceOutput [16]byte) ([]bool, []byte, error) {
	flags := make([]bool, 16*3*256)
	inputs := make([]byte, len(flags)*16)
	for column := range 4 {
		for pair := range 3 {
			for row := range 4 {
				position := column*4 + row
				dpClaim(flags, inputs, position, pair, int(referenceOutput[position]), referenceInput)
			}
		}
	}
	const batchSize = 4096
	for base := uint64(0); base < 8<<20 && !dpStep1Done(flags); base += batchSize {
		jobs := make([]job, batchSize)
		blocks := make([][16]byte, batchSize)
		for index := range batchSize {
			blocks[index] = dpCounter(base + uint64(index))
			jobs[index] = job{block: blocks[index], meta: 0xFFFF}
		}
		outputs, err := target.evalJobs(jobs)
		if err != nil {
			return nil, nil, err
		}
		for index, raw := range outputs {
			dpConsiderStep1(dpPostShift(raw), blocks[index], referenceOutput, flags, inputs)
		}
	}
	if !dpStep1Done(flags) {
		return nil, nil, fmt.Errorf("step1 did not complete")
	}
	return flags, inputs, nil
}

func dpSelectStep1(flags []bool, inputs []byte) ([][]byte, [][]int, error) {
	matrices, companions := make([][]byte, 0, 16), make([][]int, 0, 16)
	for column := range 4 {
		for row := range 4 {
			found := false
			for pairIndex, pair := range dpRSPairs {
				position := column*4 + row
				base := (position*3 + pairIndex) * 256
				complete := true
				for value := range 256 {
					if !flags[base+value] {
						complete = false
						break
					}
				}
				if !complete || found {
					continue
				}
				found = true
				matrix := make([]byte, 256*16)
				copy(matrix, inputs[base*16:(base+256)*16])
				matrices = append(matrices, matrix)
				switch row {
				case pair[0]:
					companions = append(companions, []int{column*4 + pair[2]})
				case pair[1]:
					companions = append(companions, []int{column*4 + pair[3]})
				case pair[2]:
					companions = append(companions, []int{column*4 + pair[0]})
				case pair[3]:
					companions = append(companions, []int{column*4 + pair[1]})
				}
			}
			if !found {
				return nil, nil, fmt.Errorf("step1 incomplete at column %d row %d", column, row)
			}
		}
	}
	return matrices, companions, nil
}

func dpVerifyStep1(target *dpTarget, reference [16]byte, matrices [][]byte, companions [][]int) error {
	referenceRaw, err := target.apply(reference)
	if err != nil {
		return err
	}
	referenceOutput := dpPostShift(referenceRaw)
	jobs := make([]job, 0, 16*256)
	for position := range 16 {
		for value := range 256 {
			var block [16]byte
			copy(block[:], matrices[position][value*16:(value+1)*16])
			jobs = append(jobs, job{block: block, meta: 0xFFFF})
		}
	}
	outputs, err := target.evalJobs(jobs)
	if err != nil {
		return err
	}
	for position := range 16 {
		for value := range 256 {
			view := dpPostShift(outputs[position*256+value])
			if view[position] != byte(value) {
				return fmt.Errorf("step1 verify byte %d value %d", position, value)
			}
			for _, companion := range companions[position] {
				if view[companion] != referenceOutput[companion] {
					return fmt.Errorf("step1 companion mismatch")
				}
			}
		}
	}
	return nil
}

func dpFaultByteStep2(position, candidate int) (round, faultByte int) {
	faultPosition := (position - position%4 + candidate) % 16
	return 9, int(dpInvShift[faultPosition])
}

func dpTolhuizen(rows [256][256]byte) ([256]byte, error) {
	var byPivot [256]*[256]byte
	for index := range 256 {
		pivot := rows[index][0]
		if byPivot[pivot] != nil {
			return [256]byte{}, fmt.Errorf("Tolhuizen duplicate pivot")
		}
		byPivot[pivot] = &rows[index]
	}
	permutation := [256]int{}
	for index := range permutation {
		permutation[index] = -1
	}
	permutation[0] = 0
	next := 1
	for bit := range 8 {
		for next < 256 && permutation[next] >= 0 {
			next++
		}
		if next == 256 || byPivot[next] == nil {
			return [256]byte{}, fmt.Errorf("Tolhuizen missing pivot")
		}
		permutation[next] = 1 << bit
		row := byPivot[next]
		for index := 1; index < 256; index++ {
			if permutation[index] < 0 {
				continue
			}
			target := int(row[index])
			expected := permutation[index] ^ permutation[next]
			if permutation[target] < 0 {
				permutation[target] = expected
			} else if permutation[target] != expected {
				return [256]byte{}, fmt.Errorf("Tolhuizen inconsistency")
			}
		}
	}
	var result [256]byte
	for index, value := range permutation {
		if value < 0 {
			return result, fmt.Errorf("Tolhuizen incomplete")
		}
		result[index] = byte(value)
	}
	return result, nil
}

func dpStep2(target *dpTarget, matrices [][]byte, companions [][]int) (dpEncoding, error) {
	probeJobs := make([]job, 0, 16*16*256)
	for position := range 16 {
		var plaintext [16]byte
		copy(plaintext[:], matrices[position][:16])
		for candidate := range 16 {
			round, faultByte := dpFaultByteStep2(position, candidate)
			for value := range 256 {
				meta := uint32(0xFFFF)
				if value != 0 {
					meta = uint32(round) | uint32(faultByte)<<16 | uint32(value)<<24
				}
				probeJobs = append(probeJobs, job{block: plaintext, meta: meta})
			}
		}
	}
	probe, err := target.evalJobs(probeJobs)
	if err != nil {
		return dpEncoding{}, err
	}
	positions := [16]int{}
	for position := range 16 {
		positions[position] = -1
		companion := companions[position][0]
		for candidate := range 16 {
			var seen [256]bool
			good := true
			for value := range 256 {
				view := dpPostShift(probe[(position*16+candidate)*256+value])
				if value == 0 && view[position] != 0 {
					good = false
					break
				}
				item := view[companion]
				if seen[item] {
					good = false
					break
				}
				seen[item] = true
			}
			if good {
				positions[position] = candidate
				break
			}
		}
		if positions[position] < 0 {
			return dpEncoding{}, fmt.Errorf("step2 no fault position for byte %d", position)
		}
	}
	jobs := make([]job, 0, 16*256*256)
	for position := range 16 {
		round, faultByte := dpFaultByteStep2(position, positions[position])
		for input := range 256 {
			var block [16]byte
			copy(block[:], matrices[position][input*16:(input+1)*16])
			for value := range 256 {
				meta := uint32(0xFFFF)
				if value != 0 {
					meta = uint32(round) | uint32(faultByte)<<16 | uint32(value)<<24
				}
				jobs = append(jobs, job{block: block, meta: meta})
			}
		}
	}
	outputs, err := target.evalJobs(jobs)
	if err != nil {
		return dpEncoding{}, err
	}
	var encoding dpEncoding
	for position := range 16 {
		companion := companions[position][0]
		var rows [256][256]byte
		for input := range 256 {
			var seen [256]bool
			for value := range 256 {
				view := dpPostShift(outputs[(position*256+input)*256+value])
				if value == 0 && view[position] != byte(input) {
					return encoding, fmt.Errorf("step2 unfaulted mismatch")
				}
				key := view[companion]
				if seen[key] {
					return encoding, fmt.Errorf("step2 duplicate companion")
				}
				seen[key] = true
				rows[key][input] = view[position]
			}
		}
		encoding[position], err = dpTolhuizen(rows)
		if err != nil {
			return encoding, err
		}
	}
	return encoding, nil
}

type dpColumnFaults struct {
	positions []int
	words     [][256][4]byte
}

func dpStep3(target *dpTarget, gtilde dpEncoding, reference [16]byte) (dpEncoding, [16]byte, error) {
	raw, err := target.apply(reference)
	if err != nil {
		return dpEncoding{}, [16]byte{}, err
	}
	referenceView := dpAttackView(raw, []dpEncoding{gtilde}, false)
	jobs := make([]job, 0, 16*255)
	for position := range 16 {
		for value := 1; value < 256; value++ {
			jobs = append(jobs, job{block: reference, meta: uint32(9) | uint32(position)<<16 | uint32(value)<<24})
		}
	}
	outputs, err := target.evalJobs(jobs)
	if err != nil {
		return dpEncoding{}, [16]byte{}, err
	}
	columns := [4]dpColumnFaults{}
	for position := range 16 {
		column := -1
		var words [256][4]byte
		for value := 1; value < 256; value++ {
			view := dpAttackView(outputs[position*255+value-1], []dpEncoding{gtilde}, false)
			differences := []int{}
			for index := range 16 {
				if view[index] != referenceView[index] {
					differences = append(differences, index)
				}
			}
			if len(differences) != 4 || differences[1] != differences[0]+1 || differences[2] != differences[0]+2 || differences[3] != differences[0]+3 {
				return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 invalid fault geometry")
			}
			current := differences[0] / 4
			if column < 0 {
				column = current
				copy(words[0][:], referenceView[current*4:current*4+4])
			} else if column != current {
				return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 fault changed column")
			}
			copy(words[value][:], view[current*4:current*4+4])
		}
		columns[column].positions = append(columns[column].positions, position)
		columns[column].words = append(columns[column].words, words)
	}
	return dpSolveGbar(columns)
}

func dpSolveGbar(columns [4]dpColumnFaults) (dpEncoding, [16]byte, error) {
	var maps [16][256]byte
	var pairs [16][2]int
	pairByRow := [4][2]int{{0, 1}, {2, 3}, {1, 3}, {2, 0}}
	for position := range 16 {
		column, row := position/4, position%4
		other := 2*(row/2) + (row+1)%2
		pairs[position] = [2]int{row, other}
		pair := pairByRow[row]
		first, second := columns[column].words[pair[0]], columns[column].words[pair[1]]
		if first[0] != second[0] {
			return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 bases differ")
		}
		base := first[0]
		var forward, reverse [256]int
		for index := range 256 {
			forward[index], reverse[index] = -1, -1
		}
		for fault := range 256 {
			a := int(base[row] ^ first[fault][row])
			b := int(base[other] ^ second[fault][other])
			if forward[a] >= 0 || reverse[b] >= 0 {
				return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 nonlinear differential")
			}
			forward[a] = int(base[other] ^ first[fault][other])
			reverse[b] = int(base[row] ^ second[fault][row])
		}
		for value := range 256 {
			if forward[value] < 0 || reverse[forward[value]] < 0 {
				return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 incomplete map")
			}
			maps[position][value] = byte(reverse[forward[value]])
		}
	}
	candidates := dpDecryptCandidates()
	names := [16]string{}
	for position := range 16 {
		left := dpMatFromMap(maps[position])
		hits := []string{}
		for _, candidate := range candidates {
			if len(dpInvertibleFromBasis(dpIntertwinerBasis(left, candidate.matrix), 1)) != 0 {
				hits = append(hits, candidate.name)
			}
		}
		if len(hits) != 1 {
			return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 matrix candidates=%d", len(hits))
		}
		names[position] = hits[0]
	}
	associations := [4][4]int{}
	for column := range associations {
		for index := range associations[column] {
			associations[column][index] = -1
		}
	}
	for position := range 16 {
		column := position / 4
		pair := pairByRow[position%4]
		rows, ok := dpAssociation(names[position], pairs[position][0], pairs[position][1])
		if !ok {
			return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 association missing")
		}
		for index, row := range []int{rows.left, rows.right} {
			slot := pair[index]
			if associations[column][slot] >= 0 && associations[column][slot] != row {
				return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 association conflict")
			}
			associations[column][slot] = row
		}
	}
	return dpBuildGbar(columns, maps, names, associations, candidates)
}

func dpBuildGbar(columns [4]dpColumnFaults, maps [16][256]byte, names [16]string, associations [4][4]int, candidates []dpMatrixCandidate) (dpEncoding, [16]byte, error) {
	byName := map[string]dpMat8{}
	for _, candidate := range candidates {
		byName[candidate.name] = candidate.matrix
	}
	var encoded, decoded dpEncoding
	for position := range 16 {
		basis := dpIntertwinerBasis(dpMatFromMap(maps[position]), byName[names[position]])
		gauges := dpInvertibleFromBasis(basis, 48)
		if len(gauges) == 0 {
			return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 no invertible encoding")
		}
		column, row := position/4, position%4
		chosen := -1
		if row == 0 {
			chosen = 0
		} else {
			slot0 := -1
			for slot, value := range associations[column] {
				if value == 0 {
					slot0 = slot
				}
			}
			for index, gauge := range gauges {
				table := dpTableFromMat(gauge)
				if _, ok := dpCValue(decoded[column*4], dpInverseTable(table), columns[column].words[slot0], row, dpCCoef(row)); ok {
					chosen = index
					break
				}
			}
		}
		if chosen < 0 {
			return dpEncoding{}, [16]byte{}, fmt.Errorf("step3 gauge failed")
		}
		encoded[position] = dpTableFromMat(gauges[chosen])
		decoded[position] = dpInverseTable(encoded[position])
	}
	var coefficient [16]byte
	for index := range coefficient {
		coefficient[index] = 1
	}
	for position := range 16 {
		if position%4 == 0 {
			continue
		}
		column, row, slot0 := position/4, position%4, -1
		for slot, value := range associations[column] {
			if value == 0 {
				slot0 = slot
			}
		}
		value, ok := dpCValue(decoded[column*4], decoded[position], columns[column].words[slot0], row, dpCCoef(row))
		if !ok {
			return dpEncoding{}, coefficient, fmt.Errorf("step3 C mismatch")
		}
		coefficient[position] = value
	}
	return decoded, coefficient, nil
}

func dpRecover(target *dpTarget) (dpRecovery, error) {
	started := time.Now()
	reference := target.randomInput(0)
	raw, err := target.apply(reference)
	if err != nil {
		return dpRecovery{}, err
	}
	flags, inputs, err := dpSearchStep1(target, reference, dpPostShift(raw))
	if err != nil {
		return dpRecovery{}, err
	}
	matrices, companions, err := dpSelectStep1(flags, inputs)
	if err != nil {
		return dpRecovery{}, err
	}
	if err := dpVerifyStep1(target, reference, matrices, companions); err != nil {
		return dpRecovery{}, err
	}
	gtilde, err := dpStep2(target, matrices, companions)
	if err != nil {
		return dpRecovery{}, err
	}
	gbar, coefficient, err := dpStep3(target, gtilde, reference)
	if err != nil {
		return dpRecovery{}, err
	}
	lambda, beta, err := dpStep4(target, gtilde, gbar, coefficient, reference)
	if err != nil {
		return dpRecovery{}, err
	}
	roundKey, err := dpStep5(target, gtilde, gbar, coefficient, lambda, beta, reference)
	if err != nil {
		return dpRecovery{}, err
	}
	key := dpRevertAES128RoundKey(roundKey, 2)
	input, output, err := dpExternalEncodings(target, gtilde, gbar, coefficient, lambda, beta, key)
	if err != nil {
		return dpRecovery{}, err
	}
	return dpRecovery{Key: key, InputEncoding: input, OutputEncoding: output, Milliseconds: float64(time.Since(started).Microseconds()) / 1000}, nil
}
