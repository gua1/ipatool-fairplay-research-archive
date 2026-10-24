// Go adaptation of the Apache-2.0 DarkPhoenix partial AES-128 attack.
package main

import "fmt"

type dpMeetSolution struct {
	ok     bool
	lambda [4]byte
	beta   [4]byte
}

type dpMeetRowSolution struct {
	rootLambda byte
	rootBeta   byte
	rowLambda  byte
	rowBeta    byte
}

func dpMeetCoefficients(position int) [4]byte {
	switch position {
	case 0:
		return [4]byte{0, dpGMul(14, dpGFInv(9)), dpGMul(14, dpGFInv(13)), dpGMul(14, dpGFInv(11))}
	case 1:
		return [4]byte{0, dpGMul(11, dpGFInv(14)), dpGMul(11, dpGFInv(9)), dpGMul(11, dpGFInv(13))}
	case 2:
		return [4]byte{0, dpGMul(13, dpGFInv(11)), dpGMul(13, dpGFInv(14)), dpGMul(13, dpGFInv(9))}
	default:
		return [4]byte{0, dpGMul(9, dpGFInv(13)), dpGMul(9, dpGFInv(11)), dpGMul(9, dpGFInv(14))}
	}
}

func dpLambdaCandidates(column int, limited *[4]byte) [4][]byte {
	var result [4][]byte
	if limited != nil {
		for row := range 4 {
			result[row] = []byte{limited[(column+row)%4]}
		}
		return result
	}
	all := make([]byte, 255)
	for index := range all {
		all[index] = byte(index + 1)
	}
	for row := range 4 {
		result[row] = all
	}
	return result
}

func dpMeetAt(column int, fault [][4]byte, middle, faultPosition int, limited *[4]byte) dpMeetSolution {
	if middle < 0 || middle >= len(fault) {
		return dpMeetSolution{}
	}
	coefficient := dpMeetCoefficients(faultPosition)
	lambdas := dpLambdaCandidates(column, limited)
	fault0 := fault[:middle+1]
	fault1 := make([][4]byte, 1, len(fault)-middle)
	fault1[0] = fault[0]
	fault1 = append(fault1, fault[middle+1:]...)
	table := make(map[uint32][][2]byte, len(lambdas[0])*256)
	for _, lambda := range lambdas[0] {
		for beta := range 256 {
			root := dpSbox[dpGMul(lambda, fault0[0][0])^byte(beta)]
			var hash uint32
			for index, value := range fault0[1:] {
				difference := root ^ dpSbox[dpGMul(lambda, value[0])^byte(beta)]
				hash |= uint32(difference) << (8 * index)
			}
			table[hash] = append(table[hash], [2]byte{lambda, byte(beta)})
		}
	}
	solveRow := func(row int) []dpMeetRowSolution {
		result := []dpMeetRowSolution{}
		coef := coefficient[row]
		for _, lambda := range lambdas[row] {
			for beta := range 256 {
				root := dpSbox[dpGMul(lambda, fault0[0][row])^byte(beta)]
				var hash uint32
				for index, value := range fault0[1:] {
					difference := root ^ dpSbox[dpGMul(lambda, value[row])^byte(beta)]
					hash |= uint32(dpGMul(coef, difference)) << (8 * index)
				}
				hits := table[hash]
				if len(hits) == 0 {
					continue
				}
				second := make([]byte, len(fault1)-1)
				for index, value := range fault1[1:] {
					difference := root ^ dpSbox[dpGMul(lambda, value[row])^byte(beta)]
					second[index] = dpGMul(coef, difference)
				}
				for _, hit := range hits {
					rootValue := dpSbox[dpGMul(hit[0], fault1[0][0])^hit[1]]
					same := true
					for index, value := range fault1[1:] {
						if rootValue^dpSbox[dpGMul(hit[0], value[0])^hit[1]] != second[index] {
							same = false
							break
						}
					}
					if same {
						result = append(result, dpMeetRowSolution{hit[0], hit[1], lambda, byte(beta)})
					}
				}
			}
		}
		return result
	}
	rows := [3][]dpMeetRowSolution{solveRow(1), solveRow(2), solveRow(3)}
	if len(rows[0]) != 1 || len(rows[1]) != 1 || len(rows[2]) != 1 {
		return dpMeetSolution{}
	}
	if rows[0][0].rootLambda != rows[1][0].rootLambda || rows[0][0].rootLambda != rows[2][0].rootLambda ||
		rows[0][0].rootBeta != rows[1][0].rootBeta || rows[0][0].rootBeta != rows[2][0].rootBeta {
		return dpMeetSolution{}
	}
	return dpMeetSolution{
		ok:     true,
		lambda: [4]byte{rows[0][0].rootLambda, rows[0][0].rowLambda, rows[1][0].rowLambda, rows[2][0].rowLambda},
		beta:   [4]byte{rows[0][0].rootBeta, rows[0][0].rowBeta, rows[1][0].rowBeta, rows[2][0].rowBeta},
	}
}

func dpMeet(column int, fault [][4]byte, middle int, limited *[4]byte) dpMeetSolution {
	for position := range 4 {
		if result := dpMeetAt(column, fault, middle, position, limited); result.ok {
			return result
		}
	}
	return dpMeetSolution{}
}

func dpColumnSlice(target *dpTarget, plaintext, reference [16]byte, column int, permutations []dpEncoding, protocolRound int) ([][4]byte, error) {
	const alpha = 16
	jobs := make([]job, 0, 16*alpha)
	for position := range 16 {
		faultPosition := (column*4 + position) % 16
		faultByte := int(dpInvShift[faultPosition])
		for value := 1; value <= alpha; value++ {
			meta := uint32(protocolRound) | uint32(faultByte)<<16 | uint32(value)<<24
			jobs = append(jobs, job{block: plaintext, meta: meta})
		}
	}
	outputs, err := target.evalJobs(jobs)
	if err != nil {
		return nil, err
	}
	for position := range 16 {
		columns := make([][4]byte, 1, alpha+1)
		copy(columns[0][:], reference[column*4:column*4+4])
		valid := true
		for value := 1; value <= alpha; value++ {
			view := dpAttackView(outputs[position*alpha+value-1], permutations, true)
			differences := make([]int, 0, 4)
			for index := range 16 {
				if view[index] != reference[index] {
					differences = append(differences, index)
				}
			}
			if len(differences) != 4 {
				if value == 1 {
					valid = false
					break
				}
				return nil, fmt.Errorf("fault diffusion changed")
			}
			faultColumn := differences[0] / 4
			if faultColumn != column || differences[0] != faultColumn*4 || differences[1] != faultColumn*4+1 || differences[2] != faultColumn*4+2 || differences[3] != faultColumn*4+3 {
				if value == 1 {
					valid = false
					break
				}
				return nil, fmt.Errorf("fault column changed")
			}
			var word [4]byte
			copy(word[:], view[column*4:column*4+4])
			columns = append(columns, word)
		}
		if valid {
			return columns, nil
		}
	}
	return nil, fmt.Errorf("no fault position affects column %d", column)
}

func dpFirstPermutation(gtilde, gbar dpEncoding, coefficient [16]byte) dpEncoding {
	return dpAffineEncoding(coefficient, [16]byte{}).combine(gbar).combine(gtilde)
}

func dpStep4(target *dpTarget, gtilde, gbar dpEncoding, coefficient [16]byte, reference [16]byte) ([16]byte, [16]byte, error) {
	permutation := dpFirstPermutation(gtilde, gbar, coefficient)
	raw, err := target.apply(reference)
	if err != nil {
		return [16]byte{}, [16]byte{}, err
	}
	referenceView := dpAttackView(raw, []dpEncoding{permutation}, true)
	var lambdas, betas [4][4]byte
	for column := range 4 {
		var solution dpMeetSolution
		for attempt := range 10 {
			plaintext := reference
			view := referenceView
			if attempt != 0 {
				plaintext = target.randomInput(attempt)
				raw, err = target.apply(plaintext)
				if err != nil {
					return [16]byte{}, [16]byte{}, err
				}
				view = dpAttackView(raw, []dpEncoding{permutation}, true)
			}
			fault, sliceErr := dpColumnSlice(target, plaintext, view, column, []dpEncoding{permutation}, 8)
			if sliceErr != nil {
				return [16]byte{}, [16]byte{}, sliceErr
			}
			var limited *[4]byte
			if column != 0 {
				limited = &lambdas[0]
			}
			solution = dpMeet(column, fault, 4, limited)
			if solution.ok {
				break
			}
		}
		if !solution.ok {
			return [16]byte{}, [16]byte{}, fmt.Errorf("step4 failed for column %d", column)
		}
		lambdas[column], betas[column] = solution.lambda, solution.beta
	}
	var lambda, beta [16]byte
	for column := range 4 {
		copy(lambda[column*4:column*4+4], lambdas[column][:])
		copy(beta[column*4:column*4+4], betas[column][:])
	}
	shifted := dpInvShiftRows(lambda)
	for position := range 16 {
		if shifted[position] != shifted[position-position%4] {
			return [16]byte{}, [16]byte{}, fmt.Errorf("step4 lambda disagreement")
		}
	}
	return lambda, beta, nil
}

func dpRoundPermutation(lambda, beta [16]byte) (result dpEncoding) {
	for position := range 16 {
		for value := range 256 {
			result[position][value] = dpSbox[dpGMul(lambda[position], byte(value))^beta[position]]
		}
	}
	return
}

func dpStep5(target *dpTarget, gtilde, gbar dpEncoding, coefficient, lambda, beta, reference [16]byte) ([16]byte, error) {
	permutations := []dpEncoding{dpFirstPermutation(gtilde, gbar, coefficient), dpRoundPermutation(lambda, beta)}
	fixed := [4]byte{1, 1, 1, 1}
	var betaRound [16]byte
	for column := range 4 {
		var solution dpMeetSolution
		for attempt := range 10 {
			plaintext := reference
			if attempt != 0 {
				plaintext = target.randomInput(attempt)
			}
			raw, err := target.apply(plaintext)
			if err != nil {
				return [16]byte{}, err
			}
			view := dpAttackView(raw, permutations, true)
			fault, err := dpColumnSlice(target, plaintext, view, column, permutations, 7)
			if err != nil {
				return [16]byte{}, err
			}
			solution = dpMeet(column, fault, 4, &fixed)
			if solution.ok {
				break
			}
		}
		if !solution.ok {
			return [16]byte{}, fmt.Errorf("step5 failed for column %d", column)
		}
		copy(betaRound[column*4:column*4+4], solution.beta[:])
	}
	return dpInvShiftRows(betaRound), nil
}

func dpApplyLastRoundDecrypt(data, roundKey0, roundKey1 [16]byte) [16]byte {
	state := dpXOR(dpInvSubBytes(dpInvShiftRows(data)), roundKey1)
	state = dpInvMixColumns(state)
	return dpXOR(dpInvSubBytes(dpInvShiftRows(state)), roundKey0)
}

func dpExternalEncodings(target *dpTarget, gtilde, gbar dpEncoding, coefficient, lambda, beta, key [16]byte) (dpEncoding, dpEncoding, error) {
	first := dpFirstPermutation(gtilde, gbar, coefficient)
	lambdaBeta := dpRoundPermutation(lambda, beta)
	expanded := dpExpandKey(key)
	roundKey0, roundKey1 := dpRoundKey(expanded, 0), dpRoundKey(expanded, 1)
	var output dpEncoding
	var outputSet [16][256]bool
	for value := range 256 {
		var block [16]byte
		for position := range 16 {
			block[position] = byte(value)
		}
		middle := lambdaBeta.encode(dpShiftRows(dpMixColumns(first.encode(dpShiftRows(block)))))
		decoded := dpApplyLastRoundDecrypt(middle, roundKey0, roundKey1)
		for position := range 16 {
			if outputSet[position][decoded[position]] {
				return dpEncoding{}, dpEncoding{}, fmt.Errorf("output encoding collision")
			}
			outputSet[position][decoded[position]] = true
			output[position][decoded[position]] = byte(value)
		}
	}
	outputDecoder := output.inverse()
	var input dpEncoding
	var inputSet [16][256]bool
	for value := range 256 {
		var plaintext [16]byte
		for position := range 16 {
			plaintext[position] = byte(value)
		}
		raw, err := target.apply(plaintext)
		if err != nil {
			return dpEncoding{}, dpEncoding{}, err
		}
		decoded := outputDecoder.encode(raw)
		inner := dpAESEncrypt(decoded, expanded)
		for position := range 16 {
			if inputSet[position][inner[position]] {
				return dpEncoding{}, dpEncoding{}, fmt.Errorf("input encoding collision")
			}
			inputSet[position][inner[position]] = true
			input[position][inner[position]] = byte(value)
		}
	}
	if err := dpCheckPermutation(input); err != nil {
		return dpEncoding{}, dpEncoding{}, err
	}
	if err := dpCheckPermutation(output); err != nil {
		return dpEncoding{}, dpEncoding{}, err
	}
	for index := range 4 {
		plaintext := target.randomInput(100 + index)
		raw, err := target.apply(plaintext)
		if err != nil {
			return dpEncoding{}, dpEncoding{}, err
		}
		decoded := outputDecoder.encode(raw)
		inner := dpAESEncrypt(decoded, expanded)
		if input.encode(inner) != plaintext {
			return dpEncoding{}, dpEncoding{}, fmt.Errorf("external encoding verification failed")
		}
	}
	return input, output, nil
}
