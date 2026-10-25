//go:build fairplaystate

package main

import "fmt"

func generatedInputBytes() int { return 224 }

func prepareEvaluatorInput(input []byte) ([]byte, error) {
	if len(input) != 192 && len(input) != 224 {
		return nil, fmt.Errorf("state-slot input is %d bytes, want 192 or 224", len(input))
	}
	result := make([]byte, generatedInputBytes())
	for index, value := range input {
		result[index] = value ^ generatedStateInputMask[index%len(generatedStateInputMask)]
	}
	return result, nil
}
