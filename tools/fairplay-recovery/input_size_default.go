//go:build !fairplaystate

package main

import "fmt"

func generatedInputBytes() int { return 16 }

func prepareEvaluatorInput(input []byte) ([]byte, error) {
	if len(input) != generatedInputBytes() {
		return nil, fmt.Errorf("evaluator input is %d bytes, want %d", len(input), generatedInputBytes())
	}
	return append([]byte(nil), input...), nil
}
