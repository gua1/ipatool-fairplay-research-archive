package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func flattenEncoding(value dpEncoding) []byte {
	result := make([]byte, 0, 16*256)
	for _, table := range value {
		result = append(result, table[:]...)
	}
	return result
}

func writePrivateJSON(path string, value any) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".fairplay-recovery-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Linking a same-directory temporary file publishes it atomically while
	// preserving fail-if-exists behavior. os.Rename would overwrite an existing
	// private recovery on Unix.
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return os.Remove(temporaryPath)
}

func main() {
	modelPath := flag.String("model", "", "private Go FairPlay oracle model")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "parallel oracle workers")
	recoveryOutput := flag.String("recover-output", "", "recover the AES model in-process and write private JSON")
	evaluateInput := flag.String("evaluate-input", "", "private fixed-size evaluator input")
	evaluateOutput := flag.String("evaluate-output", "", "new private evaluator output")
	flag.Parse()
	var value *model
	var err error
	if *modelPath != "" {
		value, err = loadModel(*modelPath)
	} else if embedded := embeddedModelBytes(); len(embedded) != 0 {
		value, err = loadModelBytes(embedded)
	} else {
		fmt.Fprintln(os.Stderr, "missing --model")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server, err := newOracleServer(value, *workers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *evaluateInput != "" || *evaluateOutput != "" {
		if *evaluateInput == "" || *evaluateOutput == "" || *recoveryOutput != "" {
			fmt.Fprintln(os.Stderr, "evaluation requires both --evaluate-input and --evaluate-output, without --recover-output")
			os.Exit(2)
		}
		input, err := readPrivateInput(*evaluateInput, generatedInputBytes())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		worker := newState(value)
		if err := worker.beginBytes(input); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := runGenerated(worker, fault{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		output, err := worker.outputBytes(value.block, len(input))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := writePrivateBytes(*evaluateOutput, output); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		digest := sha256.Sum256(output)
		fmt.Printf("fairplay_go_evaluation=1 bytes=%d output_sha256=%s output=%s\n", len(output), hex.EncodeToString(digest[:]), *evaluateOutput)
		return
	}
	if *recoveryOutput != "" {
		recovery, err := dpRecover(&dpTarget{server: server})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := writePrivateJSON(*recoveryOutput, recovery.modelJSON()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf(
			"fairplay_go_recovery=1 milliseconds=%.3f key_sha256=%s input_encoding_sha256=%s output_encoding_sha256=%s output=%s\n",
			recovery.Milliseconds,
			dpDigest(recovery.Key[:]),
			dpDigest(flattenEncoding(recovery.InputEncoding)),
			dpDigest(flattenEncoding(recovery.OutputEncoding)),
			*recoveryOutput,
		)
		return
	}
	if err := server.serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readPrivateInput(path string, size int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("evaluator input must be a mode-0600 regular file")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(value) != size {
		return nil, fmt.Errorf("evaluator input is %d bytes, want %d", len(value), size)
	}
	return value, nil
}

func writePrivateBytes(path string, value []byte) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".fairplay-evaluation-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return os.Remove(temporaryPath)
}
