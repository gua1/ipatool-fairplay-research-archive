package main

import (
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
