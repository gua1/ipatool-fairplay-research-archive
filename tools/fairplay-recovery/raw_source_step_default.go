//go:build !fairplayrawsource || fairplaysidb || fairplayframe || fairplaystate || fairplay26a428

package main

import "fmt"

func runRawSource(_ *model, _ string, _ bool, _ int) (string, int, error) {
	return "", 0, fmt.Errorf("raw source step is not included in this build")
}

func currentRawSourceReport() (any, error) {
	return nil, fmt.Errorf("raw source state is not included in this build")
}

func currentRawSourceBytes(_ int) ([]byte, error) {
	return nil, fmt.Errorf("raw source state is not included in this build")
}

func currentRawSourceFrameBytes() ([]byte, error) {
	return nil, fmt.Errorf("raw source state is not included in this build")
}

func currentRawSourceSINFMaterialBytes() ([]byte, error) {
	return nil, fmt.Errorf("raw source state is not included in this build")
}

func currentRawSourceEnrollmentPack() ([]byte, error) {
	return nil, fmt.Errorf("raw source state is not included in this build")
}

func configureRawSourceRuntime(_ *model, _ string, fileSpecs []string, macPath, executablePath string, stopPC uint64) error {
	if len(fileSpecs) != 0 || macPath != "" || executablePath != "" || stopPC != 0 {
		return fmt.Errorf("raw source runtime is not included in this build")
	}
	return nil
}
