//go:build fairplayrawsource && !fairplaysidb && !fairplayframe && !fairplaystate && !fairplay26a428

package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

var rawSourceBinaryHash = [32]byte{0x1e, 0x58, 0xd3, 0x7e, 0x96, 0x02, 0xdd, 0x0c, 0xa5, 0xe2, 0x4b, 0x14, 0x76, 0x20, 0x63, 0xb6, 0xc3, 0x10, 0x24, 0x8b, 0x4d, 0x3a, 0x94, 0x27, 0x27, 0x71, 0xd8, 0x15, 0xe4, 0xea, 0x17, 0x84}

var lastRawSourceState *state

func runRawSource(value *model, kernel string, loop bool, exactIterations int) (string, int, error) {
	if value.binaryHash != rawSourceBinaryHash {
		return "", 0, fmt.Errorf("raw source model does not match generated fairplayd build")
	}
	worker := newState(value)
	worker.reset()
	lastRawSourceState = worker
	if exactIterations < 0 || exactIterations > 4096 {
		return "", 0, fmt.Errorf("raw source iteration count is outside 1..4096")
	}
	if exactIterations != 0 {
		for iteration := 0; iteration < exactIterations; iteration++ {
			if _, err := runRawSourceKernelIteration(worker, kernel); err != nil {
				return "", iteration, err
			}
		}
		return worker.digest(), exactIterations, nil
	}
	if !loop {
		_, err := runRawSourceKernelIteration(worker, kernel)
		if err != nil {
			return "", 0, err
		}
		return worker.digest(), 1, nil
	}
	iterations, err := runRawSourceKernelLoop(worker, kernel)
	if err != nil {
		return "", iterations, err
	}
	return worker.digest(), iterations, nil
}

func currentRawSourceReport() (any, error) {
	if lastRawSourceState == nil {
		return nil, fmt.Errorf("raw source state is unavailable")
	}
	worker := lastRawSourceState
	registers := make(map[string]string, 32)
	for index, value := range worker.x {
		registers[fmt.Sprintf("x%d", index)] = fmt.Sprintf("%#x", value)
	}
	registers["sp"] = fmt.Sprintf("%#x", worker.sp)
	addresses := make([]uint64, 0, len(worker.model.pages))
	for address := range worker.model.pages {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(left, right int) bool { return addresses[left] < addresses[right] })
	pages := make(map[string]string, len(addresses))
	dirtyPages := make(map[string]string)
	for _, address := range addresses {
		page := worker.model.pages[address]
		if writable := worker.writable[address]; writable != nil {
			page = writable
		}
		pages[fmt.Sprintf("%#x", address)] = fmt.Sprintf("%x", sha256.Sum256(page))
		if worker.dirty[address] {
			dirtyPages[fmt.Sprintf("%#x", address)] = fmt.Sprintf("%x", page)
		}
	}
	return map[string]any{
		"schema":           "ipatool-fairplay-raw-source-state-v1",
		"registers":        registers,
		"flags":            map[string]bool{"n": worker.n, "z": worker.z, "c": worker.c, "v": worker.v},
		"page_sha256":      pages,
		"dirty_page_bytes": dirtyPages,
		"state_sha256":     worker.digest(),
	}, nil
}

func currentRawSourceBytes(size int) ([]byte, error) {
	if lastRawSourceState == nil {
		return nil, fmt.Errorf("raw source state is unavailable")
	}
	if size != 192 && size != 224 {
		return nil, fmt.Errorf("raw source output size must be 192 or 224 bytes")
	}
	return lastRawSourceState.outputBytes(0x7000000FB304, size)
}

func runRawSourceKernelIteration(worker *state, kernel string) (bool, error) {
	var exit bool
	var err error
	switch kernel {
	case "bootstrap":
		err = runRawSourceBootstrapKernel(worker, fault{})
		exit = worker.x[3] != 0x10057AE74
	case "writer":
		exit = uint32(worker.x[1])+0x9FCE627E > 0xC7
		err = runRawSourceWriterKernel(worker, fault{})
	case "tail":
		exit = uint32(worker.x[3])+0x9FCE627E >= 0x12C
		err = runRawSourceTailKernel(worker, fault{})
	case "even":
		exit = uint32(worker.x[12])+2 > 0x63
		err = runRawSourceEvenKernel(worker, fault{})
	case "odd":
		exit = uint32(worker.x[1])+0x9FCE627F > 0x64
		err = runRawSourceOddKernel(worker, fault{})
	case "digest":
		err = runRawSourceDigestKernel(worker, fault{})
	case "outer":
		err = runRawSourceOuterIteration(worker, fault{})
		if err == nil && worker.x[12] == 0x1007822CC {
			err = runRawSourceCycleBoundary(worker, fault{})
			exit = rawSourceCycleExited(worker)
		} else {
			exit = worker.x[12] != 0x1005B7438
		}
	case "cycle":
		err = runRawSourceCycleBoundary(worker, fault{})
		exit = rawSourceCycleExited(worker)
	case "outer-primary":
		err = runRawSourceOuterIteration(worker, fault{})
		exit = worker.x[12] != 0x1005B7438
	default:
		return false, fmt.Errorf("unknown raw source kernel %q", kernel)
	}
	if err != nil {
		return false, err
	}
	if kernel == "digest" {
		exit = worker.z
		if !exit {
			err = runRawSourceDigestPrologue(worker, fault{})
		}
	}
	return exit, err
}

func rawSourceCycleExited(worker *state) bool {
	if worker.x[9] == 0x1005B7438 {
		return false
	}
	return worker.x[8] != 0x1005B7438
}

func runRawSourceKernelLoop(worker *state, kernel string) (int, error) {
	if kernel == "digest-natural" {
		if err := runRawSourceDigestPrologue(worker, fault{}); err != nil {
			return 0, err
		}
		kernel = "digest"
	}
	limit := 1024
	if kernel == "bootstrap" {
		limit = 200000
	}
	for iterations := 1; iterations <= limit; iterations++ {
		exit, err := runRawSourceKernelIteration(worker, kernel)
		if err != nil {
			return iterations - 1, err
		}
		if exit {
			return iterations, nil
		}
	}
	return limit, fmt.Errorf("raw source writer loop did not reach its bounded exit")
}
