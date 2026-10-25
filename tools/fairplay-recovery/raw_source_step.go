//go:build fairplayrawsource && !fairplaysidb && !fairplayframe && !fairplaystate && !fairplay26a428

package main

import "fmt"

var rawSourceBinaryHash = [32]byte{0x1e, 0x58, 0xd3, 0x7e, 0x96, 0x02, 0xdd, 0x0c, 0xa5, 0xe2, 0x4b, 0x14, 0x76, 0x20, 0x63, 0xb6, 0xc3, 0x10, 0x24, 0x8b, 0x4d, 0x3a, 0x94, 0x27, 0x27, 0x71, 0xd8, 0x15, 0xe4, 0xea, 0x17, 0x84}

func runRawSource(value *model, kernel string, loop bool) (string, int, error) {
	if value.binaryHash != rawSourceBinaryHash {
		return "", 0, fmt.Errorf("raw source model does not match generated fairplayd build")
	}
	worker := newState(value)
	worker.reset()
	iterations := 0
	for {
		var exit bool
		var err error
		switch kernel {
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
		default:
			return "", iterations, fmt.Errorf("unknown raw source kernel %q", kernel)
		}
		if err != nil {
			return "", iterations, err
		}
		if kernel == "digest" {
			exit = worker.z
			if !exit {
				err = runRawSourceDigestPrologue(worker, fault{})
				if err != nil {
					return "", iterations, err
				}
			}
		}
		iterations++
		if !loop || exit {
			break
		}
		if iterations >= 256 {
			return "", iterations, fmt.Errorf("raw source writer loop did not reach its bounded exit")
		}
	}
	return worker.digest(), iterations, nil
}
