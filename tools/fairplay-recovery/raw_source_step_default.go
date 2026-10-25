//go:build !fairplayrawsource || fairplaysidb || fairplayframe || fairplaystate || fairplay26a428

package main

import "fmt"

func runRawSource(_ *model, _ string, _ bool) (string, int, error) {
	return "", 0, fmt.Errorf("raw source step is not included in this build")
}
