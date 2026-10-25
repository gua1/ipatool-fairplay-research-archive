//go:build fairplayrawsource && !fairplaysidb && !fairplayframe && !fairplaystate && !fairplay26a428

package main

import "testing"

func TestRawSourceRuntimeUsesMostSpecificFileSuffix(t *testing.T) {
	runtime := rawSourceRuntime{files: map[string][]byte{
		"App.supf":          {1},
		"/SC_Info/App.supf": {2},
	}}
	suffix, data, ok := runtime.matchingFile("/Applications/App.app/SC_Info/App.supf")
	if !ok || suffix != "/SC_Info/App.supf" || len(data) != 1 || data[0] != 2 {
		t.Fatalf("match = %q, %v, %v", suffix, data, ok)
	}
}
