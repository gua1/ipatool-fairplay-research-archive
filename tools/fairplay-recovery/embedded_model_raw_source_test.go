//go:build fairplayrawsource && !fairplaysidb && !fairplayframe && !fairplaystate && !fairplay26a428

package main

import "testing"

func TestEmbeddedRawSourceModelHasNoExecutablePath(t *testing.T) {
	if len(rawSourceModel) == 0 || len(rawSourceModel) > 1024*1024 {
		t.Fatalf("embedded raw-source model size = %d", len(rawSourceModel))
	}
	value, err := loadModelBytes(rawSourceModel)
	if err != nil {
		t.Fatal(err)
	}
	page := value.pages[0x700000200000]
	if len(page) != int(pageSize) {
		t.Fatal("embedded raw-source model lacks executable-path page")
	}
	for index, octet := range page {
		if octet != 0 {
			t.Fatalf("embedded raw-source model retains executable-path byte %d", index)
		}
	}
}
