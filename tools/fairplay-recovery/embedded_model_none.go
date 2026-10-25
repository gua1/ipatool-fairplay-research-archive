//go:build !fairplaysidb && !fairplayframe && !fairplaystate && !fairplayrawsource

package main

func embeddedModelBytes() []byte { return nil }
