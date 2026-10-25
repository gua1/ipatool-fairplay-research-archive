//go:build !fairplaysidb && !fairplayframe && !fairplaystate

package main

func embeddedModelBytes() []byte { return nil }
