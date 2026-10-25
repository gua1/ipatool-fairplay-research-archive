//go:build fairplaysidb && !fairplayframe && !fairplaystate

package main

func enrollmentFrameAddress() (uint64, bool) { return 0x7000000FB724, true }

func embeddedModelNeedsEnrollmentFrame() bool { return true }
