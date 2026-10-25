//go:build !fairplaysidb || fairplayframe || fairplaystate

package main

func enrollmentFrameAddress() (uint64, bool) { return 0, false }

func embeddedModelNeedsEnrollmentFrame() bool { return false }
