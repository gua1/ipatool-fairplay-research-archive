//go:build fairplayframe && !fairplaystate

package main

import _ "embed"

// frameModel contains only build-global 26A428 state. The generator zeros the
// enrollment input, output, unused object bytes, and unused stack bytes before
// this artifact is checked in.
//
//go:embed profiles/macos26a428-frame-public.model.gz
var frameModel []byte

func embeddedModelBytes() []byte { return frameModel }
