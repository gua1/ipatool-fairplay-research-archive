//go:build fairplaystate

package main

import _ "embed"

//go:embed profiles/macos26a428-state-public.model.gz
var stateModel []byte

func embeddedModelBytes() []byte { return stateModel }
