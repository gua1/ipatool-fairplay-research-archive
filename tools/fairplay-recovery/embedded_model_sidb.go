//go:build fairplaysidb && !fairplayframe && !fairplaystate

package main

import _ "embed"

//go:embed profiles/macos26a428-sidb-public.model.gz
var embeddedSIDBModel []byte

func embeddedModelBytes() []byte { return embeddedSIDBModel }
