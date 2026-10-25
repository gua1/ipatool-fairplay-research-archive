package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/majd/ipatool/v2/internal/fairplay"
)

func main() {
	binary := flag.String("binary", "", "arm64e or universal fairplayd Mach-O")
	flag.Parse()
	if *binary == "" {
		fmt.Fprintln(os.Stderr, "missing --binary")
		os.Exit(2)
	}
	profile, err := fairplay.InspectFairPlayBinaryProfile(*binary)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(profile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
