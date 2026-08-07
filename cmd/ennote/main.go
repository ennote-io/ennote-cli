package main

import (
	"os"

	"github.com/ennote-io/ennote-cli/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
