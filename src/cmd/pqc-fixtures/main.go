// Command pqc-fixtures is the CLI binary entrypoint.
package main

import (
	"os"

	"github.com/GreatSarmad/pqc-fixtures/src/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
