// Package cli implements the pqc-fixtures command-line entrypoint.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/GreatSarmad/pqc-fixtures/src/engine"
)

// Version is the tool version, injected at release build time via
// -ldflags "-X github.com/GreatSarmad/pqc-fixtures/src/cli.Version=vX.Y.Z"
// (see .github/workflows/release.yml).
var Version = "dev"

const usage = `pqc-fixtures - generate oversized post-quantum test artifacts

Usage:
  pqc-fixtures [command]

Commands:
  engine         report the bundled OpenSSL engine's path and version

Generation commands are not yet implemented (see ROADMAP.md, stage F1 onward).

Flags:
  -h, --help     show this help message
  -v, --version  print the version
`

// Execute runs the CLI for the given args, writing output to stdout, and
// returns the process exit code.
func Execute(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[0] {
	case "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "-v", "--version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "engine":
		return engineCommand(stdout, engine.Locate)
	default:
		fmt.Fprintf(stdout, "pqc-fixtures: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// engineCommand reports the located engine, so a user can confirm a release
// archive is intact and see exactly which OpenSSL their fixtures came from
// (design-dossier §9: engine version is auditable). locate is a parameter so
// tests can drive the failure path without an engine on disk.
func engineCommand(stdout io.Writer, locate func() (*engine.Engine, error)) int {
	e, err := locate()
	if err != nil {
		fmt.Fprintf(stdout, "pqc-fixtures: %v\n", err)
		return 1
	}

	version, err := e.Version(context.Background())
	if err != nil {
		fmt.Fprintf(stdout, "pqc-fixtures: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "path:    %s\n", e.Path)
	fmt.Fprintf(stdout, "version: %s\n", version)
	fmt.Fprintf(stdout, "pinned:  %s\n", engine.PinnedVersion)
	if e.FromOverride {
		fmt.Fprintf(stdout, "source:  %s (not the bundled engine)\n", engine.EnvOverride)
	} else {
		fmt.Fprintln(stdout, "source:  bundled")
	}
	if version != engine.PinnedVersion {
		fmt.Fprintf(stdout, "\nwarning: engine version %s differs from the pinned %s; "+
			"generated fixtures may not match the documented size envelopes\n", version, engine.PinnedVersion)
	}
	return 0
}
