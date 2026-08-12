// Package cli implements the pqc-fixtures command-line entrypoint. It is a
// thin layer over src/gen (design-dossier §7): it parses flags, resolves them
// into a FixtureSpec, and reports results. No generation logic lives here.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/GreatSarmad/pqc-fixtures/src/engine"
	"github.com/GreatSarmad/pqc-fixtures/src/gen"
	"github.com/GreatSarmad/pqc-fixtures/src/manifest"
	"github.com/GreatSarmad/pqc-fixtures/src/profile"
)

// Version is the tool version, injected at release build time via
// -ldflags "-X github.com/GreatSarmad/pqc-fixtures/src/cli.Version=vX.Y.Z"
// (see .github/workflows/release.yml).
var Version = "dev"

const usage = `pqc-fixtures - generate oversized post-quantum test artifacts

Usage:
  pqc-fixtures <command> [flags]

Commands:
  gen            generate a post-quantum certificate chain and its manifest
  schema         print the JSON Schema for manifest.json
  engine         report the bundled OpenSSL engine's path and version

Flags:
  -h, --help     show this help message
  -v, --version  print the version

Run "pqc-fixtures gen --help" for generation flags.

Everything runs offline. Generated keys and certificates are deliberately
insecure test fixtures: never use them for anything real.
`

// Execute runs the CLI for the given args and returns the process exit code.
// Normal output goes to stdout, diagnostics to stderr.
func Execute(args []string, stdout, stderr io.Writer) int {
	gen.ToolVersion = Version

	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "-v", "--version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "gen":
		return genCommand(args[1:], stdout, stderr, engine.Locate)
	case "schema":
		stdout.Write(manifest.Schema())
		return 0
	case "engine":
		return engineCommand(stdout, stderr, engine.Locate)
	default:
		fmt.Fprintf(stderr, "pqc-fixtures: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

const genUsage = `pqc-fixtures gen - generate a post-quantum certificate chain

Usage:
  pqc-fixtures gen --out ./testdata [flags]

Writes a root CA, any intermediates, a leaf certificate usable as a local TLS
server certificate, a concatenated fullchain.pem, and a manifest.json
recording every artifact's size and SHA-256.

Flags:
`

// genCommand parses gen's flags and runs a generation.
func genCommand(args []string, stdout, stderr io.Writer, locate func() (*engine.Engine, error)) int {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, genUsage)
		fs.PrintDefaults()
	}

	var (
		algo    = fs.String("algo", "ml-dsa-65", "algorithm: "+strings.Join(profile.SignatureIDs(), ", "))
		chain   = fs.Int("chain", 3, "certificates from root to leaf inclusive")
		out     = fs.String("out", "", "output directory (required)")
		days    = fs.Int("days", gen.MaxValidityDays, "certificate validity in days (max 30)")
		formats = fs.String("formats", "pem,der", "output encodings: pem, der, or pem,der")
		seed    = fs.String("seed", "", "hex seed for reproducible keys (ML-DSA only; see ADR-002)")
		sans    = fs.String("sans", strings.Join(gen.DefaultSANs, ","), "leaf subject alternative names")
		force   = fs.Bool("force", false, "replace an existing pqc-fixtures output directory")
		quiet   = fs.Bool("quiet", false, "suppress progress output")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "pqc-fixtures gen: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	spec, err := gen.Resolve(gen.Options{
		Algorithm:    *algo,
		ChainDepth:   *chain,
		OutDir:       *out,
		ValidityDays: *days,
		Formats:      *formats,
		SeedHex:      *seed,
		SANs:         splitList(*sans),
		Force:        *force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures gen: %v\n", err)
		return 2
	}
	for _, w := range spec.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	eng, err := locate()
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures gen: %v\n", err)
		return 1
	}

	var progress io.Writer = stdout
	if *quiet {
		progress = nil
	}
	result, err := gen.Generate(context.Background(), spec, eng, progress)
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures gen: %v\n", err)
		return 1
	}

	if !*quiet {
		fmt.Fprintf(stdout, "\nThese are insecure test fixtures. They expire in %d days and must never\n"+
			"be used to protect anything. Details: %s\n",
			spec.ValidityDays, manifest.FileName)
	}
	_ = result
	return 0
}

// splitList turns a comma-separated flag value into a slice, dropping empties.
// An explicitly empty value means "no SANs", which is distinct from unset.
func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

// engineCommand reports the located engine, so a user can confirm a release
// archive is intact and see exactly which OpenSSL their fixtures came from
// (design-dossier §9: engine version is auditable). locate is a parameter so
// tests can drive the failure path without an engine on disk.
func engineCommand(stdout, stderr io.Writer, locate func() (*engine.Engine, error)) int {
	e, err := locate()
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures: %v\n", err)
		return 1
	}

	version, err := e.Version(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures: %v\n", err)
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
		fmt.Fprintf(stderr, "\nwarning: engine version %s differs from the pinned %s; "+
			"generated fixtures may not match the documented size envelopes\n", version, engine.PinnedVersion)
	}
	return 0
}
