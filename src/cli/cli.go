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
	"github.com/GreatSarmad/pqc-fixtures/src/preset"
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
  presets        list the worst-case presets gen can generate
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
	case "presets":
		return presetsCommand(args[1:], stdout, stderr)
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

  pqc-fixtures gen --preset worst-case-tls --out ./testdata

Writes a root CA, any intermediates, a leaf certificate usable as a local TLS
server certificate, a concatenated fullchain.pem, and a manifest.json
recording every artifact's size and SHA-256.

A preset is a complete, named specification (run "pqc-fixtures presets").
Flags given alongside --preset override it, and the manifest records that the
run no longer matches the preset it names.

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
		presetName = fs.String("preset", "", "worst-case preset: "+strings.Join(preset.Names(), ", "))
		algo       = fs.String("algo", "ml-dsa-65", "algorithm: "+strings.Join(profile.SignatureIDs(), ", "))
		chain      = fs.Int("chain", 3, "certificates from root to leaf inclusive")
		out        = fs.String("out", "", "output directory (required)")
		days       = fs.Int("days", gen.MaxValidityDays, "certificate validity in days (max 30)")
		formats    = fs.String("formats", "pem,der", "output encodings: pem, der, or pem,der")
		seed       = fs.String("seed", "", "hex seed for reproducible keys (ML-DSA only; see ADR-002)")
		sans       = fs.String("sans", strings.Join(gen.DefaultSANs, ","), "leaf subject alternative names")
		force      = fs.Bool("force", false, "replace an existing pqc-fixtures output directory")
		quiet      = fs.Bool("quiet", false, "suppress progress output")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "pqc-fixtures gen: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	opts := gen.Options{
		Algorithm:    *algo,
		ChainDepth:   *chain,
		OutDir:       *out,
		ValidityDays: *days,
		Formats:      *formats,
		SeedHex:      *seed,
		SANs:         splitList(*sans),
		Force:        *force,
	}

	var presetNotes []string
	if *presetName != "" {
		var err error
		if presetNotes, err = applyPreset(&opts, *presetName, explicitFlags(fs)); err != nil {
			fmt.Fprintf(stderr, "pqc-fixtures gen: %v\n", err)
			return 2
		}
	}

	spec, err := gen.Resolve(opts)
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures gen: %v\n", err)
		return 2
	}
	for _, note := range presetNotes {
		fmt.Fprintf(stderr, "warning: %s\n", note)
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

// explicitFlags reports which flags the user actually typed, as distinct from
// the ones sitting at their default. A preset supplies everything the user did
// not, so telling the two apart is the whole mechanism.
func explicitFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// applyPreset overlays a named preset onto opts, leaving any flag the user
// typed untouched, and returns the warnings to show before generation starts.
//
// Resolving a preset lives here rather than in src/gen because only the CLI
// knows which values came from the user and which are defaults; the core
// receives an ordinary Options with the preset recorded as provenance.
func applyPreset(opts *gen.Options, name string, explicit map[string]bool) ([]string, error) {
	p, err := preset.Lookup(name)
	if err != nil {
		return nil, err
	}

	var notes []string
	if p.Deprecated != "" {
		notes = append(notes, fmt.Sprintf("preset %s is deprecated: %s", p.Name, p.Deprecated))
	}

	var overridden []string
	take := func(flagName string, specified bool, assign func()) {
		if !specified {
			return
		}
		if explicit[flagName] {
			overridden = append(overridden, "--"+flagName)
			return
		}
		assign()
	}
	take("algo", p.Spec.Algorithm != "", func() { opts.Algorithm = p.Spec.Algorithm })
	take("chain", p.Spec.ChainDepth > 0, func() { opts.ChainDepth = p.Spec.ChainDepth })
	take("days", p.Spec.ValidityDays > 0, func() { opts.ValidityDays = p.Spec.ValidityDays })
	take("formats", p.Spec.Formats != "", func() { opts.Formats = p.Spec.Formats })
	take("sans", len(p.Spec.SubjectAltNames) > 0, func() { opts.SANs = p.Spec.SubjectAltNames })

	opts.PresetName = p.Name
	opts.PresetVersion = p.Version
	opts.PresetModified = len(overridden) > 0
	if len(overridden) > 0 {
		notes = append(notes, fmt.Sprintf(
			"%s overrode preset %s, so this run does not produce what %s promises; "+
				"the manifest records it as a modified preset",
			strings.Join(overridden, " and "), p.Name, p.Name))
	}
	return notes, nil
}

const presetsUsage = `pqc-fixtures presets - worst-case fixture specifications

Usage:
  pqc-fixtures presets           list every preset
  pqc-fixtures presets <name>    describe one preset in full

Each preset is a complete generation request. Generate one with:
  pqc-fixtures gen --preset <name> --out ./testdata
`

// presetsCommand lists the shipped presets, or describes one of them.
func presetsCommand(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0:
		listPresets(stdout)
		return 0
	case args[0] == "-h" || args[0] == "--help":
		fmt.Fprint(stdout, presetsUsage)
		return 0
	case len(args) > 1:
		fmt.Fprintf(stderr, "pqc-fixtures presets: unexpected argument %q\n\n%s", args[1], presetsUsage)
		return 2
	}

	p, err := preset.Lookup(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "pqc-fixtures presets: %v\n", err)
		return 2
	}
	describePreset(stdout, p)
	return 0
}

// listPresets prints one aligned block per preset: the headline, then the
// numbers that make it worth generating.
func listPresets(stdout io.Writer) {
	fmt.Fprintln(stdout, "Worst-case presets. Generate one with: pqc-fixtures gen --preset <name> --out ./testdata")
	for _, p := range preset.All() {
		fmt.Fprintf(stdout, "\n%s\n", p.Name)
		fmt.Fprintf(stdout, "  %s\n", p.Summary)
		fmt.Fprintf(stdout, "  %s\n", presetShape(p))
		if p.Deprecated != "" {
			fmt.Fprintf(stdout, "  DEPRECATED: %s\n", p.Deprecated)
		}
	}
	fmt.Fprintf(stdout, "\nRun \"pqc-fixtures presets <name>\" for what each one is designed to break.\n")
}

// describePreset prints everything a preset file carries.
func describePreset(stdout io.Writer, p preset.Preset) {
	fmt.Fprintf(stdout, "%s (v%d)\n\n", p.Name, p.Version)
	if p.Deprecated != "" {
		fmt.Fprintf(stdout, "DEPRECATED: %s\n\n", p.Deprecated)
	}
	fmt.Fprintf(stdout, "%s\n\n", p.Description)
	fmt.Fprintf(stdout, "Generates: %s\n", presetShape(p))
	if len(p.Spec.SubjectAltNames) > 0 {
		fmt.Fprintf(stdout, "Leaf SANs: %s\n", strings.Join(p.Spec.SubjectAltNames, ", "))
	}
	fmt.Fprintf(stdout, "Validity:  %d days\n", p.Spec.ValidityDays)
	fmt.Fprintf(stdout, "Encodings: %s\n", p.Spec.Formats)
	fmt.Fprintln(stdout, "\nDesigned to break:")
	for _, b := range p.Breaks {
		fmt.Fprintf(stdout, "  - %s\n", b)
	}
	fmt.Fprintf(stdout, "\n  pqc-fixtures gen --preset %s --out ./testdata\n", p.Name)
}

// presetShape is the one-line size statement: what you get and how big it is
// at minimum. Every number here comes from the AlgorithmProfile registry, not
// from the preset file.
func presetShape(p preset.Preset) string {
	prof, err := p.Profile()
	if err != nil {
		return p.Spec.Algorithm
	}
	certs, each := "certificates", " each"
	if p.Spec.ChainDepth == 1 {
		certs, each = "certificate", ""
	}
	return fmt.Sprintf("%d %s %s, %s B signature%s, at least %s B of DER chain",
		p.Spec.ChainDepth, prof.EngineName, certs,
		thousands(prof.SignatureBytes), each, thousands(prof.MinChainBytes(p.Spec.ChainDepth)))
}

// thousands formats a byte count with separators. The core has its own copy;
// duplicating five lines is cheaper here than exporting formatting from a
// package whose job is generation.
func thousands(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, digit := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, digit)
	}
	return string(out)
}
