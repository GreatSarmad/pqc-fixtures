// Package preset holds the named worst-case fixture specifications
// (design-dossier §6: "presets are named FixtureSpecs shipped as data files,
// not code"). Each preset is one JSON file under presets/, embedded into the
// binary so `pqc-fixtures presets` works offline like everything else.
//
// A preset file carries only the request - which algorithm, how deep a chain,
// how long it lives - and the prose explaining what it is meant to break. It
// carries no byte counts: every size a preset promises is derived from
// src/profile's AlgorithmProfile registry, so a preset can never drift out of
// step with the standards' own numbers.
//
// Presets are versioned data. Changing a preset's parameters means bumping its
// Version, which is recorded in the manifest of every run that used it, so a
// fixture set generated months ago stays interpretable (design-dossier §10,
// "standards churn breaks presets").
package preset

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/GreatSarmad/pqc-fixtures/src/profile"
)

//go:embed presets/*.json
var files embed.FS

// Spec is the generation request a preset names. Field names and semantics
// mirror the `gen` flags they stand in for; a zero value means "leave the
// tool's own default in place".
type Spec struct {
	// Algorithm is a src/profile ID, e.g. "slh-dsa-sha2-256f".
	Algorithm string `json:"algorithm"`
	// ChainDepth is certificates from root to leaf inclusive.
	ChainDepth int `json:"chainDepth"`
	// ValidityDays is the certificate lifetime, capped by gen.MaxValidityDays.
	ValidityDays int `json:"validityDays"`
	// Formats is the --formats value, e.g. "pem,der".
	Formats string `json:"formats"`
	// SubjectAltNames replaces the default leaf SANs when non-empty.
	SubjectAltNames []string `json:"subjectAltNames,omitempty"`
}

// Preset is one named worst-case fixture specification.
type Preset struct {
	// Name is what the user passes to --preset. It must equal the file's stem.
	Name string `json:"name"`
	// Version is bumped whenever Spec changes, and is recorded in the manifest.
	Version int `json:"version"`
	// Summary is a single line for `pqc-fixtures presets`.
	Summary string `json:"summary"`
	// Description explains what the preset is for, in full sentences.
	Description string `json:"description"`
	// Breaks lists the specific failures this preset is designed to provoke.
	Breaks []string `json:"breaks"`
	// Spec is the generation request itself.
	Spec Spec `json:"spec"`
	// Deprecated, when non-empty, is the reason this preset should no longer
	// be used. Deprecated presets keep working and warn (design-dossier §10).
	Deprecated string `json:"deprecated,omitempty"`
}

// Profile resolves the preset's algorithm in the registry. Load has already
// proved it exists, so a caller can ignore the error in practice.
func (p Preset) Profile() (profile.Profile, error) { return profile.Lookup(p.Spec.Algorithm) }

// MinChainBytes is the smallest total DER certificate-chain size this preset
// can produce, taken from the AlgorithmProfile registry so no preset file ever
// carries a byte count of its own.
func (p Preset) MinChainBytes() int {
	prof, err := p.Profile()
	if err != nil {
		return 0
	}
	return prof.MinChainBytes(p.Spec.ChainDepth)
}

// registry is keyed by Preset.Name, populated once at package load.
var registry = mustLoad()

// Lookup resolves a --preset value.
func Lookup(name string) (Preset, error) {
	p, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Preset{}, fmt.Errorf("unknown preset %q; known presets: %s", name, strings.Join(Names(), ", "))
	}
	return p, nil
}

// Names lists every preset name, sorted, for help text and errors.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns every preset, ordered by name.
func All() []Preset {
	out := make([]Preset, 0, len(registry))
	for _, name := range Names() {
		out = append(out, registry[name])
	}
	return out
}

// mustLoad decodes the embedded preset files. A malformed preset is a build
// defect, not a user error, so it panics at package load rather than failing
// some later run: the files ship inside the binary and cannot change.
func mustLoad() map[string]Preset {
	loaded, err := Load(files)
	if err != nil {
		panic("preset: " + err.Error())
	}
	return loaded
}

// Load reads and validates every presets/*.json in fsys, keyed by name. The
// shipped registry is loaded from the embedded files at package load; Load is
// exported so the validation can be exercised against hand-built inputs
// without shipping a broken preset to find out.
func Load(fsys fs.FS) (map[string]Preset, error) {
	entries, err := fs.Glob(fsys, "presets/*.json")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no preset files found")
	}
	sort.Strings(entries)

	out := make(map[string]Preset, len(entries))
	for _, name := range entries {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var p Preset
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", name, err)
		}
		stem := strings.TrimSuffix(path.Base(name), ".json")
		if p.Name != stem {
			return nil, fmt.Errorf("%s declares name %q; it must match the file name", name, p.Name)
		}
		if err := validate(p); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if _, clash := out[p.Name]; clash {
			return nil, fmt.Errorf("duplicate preset %q", p.Name)
		}
		out[p.Name] = p
	}
	return out, nil
}

// validate enforces the invariants a preset file must satisfy. The bounds it
// does not know about - the validity cap and the chain-depth cap - belong to
// src/gen and are re-checked there when the preset is resolved, so this stays
// free of a dependency on the package that consumes it.
func validate(p Preset) error {
	if p.Version < 1 {
		return fmt.Errorf("version must be at least 1, got %d", p.Version)
	}
	if strings.TrimSpace(p.Summary) == "" {
		return fmt.Errorf("summary is required")
	}
	if strings.TrimSpace(p.Description) == "" {
		return fmt.Errorf("description is required")
	}
	if len(p.Breaks) == 0 {
		return fmt.Errorf("breaks must name at least one failure the preset provokes")
	}
	prof, err := profile.Lookup(p.Spec.Algorithm)
	if err != nil {
		return err
	}
	if prof.Kind != profile.KindSignature {
		return fmt.Errorf("%s cannot sign certificates", prof.ID)
	}
	if p.Spec.ChainDepth < 1 {
		return fmt.Errorf("chainDepth must be at least 1, got %d", p.Spec.ChainDepth)
	}
	if p.Spec.ValidityDays < 1 {
		return fmt.Errorf("validityDays must be at least 1, got %d", p.Spec.ValidityDays)
	}
	if strings.TrimSpace(p.Spec.Formats) == "" {
		return fmt.Errorf("formats is required")
	}
	return nil
}
