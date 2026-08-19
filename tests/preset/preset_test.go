package preset_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/GreatSarmad/pqc-fixtures/src/gen"
	"github.com/GreatSarmad/pqc-fixtures/src/preset"
)

// The three presets ROADMAP F2 names. They are listed here rather than derived
// from the registry so that deleting a preset file fails a test instead of
// quietly shrinking the shipped set.
var required = []string{"deep-chain", "jumbo", "worst-case-tls"}

func TestEveryRequiredPresetShips(t *testing.T) {
	for _, name := range required {
		if _, err := preset.Lookup(name); err != nil {
			t.Errorf("Lookup(%q): %v", name, err)
		}
	}
}

func TestLookupIsCaseInsensitiveAndRejectsUnknownNames(t *testing.T) {
	p, err := preset.Lookup("  JUMBO ")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if p.Name != "jumbo" {
		t.Errorf("Name = %q, want jumbo", p.Name)
	}

	_, err = preset.Lookup("no-such-preset")
	if err == nil {
		t.Fatal("Lookup of an unknown preset returned no error")
	}
	// The error has to teach, not just refuse.
	for _, name := range required {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not list the known preset %q", err, name)
		}
	}
}

// TestPresetsResolveIntoAValidSpec: a preset is only useful if the core
// accepts it, so every shipped preset is pushed through gen.Resolve - which is
// where the chain-depth and validity caps the preset package deliberately does
// not know about are enforced.
func TestPresetsResolveIntoAValidSpec(t *testing.T) {
	for _, p := range preset.All() {
		spec, err := gen.Resolve(gen.Options{
			Algorithm:     p.Spec.Algorithm,
			ChainDepth:    p.Spec.ChainDepth,
			OutDir:        t.TempDir(),
			ValidityDays:  p.Spec.ValidityDays,
			Formats:       p.Spec.Formats,
			SANs:          p.Spec.SubjectAltNames,
			PresetName:    p.Name,
			PresetVersion: p.Version,
		})
		if err != nil {
			t.Errorf("preset %s does not resolve: %v", p.Name, err)
			continue
		}
		if spec.PresetName != p.Name || spec.PresetVersion != p.Version {
			t.Errorf("preset %s: spec records %s v%d", p.Name, spec.PresetName, spec.PresetVersion)
		}
		if len(spec.Warnings) > 0 {
			t.Errorf("preset %s resolves with warnings: %v", p.Name, spec.Warnings)
		}
	}
}

// TestEveryPresetIsVersionedAndDocumented guards the contract that makes an
// old fixture set interpretable: a name, a version, and prose saying what the
// preset is for.
func TestEveryPresetIsVersionedAndDocumented(t *testing.T) {
	for _, p := range preset.All() {
		if p.Version < 1 {
			t.Errorf("preset %s has version %d", p.Name, p.Version)
		}
		if strings.TrimSpace(p.Summary) == "" || strings.TrimSpace(p.Description) == "" {
			t.Errorf("preset %s is missing a summary or description", p.Name)
		}
		if len(p.Breaks) == 0 {
			t.Errorf("preset %s does not say what it is designed to break", p.Name)
		}
	}
}

// TestPresetSizesComeFromTheRegistry: no preset file may carry a byte count of
// its own, so the numbers a preset promises can never drift from FIPS
// 203/204/205 as src/profile records them (ROADMAP F2).
func TestPresetSizesComeFromTheRegistry(t *testing.T) {
	for _, p := range preset.All() {
		prof, err := p.Profile()
		if err != nil {
			t.Errorf("preset %s: %v", p.Name, err)
			continue
		}
		want := prof.MinChainBytes(p.Spec.ChainDepth)
		if got := p.MinChainBytes(); got != want {
			t.Errorf("preset %s: MinChainBytes = %d, want the registry's %d", p.Name, got, want)
		}
	}

	dir := presetDir(t)
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("globbing %s: %v (%d files)", dir, err, len(entries))
	}
	for _, path := range entries {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var generic map[string]any
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		spec, _ := generic["spec"].(map[string]any)
		for key := range spec {
			switch key {
			case "algorithm", "chainDepth", "validityDays", "formats", "subjectAltNames":
			default:
				t.Errorf("%s: spec carries %q; presets describe the request, never its sizes", path, key)
			}
		}
	}
}

// TestWorstCasePresetsClearTheDossierBar: design-dossier §8 criterion 7 wants a
// chain of at least 45 KB. The floor is registry-derived, so this holds without
// generating anything.
func TestWorstCasePresetsClearTheDossierBar(t *testing.T) {
	const wantBytes = 45 * 1000
	for _, name := range []string{"jumbo", "worst-case-tls"} {
		p, err := preset.Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if got := p.MinChainBytes(); got < wantBytes {
			t.Errorf("preset %s guarantees only %d bytes of chain, want at least %d", name, got, wantBytes)
		}
	}
}

// TestDeepChainIsDeeperThanCommonLimits: deep-chain earns its name by sitting
// at the chain-length cap that trips real TLS stacks, not by being large.
func TestDeepChainIsDeeperThanCommonLimits(t *testing.T) {
	p, err := preset.Lookup("deep-chain")
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec.ChainDepth < 10 {
		t.Errorf("deep-chain depth = %d, want at least 10 (Java's default cap)", p.Spec.ChainDepth)
	}
	if p.Spec.ChainDepth > gen.MaxChainDepth {
		t.Errorf("deep-chain depth = %d, above gen.MaxChainDepth %d", p.Spec.ChainDepth, gen.MaxChainDepth)
	}
}

// TestSeedableAlgorithmsAreNotPromisedByNonSeedablePresets records the ADR-002
// consequence: the SLH-DSA presets can never be reproducible, so nothing in
// their prose may claim otherwise.
func TestSLHDSAPresetsDoNotPromiseReproducibility(t *testing.T) {
	for _, p := range preset.All() {
		prof, err := p.Profile()
		if err != nil {
			t.Fatal(err)
		}
		if prof.Seedable() {
			continue
		}
		text := strings.ToLower(p.Summary + " " + p.Description + " " + strings.Join(p.Breaks, " "))
		for _, claim := range []string{"reproducib", "deterministic", "byte-identical"} {
			if strings.Contains(text, claim) {
				t.Errorf("preset %s uses %s but %s cannot be seeded (ADR-002)", p.Name, claim, prof.EngineName)
			}
		}
	}
}

// The loader's validation is what stops a malformed preset from shipping, so
// it is exercised directly against hand-built files.
func TestLoadRejectsMalformedPresets(t *testing.T) {
	valid := `{"name":"x","version":1,"summary":"s","description":"d","breaks":["b"],` +
		`"spec":{"algorithm":"ml-dsa-44","chainDepth":2,"validityDays":30,"formats":"pem"}}`

	cases := []struct {
		name string
		body string
		want string
	}{
		{"name does not match the file", strings.Replace(valid, `"name":"x"`, `"name":"y"`, 1), "must match the file name"},
		{"version missing", strings.Replace(valid, `"version":1`, `"version":0`, 1), "version"},
		{"summary missing", strings.Replace(valid, `"summary":"s"`, `"summary":""`, 1), "summary"},
		{"description missing", strings.Replace(valid, `"description":"d"`, `"description":""`, 1), "description"},
		{"breaks missing", strings.Replace(valid, `"breaks":["b"]`, `"breaks":[]`, 1), "breaks"},
		{"unknown algorithm", strings.Replace(valid, `"ml-dsa-44"`, `"rsa-2048"`, 1), "unknown algorithm"},
		{"kem cannot sign", strings.Replace(valid, `"ml-dsa-44"`, `"ml-kem-768"`, 1), "cannot sign"},
		{"chain depth zero", strings.Replace(valid, `"chainDepth":2`, `"chainDepth":0`, 1), "chainDepth"},
		{"validity zero", strings.Replace(valid, `"validityDays":30`, `"validityDays":0`, 1), "validityDays"},
		{"formats empty", strings.Replace(valid, `"formats":"pem"`, `"formats":""`, 1), "formats"},
		{"unknown field", strings.Replace(valid, `"version":1`, `"version":1,"colour":"blue"`, 1), "colour"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{"presets/x.json": &fstest.MapFile{Data: []byte(tc.body)}}
			_, err := preset.Load(fsys)
			if err == nil {
				t.Fatalf("load accepted a preset with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}

	t.Run("valid preset loads", func(t *testing.T) {
		fsys := fstest.MapFS{"presets/x.json": &fstest.MapFile{Data: []byte(valid)}}
		loaded, err := preset.Load(fsys)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(loaded) != 1 || loaded["x"].Spec.ChainDepth != 2 {
			t.Errorf("loaded = %#v", loaded)
		}
	})

	t.Run("no presets at all", func(t *testing.T) {
		if _, err := preset.Load(fstest.MapFS{}); err == nil {
			t.Error("load accepted an empty preset directory")
		}
	})
}

// presetDir locates the shipped preset files relative to the module root.
func presetDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "src", "preset", "presets")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the test's working directory")
		}
		dir = parent
	}
}
