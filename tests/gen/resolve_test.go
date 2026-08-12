package gen_test

import (
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/gen"
)

// validOptions is a request that resolves cleanly; each test perturbs one
// field.
func validOptions() gen.Options {
	return gen.Options{
		Algorithm:    "ml-dsa-65",
		ChainDepth:   3,
		OutDir:       "./testdata",
		ValidityDays: 30,
		Formats:      "pem,der",
	}
}

func TestResolveDefaults(t *testing.T) {
	spec, err := gen.Resolve(validOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if spec.Profile.ID != "ml-dsa-65" {
		t.Errorf("Profile.ID = %q, want ml-dsa-65", spec.Profile.ID)
	}
	if got := strings.Join(spec.Formats, ","); got != "pem,der" {
		t.Errorf("Formats = %q, want pem,der", got)
	}
	if got := strings.Join(spec.SANs, ","); got != strings.Join(gen.DefaultSANs, ",") {
		t.Errorf("SANs = %v, want the defaults %v", spec.SANs, gen.DefaultSANs)
	}
	if spec.Seeded() {
		t.Error("Seeded() is true without --seed")
	}
	if len(spec.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", spec.Warnings)
	}
}

func TestResolveRejectsBadRequests(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*gen.Options)
		expect string
	}{
		"unknown algorithm":  {func(o *gen.Options) { o.Algorithm = "rsa-4096" }, "unknown algorithm"},
		"kem algorithm":      {func(o *gen.Options) { o.Algorithm = "ml-kem-768" }, "cannot sign certificates"},
		"zero chain":         {func(o *gen.Options) { o.ChainDepth = 0 }, "--chain"},
		"negative chain":     {func(o *gen.Options) { o.ChainDepth = -1 }, "--chain"},
		"chain beyond cap":   {func(o *gen.Options) { o.ChainDepth = gen.MaxChainDepth + 1 }, "--chain"},
		"validity beyond 30": {func(o *gen.Options) { o.ValidityDays = gen.MaxValidityDays + 1 }, "--days"},
		"zero validity":      {func(o *gen.Options) { o.ValidityDays = 0 }, "--days"},
		"missing out":        {func(o *gen.Options) { o.OutDir = "  " }, "--out"},
		"unknown format":     {func(o *gen.Options) { o.Formats = "pem,pkcs12" }, "unknown format"},
		"non-hex seed":       {func(o *gen.Options) { o.SeedHex = "zzzz" }, "hex"},
		"short seed":         {func(o *gen.Options) { o.SeedHex = "00112233" }, "at least 16 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := validOptions()
			tc.mutate(&opts)
			_, err := gen.Resolve(opts)
			if err == nil {
				t.Fatalf("Resolve accepted %s", name)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not mention %q", err, tc.expect)
			}
		})
	}
}

// TestResolveSeedIsAlgorithmAware is ADR-002 in the CLI surface: --seed works
// for ML-DSA and is a documented no-op for SLH-DSA rather than a silent one.
func TestResolveSeedIsAlgorithmAware(t *testing.T) {
	const seed = "00112233445566778899aabbccddeeff"

	opts := validOptions()
	opts.SeedHex = seed
	spec, err := gen.Resolve(opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !spec.Seeded() {
		t.Error("ML-DSA run with --seed is not marked seeded")
	}
	if len(spec.Warnings) != 0 {
		t.Errorf("unexpected warnings for a seedable algorithm: %v", spec.Warnings)
	}

	opts.Algorithm = "slh-dsa-sha2-256f"
	spec, err = gen.Resolve(opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if spec.Seeded() {
		t.Error("SLH-DSA run is marked seeded, but SLH-DSA has no seeded keygen (ADR-002)")
	}
	if len(spec.Warnings) == 0 {
		t.Fatal("SLH-DSA + --seed produced no warning; the no-op must be visible")
	}
	if !strings.Contains(strings.Join(spec.Warnings, " "), "not reproducible") {
		t.Errorf("warning %v does not explain the consequence", spec.Warnings)
	}
}

func TestResolveSeedAcceptsHexPrefix(t *testing.T) {
	opts := validOptions()
	opts.SeedHex = "0x00112233445566778899aabbccddeeff"
	spec, err := gen.Resolve(opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !spec.Seeded() {
		t.Error("0x-prefixed seed was not accepted")
	}
}

func TestResolveFormats(t *testing.T) {
	for raw, want := range map[string]string{
		"":            "pem,der",
		"pem":         "pem",
		"der":         "der",
		"DER , pem":   "pem,der",
		"pem,pem,der": "pem,der",
	} {
		opts := validOptions()
		opts.Formats = raw
		spec, err := gen.Resolve(opts)
		if err != nil {
			t.Fatalf("Resolve(formats=%q): %v", raw, err)
		}
		if got := strings.Join(spec.Formats, ","); got != want {
			t.Errorf("formats %q resolved to %q, want %q", raw, got, want)
		}
	}
}
