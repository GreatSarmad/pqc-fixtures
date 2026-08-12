package gen_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/engine"
	"github.com/GreatSarmad/pqc-fixtures/src/gen"
	"github.com/GreatSarmad/pqc-fixtures/src/manifest"
)

// failingEngine implements the core's Engine seam and fails partway through a
// run. The failure paths of design-dossier §9 ("partial/corrupt generation")
// are exactly the ones a real engine will not reproduce on demand, so they are
// tested against a stub instead.
type failingEngine struct {
	failAfterKeys int
	keys          int
}

var errEngineExploded = errors.New("simulated engine failure")

func (f *failingEngine) Version(context.Context) (string, error) { return "3.5.7", nil }

func (f *failingEngine) GenerateKey(_ context.Context, req engine.KeyRequest) error {
	if f.keys >= f.failAfterKeys {
		return errEngineExploded
	}
	f.keys++
	// Leave a real file behind, so the test proves the staging directory is
	// cleaned up rather than simply never written to.
	return os.WriteFile(req.OutPath, []byte("stub key\n"), 0o600)
}

func (f *failingEngine) IssueCert(context.Context, engine.CertRequest) error {
	return errEngineExploded
}
func (f *failingEngine) ConvertCert(context.Context, string, string) error { return errEngineExploded }
func (f *failingEngine) ConvertKey(context.Context, string, string) error  { return errEngineExploded }
func (f *failingEngine) VerifyChain(context.Context, string, []string, string) error {
	return errEngineExploded
}

func resolveInto(t *testing.T, outDir string, mutate func(*gen.Options)) *gen.Spec {
	t.Helper()
	opts := validOptions()
	opts.OutDir = outDir
	if mutate != nil {
		mutate(&opts)
	}
	spec, err := gen.Resolve(opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return spec
}

// TestFailedRunLeavesNothingBehind: a run that dies mid-generation must not
// create the output directory, and must not leave staging directories in its
// parent (design-dossier §9: atomic output).
func TestFailedRunLeavesNothingBehind(t *testing.T) {
	parent := t.TempDir()
	outDir := filepath.Join(parent, "testdata")

	_, err := gen.Generate(context.Background(), resolveInto(t, outDir, nil), &failingEngine{failAfterKeys: 1}, nil)
	if err == nil {
		t.Fatal("Generate succeeded with a failing engine")
	}

	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("output directory exists after a failed run (stat error: %v)", err)
	}
	assertNoStagingDirs(t, parent)
}

// TestFailedForcedRunKeepsThePreviousFixtures: --force must not destroy a
// usable fixture set until the replacement is complete.
func TestFailedForcedRunKeepsThePreviousFixtures(t *testing.T) {
	parent := t.TempDir()
	outDir := filepath.Join(parent, "testdata")
	writeFixtureDir(t, outDir, "previous run")

	_, err := gen.Generate(context.Background(),
		resolveInto(t, outDir, func(o *gen.Options) { o.Force = true }),
		&failingEngine{failAfterKeys: 0}, nil)
	if err == nil {
		t.Fatal("Generate succeeded with a failing engine")
	}

	kept, err := os.ReadFile(filepath.Join(outDir, "INSECURE-TEST-marker.txt"))
	if err != nil {
		t.Fatalf("previous fixture set was destroyed by a failed --force run: %v", err)
	}
	if string(kept) != "previous run" {
		t.Errorf("previous fixture content changed: %q", kept)
	}
	assertNoStagingDirs(t, parent)
}

// TestRefusesNonEmptyDestinationWithoutForce protects a user who points --out
// at a directory that already holds something.
func TestRefusesNonEmptyDestinationWithoutForce(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "testdata")
	writeFixtureDir(t, outDir, "previous run")

	_, err := gen.Generate(context.Background(), resolveInto(t, outDir, nil), &failingEngine{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected a refusal mentioning --force, got %v", err)
	}
}

// TestForceRefusesDirectoriesWeDidNotWrite: --force replaces a previous
// pqc-fixtures run, never arbitrary user data.
func TestForceRefusesDirectoriesWeDidNotWrite(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "important")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "thesis.txt"), []byte("years of work"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := gen.Generate(context.Background(),
		resolveInto(t, outDir, func(o *gen.Options) { o.Force = true }),
		&failingEngine{}, nil)
	if err == nil {
		t.Fatal("--force replaced a directory pqc-fixtures did not create")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error %q does not explain the refusal", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "thesis.txt")); err != nil {
		t.Errorf("unrelated file was removed: %v", err)
	}
}

func TestAcceptsEmptyDestination(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "empty")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, err := gen.Generate(context.Background(), resolveInto(t, outDir, nil), &failingEngine{failAfterKeys: 1}, nil)
	if err == nil || strings.Contains(err.Error(), "not empty") {
		t.Fatalf("an empty destination should be accepted, got %v", err)
	}
}

// writeFixtureDir creates a directory that looks like a previous pqc-fixtures
// run, so --force recognizes it as ours.
func writeFixtureDir(t *testing.T, dir, marker string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "INSECURE-TEST-marker.txt"), []byte(marker), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	previous := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Warning:       manifest.Warning,
		Tool:          manifest.Tool{Name: "pqc-fixtures", Version: "test"},
		Engine:        manifest.Engine{Name: "openssl", Version: "3.5.7", PinnedVersion: "3.5.7"},
		GeneratedAt:   "2026-08-12T00:00:00Z",
	}
	if err := previous.WriteFile(filepath.Join(dir, manifest.FileName)); err != nil {
		t.Fatalf("writing previous manifest: %v", err)
	}
}

func assertNoStagingDirs(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pqc-fixtures-tmp-") ||
			strings.Contains(entry.Name(), ".replaced-") {
			t.Errorf("staging directory %q survived the run", entry.Name())
		}
	}
}
