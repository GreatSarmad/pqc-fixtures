// Package testengine locates an OpenSSL engine for tests that need real
// artifacts.
//
// Most of the core is tested without an engine. The acceptance criteria that
// are about bytes on disk - chain verification, size fidelity, manifest hashes
// (design-dossier §8 criteria 2, 3, 4, 6) - cannot be: they only mean anything
// against a real engine. Those tests skip when none is present, so `make test`
// stays fast on a bare checkout, and run for real in the Engine workflow,
// which builds the pinned engine on all three supported platforms.
package testengine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/engine"
)

// Locate returns an engine from PQC_FIXTURES_OPENSSL or from dist/engine in
// the repository root, skipping the test if neither is available.
func Locate(t *testing.T) *engine.Engine {
	t.Helper()

	if path, ok := os.LookupEnv(engine.EnvOverride); ok && path != "" {
		e, err := engine.LocateIn("", os.LookupEnv)
		if err != nil {
			t.Fatalf("%s=%s is set but unusable: %v", engine.EnvOverride, path, err)
		}
		return e
	}

	dist := filepath.Join(repoRoot(t), "dist")
	e, err := engine.LocateIn(dist, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Skipf("no OpenSSL engine available: build one with `make engine`, or set %s "+
			"to an OpenSSL %s binary (%v)", engine.EnvOverride, engine.PinnedVersion, err)
	}
	return e
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod above %s", dir)
		}
		dir = parent
	}
}
