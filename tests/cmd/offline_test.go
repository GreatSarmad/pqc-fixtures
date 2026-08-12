package cmd_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBinaryCannotSpeakToTheNetwork guards design-dossier §8 criterion 5 and
// the ADR-007 prohibition on telemetry, structurally: if the shipped binary
// links no client networking package, no code path can phone home.
//
// `net` and `net/url` are allowed: crypto/x509 pulls them in to parse IP and
// URI names out of certificates. Nothing that can originate a request is.
func TestBinaryCannotSpeakToTheNetwork(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain available: %v", err)
	}

	cmd := exec.Command(goBin, "list", "-deps", "./src/cmd/pqc-fixtures")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps in %s: %v: %s", cmd.Dir, err, stderrOf(err))
	}

	forbidden := []string{
		"net/http",
		"net/smtp",
		"net/rpc",
		"net/http/httptrace",
		"golang.org/x/net",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range forbidden {
			if dep == banned || strings.HasPrefix(dep, banned+"/") {
				t.Errorf("the pqc-fixtures binary depends on %s; the tool is offline by construction", dep)
			}
		}
	}
}

// TestNoThirdPartyDependencies keeps the supply-chain surface at zero, which
// is the mitigation design-dossier §9 promises an audience that reads go.mod
// before installing anything.
func TestNoThirdPartyDependencies(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain available: %v", err)
	}

	cmd := exec.Command(goBin, "list", "-m", "all")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m all: %v: %s", err, stderrOf(err))
	}
	modules := strings.Fields(strings.TrimSpace(string(out)))
	if len(modules) != 1 || modules[0] != "github.com/GreatSarmad/pqc-fixtures" {
		t.Errorf("the module graph is no longer just this module: %v", modules)
	}
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

// stderrOf surfaces a failed command's diagnostics.
func stderrOf(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return strings.TrimSpace(string(exitErr.Stderr))
	}
	return ""
}
