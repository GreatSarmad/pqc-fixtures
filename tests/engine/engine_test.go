package engine_test

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/engine"
)

// fakeEngine writes an executable stub at dir/engine/openssl that echoes the
// given `openssl version` output. Locating and identifying the engine must work
// without a real 6 MB OpenSSL build in the test tree.
func fakeEngine(t *testing.T, dir, versionOutput string) string {
	t.Helper()
	engineDir := filepath.Join(dir, "engine")
	if err := os.MkdirAll(engineDir, 0o755); err != nil {
		t.Fatalf("creating engine dir: %v", err)
	}
	path := filepath.Join(engineDir, "openssl")
	script := "#!/bin/sh\necho '" + versionOutput + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake engine: %v", err)
	}
	return path
}

func noEnv(string) (string, bool) { return "", false }

// The fake engines below deliberately report a version that is NOT the current
// pin. Resolution and version parsing must work on whatever the engine on disk
// says, so hardcoding the pinned version here would weaken the tests and force
// an edit on every bump. Do not "fix" these to match engine.PinnedVersion —
// TestPinnedVersionMatchesBuildPin is what guards the pin itself.

func TestLocateFindsBundledEngine(t *testing.T) {
	binDir := t.TempDir()
	want := fakeEngine(t, binDir, "OpenSSL 3.5.7 9 Jun 2026")

	got, err := engine.LocateIn(binDir, noEnv)
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	if got.Path != want {
		t.Errorf("Path = %q, want %q", got.Path, want)
	}
	if got.FromOverride {
		t.Error("FromOverride = true, want false for a bundled engine")
	}
}

func TestLocatePrefersEnvironmentOverride(t *testing.T) {
	binDir := t.TempDir()
	fakeEngine(t, binDir, "OpenSSL 3.5.7 9 Jun 2026")

	overrideDir := t.TempDir()
	override := fakeEngine(t, overrideDir, "OpenSSL 3.6.2 7 Apr 2026")

	got, err := engine.LocateIn(binDir, func(k string) (string, bool) {
		if k == engine.EnvOverride {
			return override, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	if got.Path != override {
		t.Errorf("Path = %q, want the override %q", got.Path, override)
	}
	if !got.FromOverride {
		t.Error("FromOverride = false, want true when PQC_FIXTURES_OPENSSL is set")
	}
}

func TestLocateReportsMissingEngineActionably(t *testing.T) {
	_, err := engine.LocateIn(t.TempDir(), noEnv)
	if err == nil {
		t.Fatal("LocateIn succeeded with no engine present, want an error")
	}
	if !errors.Is(err, engine.ErrNotFound) {
		t.Errorf("error does not wrap ErrNotFound: %v", err)
	}
	// A user whose engine is missing must be told how to recover, not just that
	// a path is missing — and the message must not assert how they got here.
	for _, want := range []string{"Unpack the whole release archive", engine.EnvOverride} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "copying the binary out") {
		t.Errorf("error still accuses the user of copying the binary: %v", err)
	}
}

// TestLocateForExecutableFollowsASymlinkedCommand covers the ordinary way a CLI
// gets installed: the real files live in one directory and a symlink on PATH
// points at the binary. os.Executable does not resolve symlinks on macOS, so
// without this the engine is sought beside the link and every command fails.
func TestLocateForExecutableFollowsASymlinkedCommand(t *testing.T) {
	realDir := t.TempDir()
	want := fakeEngine(t, realDir, "OpenSSL 3.5.7 9 Jun 2026")
	binary := filepath.Join(realDir, "pqc-fixtures")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("writing fake binary: %v", err)
	}

	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "pqc-fixtures")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatalf("symlinking: %v", err)
	}

	got, err := engine.LocateForExecutable(link, noEnv)
	if err != nil {
		t.Fatalf("LocateForExecutable through a symlink: %v", err)
	}
	// Compare the files, not the spellings: resolving through the link also
	// normalises the path (on macOS /var is itself a symlink to /private/var),
	// so the engine is reported at its fully resolved location.
	if !sameFile(t, got.Path, want) {
		t.Errorf("Path = %q, want the engine beside the link's target, %q", got.Path, want)
	}
	if got.FromOverride {
		t.Error("FromOverride = true, want false for a bundled engine")
	}
}

// sameFile reports whether two paths name the same file on disk, so tests can
// assert on identity rather than on how a path happens to be spelled.
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatalf("stat %s: %v", a, err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatalf("stat %s: %v", b, err)
	}
	return os.SameFile(fa, fb)
}

// TestLocateForExecutablePrefersTheCommandsOwnDirectory pins the precedence:
// an engine beside the link wins over one beside the link's target, so adding
// symlink support cannot change what an existing working layout resolves to.
func TestLocateForExecutablePrefersTheCommandsOwnDirectory(t *testing.T) {
	realDir := t.TempDir()
	fakeEngine(t, realDir, "OpenSSL 3.5.7 9 Jun 2026")
	binary := filepath.Join(realDir, "pqc-fixtures")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("writing fake binary: %v", err)
	}

	linkDir := t.TempDir()
	beside := fakeEngine(t, linkDir, "OpenSSL 3.6.2 7 Apr 2026")
	link := filepath.Join(linkDir, "pqc-fixtures")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatalf("symlinking: %v", err)
	}

	got, err := engine.LocateForExecutable(link, noEnv)
	if err != nil {
		t.Fatalf("LocateForExecutable: %v", err)
	}
	if !sameFile(t, got.Path, beside) {
		t.Errorf("Path = %q, want the engine beside the command itself, %q", got.Path, beside)
	}
}

// TestLocateForExecutableStillReportsAMissingEngine: following symlinks must not
// swallow the actionable error when there is no engine on either path.
func TestLocateForExecutableStillReportsAMissingEngine(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "pqc-fixtures")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("writing fake binary: %v", err)
	}

	if _, err := engine.LocateForExecutable(binary, noEnv); !errors.Is(err, engine.ErrNotFound) {
		t.Errorf("error does not wrap ErrNotFound: %v", err)
	}
}

func TestLocateRejectsNonExecutableEngine(t *testing.T) {
	binDir := t.TempDir()
	engineDir := filepath.Join(binDir, "engine")
	if err := os.MkdirAll(engineDir, 0o755); err != nil {
		t.Fatalf("creating engine dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(engineDir, "openssl"), []byte("not a program"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if _, err := engine.LocateIn(binDir, noEnv); err == nil {
		t.Fatal("LocateIn accepted a non-executable engine, want an error")
	}
}

func TestVersionReportsEngineVersion(t *testing.T) {
	binDir := t.TempDir()
	fakeEngine(t, binDir, "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)")

	e, err := engine.LocateIn(binDir, noEnv)
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	version, err := e.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if version != "3.5.7" {
		t.Errorf("Version = %q, want %q", version, "3.5.7")
	}
}

func TestVersionRejectsUnrecognizedOutput(t *testing.T) {
	binDir := t.TempDir()
	fakeEngine(t, binDir, "LibreSSL 3.3.6")

	e, err := engine.LocateIn(binDir, noEnv)
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	if _, err := e.Version(context.Background()); err == nil {
		t.Fatal("Version accepted non-OpenSSL output, want an error")
	}
}

// The Go constant and the shell pin are read by different tools (the CLI and
// the release workflow); ADR-001's reproducibility guarantee depends on them
// never drifting apart.
func TestPinnedVersionMatchesBuildPin(t *testing.T) {
	pins := readPinFile(t)

	if got := pins["OPENSSL_VERSION"]; got != engine.PinnedVersion {
		t.Errorf("scripts/openssl-pin.env OPENSSL_VERSION = %q, but engine.PinnedVersion = %q", got, engine.PinnedVersion)
	}

	sha := pins["OPENSSL_SHA256"]
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sha) {
		t.Errorf("OPENSSL_SHA256 = %q, want a 64-character lowercase hex digest", sha)
	}
}

// ADR-001 pins the 3.5.x LTS branch: it is the first release line with native
// ML-KEM/ML-DSA/SLH-DSA and is supported until 2030. A pin outside that branch
// would silently change the algorithm surface the fixtures depend on.
func TestPinnedVersionStaysOnTheLTSBranch(t *testing.T) {
	if !strings.HasPrefix(engine.PinnedVersion, "3.5.") {
		t.Errorf("PinnedVersion = %q, want a 3.5.x LTS release (ADR-001)", engine.PinnedVersion)
	}
}

func readPinFile(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "scripts", "openssl-pin.env"))
	if err != nil {
		t.Fatalf("opening pin file: %v", err)
	}
	defer f.Close()

	pins := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("unparsable line in pin file: %q", line)
		}
		pins[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading pin file: %v", err)
	}
	return pins
}
