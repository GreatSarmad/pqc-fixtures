// Package engine locates the vendored OpenSSL engine that pqc-fixtures shells
// out to. It performs no cryptography itself (design-dossier §3) and makes no
// network calls (§8 criterion 5) - it only resolves and identifies the binary
// that ADR-001 requires us to ship alongside the CLI.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PinnedVersion is the OpenSSL version the release pipeline vendors. It is kept
// in sync with scripts/openssl-pin.env, which is the single source of truth for
// the build; tests/engine asserts the two agree.
const PinnedVersion = "3.5.8"

// EnvOverride names an explicit engine path, for development against a locally
// built engine and for packagers who bundle the engine elsewhere.
const EnvOverride = "PQC_FIXTURES_OPENSSL"

// dirName is the directory, relative to the pqc-fixtures executable, that the
// release artifact unpacks the engine into.
const dirName = "engine"

// binName is the engine executable's filename inside dirName.
const binName = "openssl"

// ErrNotFound reports that no vendored engine could be located.
var ErrNotFound = errors.New("vendored OpenSSL engine not found")

// Engine is a located engine binary.
type Engine struct {
	// Path is the absolute path to the engine executable.
	Path string
	// FromOverride reports whether the path came from EnvOverride rather than
	// from the release layout. Callers surface this so a user debugging a
	// version mismatch can see they are not running the shipped engine.
	FromOverride bool
}

// Locate resolves the engine for the currently running executable.
func Locate() (*Engine, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("determining executable path: %w", err)
	}
	return LocateForExecutable(exe, os.LookupEnv)
}

// LocateForExecutable resolves the engine for a given executable path.
//
// Putting the command on PATH with a symlink is the ordinary way to install a
// CLI, and it has to keep working. os.Executable resolves symlinks on Linux
// (/proc/self/exe) but not on macOS (_NSGetExecutablePath), so on macOS the
// engine would otherwise be looked for beside the *link* instead of beside the
// real binary, and every command would fail.
//
// The link's own directory is tried first, so a deliberately placed engine
// beside the link still wins and existing layouts are unaffected.
func LocateForExecutable(exe string, lookupEnv func(string) (string, bool)) (*Engine, error) {
	dirs := []string{filepath.Dir(exe)}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		if dir := filepath.Dir(resolved); dir != dirs[0] {
			dirs = append(dirs, dir)
		}
	}

	var firstErr error
	for _, dir := range dirs {
		eng, err := LocateIn(dir, lookupEnv)
		if err == nil {
			return eng, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// LocateIn is Locate against an explicit environment: binDir is the directory
// holding the pqc-fixtures executable and lookupEnv reads the environment.
// Exported so tests (and, later, packagers' harnesses) can exercise resolution
// without installing a real engine.
func LocateIn(binDir string, lookupEnv func(string) (string, bool)) (*Engine, error) {
	if override, ok := lookupEnv(EnvOverride); ok && override != "" {
		if err := executable(override); err != nil {
			return nil, fmt.Errorf("%s=%s: %w", EnvOverride, override, err)
		}
		abs, err := filepath.Abs(override)
		if err != nil {
			return nil, err
		}
		return &Engine{Path: abs, FromOverride: true}, nil
	}

	bundled := filepath.Join(binDir, dirName, binName)
	if err := executable(bundled); err != nil {
		// Say what is missing and how to fix it, without guessing how the user
		// got here. The old wording asserted they had copied the binary out of
		// the archive, which was wrong for anyone whose engine had simply not
		// been unpacked alongside it.
		return nil, fmt.Errorf("%w at %s: %v\n\n"+
			"pqc-fixtures ships the engine as an %s/ directory beside the binary, and "+
			"needs both. Unpack the whole release archive and keep it together — a "+
			"symlink to the binary from somewhere on your PATH is fine. Alternatively, "+
			"point %s at an OpenSSL %s build",
			ErrNotFound, bundled, err, dirName, EnvOverride, PinnedVersion)
	}
	abs, err := filepath.Abs(bundled)
	if err != nil {
		return nil, err
	}
	return &Engine{Path: abs}, nil
}

// executable checks that path is a regular file with an execute bit set.
func executable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("is a directory, not an executable")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("is not executable")
	}
	return nil
}

// Version runs `openssl version` and returns the bare version number — whatever
// the engine on disk reports, which is not necessarily PinnedVersion. Every
// Manifest records it so users can audit their exposure to engine CVEs
// (design-dossier §9).
func (e *Engine) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.Path, "version")
	// The engine must never pick up a system openssl.cnf: builds are pinned so
	// that generation is reproducible across machines.
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("running %s version: %w: %s", e.Path, err, strings.TrimSpace(stderr.String()))
	}
	return parseVersion(stdout.String())
}

// parseVersion extracts the version number from an `openssl version` line of
// the form "OpenSSL <version> <date>", optionally followed by a parenthesised
// "(Library: ...)" clause. The version is read from the line, never assumed, so
// this keeps working across pin bumps.
func parseVersion(out string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 || fields[0] != "OpenSSL" {
		return "", fmt.Errorf("unrecognized version output: %q", strings.TrimSpace(out))
	}
	return fields[1], nil
}
