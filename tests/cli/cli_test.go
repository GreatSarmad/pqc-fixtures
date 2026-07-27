package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/cli"
	"github.com/GreatSarmad/pqc-fixtures/src/engine"
)

func TestExecuteVersion(t *testing.T) {
	for _, flag := range []string{"-v", "--version"} {
		var out bytes.Buffer
		code := cli.Execute([]string{flag}, &out)
		if code != 0 {
			t.Errorf("%s: exit code = %d, want 0", flag, code)
		}
		if got := strings.TrimSpace(out.String()); got != cli.Version {
			t.Errorf("%s: output = %q, want %q", flag, got, cli.Version)
		}
	}
}

func TestExecuteHelp(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {}} {
		var out bytes.Buffer
		code := cli.Execute(args, &out)
		if code != 0 {
			t.Errorf("%v: exit code = %d, want 0", args, code)
		}
		if !strings.Contains(out.String(), "pqc-fixtures") {
			t.Errorf("%v: output %q does not mention pqc-fixtures", args, out.String())
		}
	}
}

func TestExecuteEngineReportsLocatedEngine(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "openssl")
	script := "#!/bin/sh\necho 'OpenSSL " + engine.PinnedVersion + " 9 Jun 2026'\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("writing stub engine: %v", err)
	}
	t.Setenv(engine.EnvOverride, stub)

	var out bytes.Buffer
	if code := cli.Execute([]string{"engine"}, &out); code != 0 {
		t.Fatalf("exit code = %d, want 0 (output: %q)", code, out.String())
	}
	for _, want := range []string{stub, engine.PinnedVersion, engine.EnvOverride} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q does not mention %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "warning:") {
		t.Errorf("unexpected version-mismatch warning for the pinned version: %q", out.String())
	}
}

func TestExecuteEngineWarnsOnVersionMismatch(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "openssl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'OpenSSL 3.0.21 9 Jun 2026'\n"), 0o755); err != nil {
		t.Fatalf("writing stub engine: %v", err)
	}
	t.Setenv(engine.EnvOverride, stub)

	var out bytes.Buffer
	if code := cli.Execute([]string{"engine"}, &out); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "warning:") {
		t.Errorf("output %q lacks a warning about the unpinned engine version", out.String())
	}
}

func TestExecuteEngineFailsWithoutEngine(t *testing.T) {
	// No override and no engine/ directory beside the test binary.
	t.Setenv(engine.EnvOverride, "")

	var out bytes.Buffer
	if code := cli.Execute([]string{"engine"}, &out); code != 1 {
		t.Errorf("exit code = %d, want 1 (output: %q)", code, out.String())
	}
	if !strings.Contains(out.String(), "engine not found") {
		t.Errorf("output %q does not explain that the engine is missing", out.String())
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	code := cli.Execute([]string{"bogus"}, &out)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out.String(), "bogus") {
		t.Errorf("output %q does not echo the unknown command", out.String())
	}
}
