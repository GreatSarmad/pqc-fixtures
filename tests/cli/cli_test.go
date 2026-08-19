package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/cli"
	"github.com/GreatSarmad/pqc-fixtures/src/engine"
	"github.com/GreatSarmad/pqc-fixtures/src/gen"
	"github.com/GreatSarmad/pqc-fixtures/src/manifest"
	"github.com/GreatSarmad/pqc-fixtures/src/preset"
	"github.com/GreatSarmad/pqc-fixtures/tests/internal/testengine"
)

// run executes the CLI and returns its exit code with both output streams.
func run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestExecuteVersion(t *testing.T) {
	for _, flag := range []string{"-v", "--version"} {
		code, stdout, _ := run(flag)
		if code != 0 {
			t.Errorf("%s: exit code = %d, want 0", flag, code)
		}
		if got := strings.TrimSpace(stdout); got != cli.Version {
			t.Errorf("%s: output = %q, want %q", flag, got, cli.Version)
		}
	}
}

func TestExecuteHelp(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {}} {
		code, stdout, _ := run(args...)
		if code != 0 {
			t.Errorf("%v: exit code = %d, want 0", args, code)
		}
		for _, want := range []string{"pqc-fixtures", "gen", "schema", "engine"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%v: help does not mention %q", args, want)
			}
		}
	}
}

// TestHelpWarnsAboutTheArtifacts: the top-level help is where a first-time
// user finds out these fixtures are not safe to use.
func TestHelpWarnsAboutTheArtifacts(t *testing.T) {
	_, stdout, _ := run("--help")
	if !strings.Contains(stdout, "insecure") {
		t.Errorf("help text does not warn that the fixtures are insecure:\n%s", stdout)
	}
}

func TestSchemaCommandPrintsTheContract(t *testing.T) {
	code, stdout, stderr := run("schema")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(stdout), &schema); err != nil {
		t.Fatalf("schema output is not valid JSON: %v", err)
	}
	if schema["title"] != "pqc-fixtures Manifest" {
		t.Errorf("unexpected schema printed: title = %v", schema["title"])
	}
}

func TestGenHelp(t *testing.T) {
	code, _, stderr := run("gen", "--help")
	// flag.ContinueOnError reports -h as an error, which is the conventional
	// "usage requested" path; what matters is that the flags are documented.
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	for _, want := range []string{"--out", "-algo", "-chain", "-seed"} {
		if !strings.Contains(stderr, strings.TrimPrefix(want, "-")) {
			t.Errorf("gen usage does not document %q:\n%s", want, stderr)
		}
	}
}

func TestGenRejectsBadFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"missing out":       {"gen"},
		"unknown algorithm": {"gen", "--out", "x", "--algo", "rsa-4096"},
		"validity too long": {"gen", "--out", "x", "--days", "365"},
		"unknown flag":      {"gen", "--out", "x", "--nope"},
		"stray argument":    {"gen", "--out", "x", "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := run(args...)
			if code != 2 {
				t.Errorf("exit code = %d, want 2 (stderr: %s)", code, stderr)
			}
			if stderr == "" {
				t.Error("nothing was written to stderr")
			}
		})
	}
}

// TestGenWithoutAnEngineFails: a user who copied the binary out of the release
// archive gets an actionable message and a non-zero exit, not a stack trace.
func TestGenWithoutAnEngineFails(t *testing.T) {
	t.Setenv(engine.EnvOverride, "")
	outDir := filepath.Join(t.TempDir(), "testdata")

	code, _, stderr := run("gen", "--out", outDir)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "engine not found") {
		t.Errorf("stderr %q does not explain that the engine is missing", stderr)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Error("output directory was created despite the failure")
	}
}

// TestGenEndToEnd drives the whole slice through the CLI, the way a user does.
func TestGenEndToEnd(t *testing.T) {
	eng := testengine.Locate(t)
	t.Setenv(engine.EnvOverride, eng.Path)

	outDir := filepath.Join(t.TempDir(), "testdata")
	code, stdout, stderr := run("gen", "--out", outDir, "--chain", "3")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"ML-DSA-65", "3,309", "verifies"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("progress output does not mention %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stdout, "insecure test fixtures") {
		t.Errorf("the run did not warn the user about what it produced:\n%s", stdout)
	}

	man, err := manifest.Load(filepath.Join(outDir, manifest.FileName))
	if err != nil {
		t.Fatalf("loading manifest: %v", err)
	}
	if man.Spec.ChainDepth != 3 || man.Spec.Algorithm != "ml-dsa-65" {
		t.Errorf("manifest spec = %+v", man.Spec)
	}
	if man.Tool.Version != cli.Version {
		t.Errorf("manifest records tool version %q, want %q", man.Tool.Version, cli.Version)
	}
}

func TestGenQuietPrintsNothing(t *testing.T) {
	eng := testengine.Locate(t)
	t.Setenv(engine.EnvOverride, eng.Path)

	outDir := filepath.Join(t.TempDir(), "testdata")
	code, stdout, stderr := run("gen", "--out", outDir, "--chain", "2", "--quiet")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("--quiet still wrote to stdout:\n%s", stdout)
	}
}

// TestGenWarnsOnUnseedableAlgorithm: the ADR-002 caveat has to reach the user,
// on stderr, before they rely on reproducibility.
func TestGenWarnsOnUnseedableAlgorithm(t *testing.T) {
	eng := testengine.Locate(t)
	t.Setenv(engine.EnvOverride, eng.Path)

	outDir := filepath.Join(t.TempDir(), "testdata")
	code, _, stderr := run("gen", "--out", outDir, "--chain", "2",
		"--algo", "slh-dsa-sha2-256f", "--seed", "00112233445566778899aabbccddeeff", "--quiet")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "warning:") || !strings.Contains(stderr, "not reproducible") {
		t.Errorf("stderr does not warn that SLH-DSA ignores --seed:\n%s", stderr)
	}
}

func TestExecuteEngineReportsLocatedEngine(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "openssl")
	script := "#!/bin/sh\necho 'OpenSSL " + engine.PinnedVersion + " 9 Jun 2026'\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("writing stub engine: %v", err)
	}
	t.Setenv(engine.EnvOverride, stub)

	code, stdout, stderr := run("engine")
	if code != 0 {
		t.Fatalf("exit code = %d (stdout: %q)", code, stdout)
	}
	for _, want := range []string{stub, engine.PinnedVersion, engine.EnvOverride} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output %q does not mention %q", stdout, want)
		}
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("unexpected version-mismatch warning for the pinned version: %q", stderr)
	}
}

func TestExecuteEngineWarnsOnVersionMismatch(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "openssl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'OpenSSL 3.0.21 9 Jun 2026'\n"), 0o755); err != nil {
		t.Fatalf("writing stub engine: %v", err)
	}
	t.Setenv(engine.EnvOverride, stub)

	code, _, stderr := run("engine")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stderr, "warning:") {
		t.Errorf("stderr %q lacks a warning about the unpinned engine version", stderr)
	}
}

func TestExecuteEngineFailsWithoutEngine(t *testing.T) {
	// No override and no engine/ directory beside the test binary.
	t.Setenv(engine.EnvOverride, "")

	code, _, stderr := run("engine")
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stderr, "engine not found") {
		t.Errorf("stderr %q does not explain that the engine is missing", stderr)
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	code, _, stderr := run("bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "bogus") {
		t.Errorf("stderr %q does not echo the unknown command", stderr)
	}
}

// TestExecuteSetsTheManifestToolVersion: the manifest records which build
// produced a fixture set, so the CLI has to hand its version to the core.
func TestExecuteSetsTheManifestToolVersion(t *testing.T) {
	run("--version")
	if gen.ToolVersion != cli.Version {
		t.Errorf("gen.ToolVersion = %q, want %q", gen.ToolVersion, cli.Version)
	}
}

func TestPresetsCommandListsEveryPreset(t *testing.T) {
	code, stdout, stderr := run("presets")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, p := range preset.All() {
		if !strings.Contains(stdout, p.Name) || !strings.Contains(stdout, p.Summary) {
			t.Errorf("preset listing omits %s:\n%s", p.Name, stdout)
		}
	}
	// The listing exists to make the sizes obvious without generating anything.
	if !strings.Contains(stdout, "49,856") {
		t.Errorf("preset listing does not show the SLH-DSA signature size:\n%s", stdout)
	}
}

func TestPresetsCommandDescribesOnePreset(t *testing.T) {
	p, err := preset.Lookup("worst-case-tls")
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("presets", "worst-case-tls")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{p.Description, p.Breaks[0], "gen --preset worst-case-tls"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("description omits %q:\n%s", want, stdout)
		}
	}
}

func TestPresetsCommandRejectsUnknownNames(t *testing.T) {
	code, _, stderr := run("presets", "no-such-preset")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "jumbo") {
		t.Errorf("stderr does not list the presets that do exist:\n%s", stderr)
	}
}

// TestGenPresetProducesWhatThePresetPromises is the ROADMAP F2 acceptance
// check: naming a preset generates its chain, and the manifest carries both
// the attribution and the registry-derived floor the output must clear.
func TestGenPresetProducesWhatThePresetPromises(t *testing.T) {
	eng := testengine.Locate(t)
	t.Setenv(engine.EnvOverride, eng.Path)

	for _, name := range []string{"jumbo", "deep-chain", "worst-case-tls"} {
		t.Run(name, func(t *testing.T) {
			p, err := preset.Lookup(name)
			if err != nil {
				t.Fatal(err)
			}
			outDir := filepath.Join(t.TempDir(), "testdata")
			code, _, stderr := run("gen", "--preset", name, "--out", outDir, "--quiet")
			if code != 0 {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
			}
			if strings.Contains(stderr, "warning:") {
				t.Errorf("a shipped preset warned on a plain run:\n%s", stderr)
			}

			man, err := manifest.Load(filepath.Join(outDir, manifest.FileName))
			if err != nil {
				t.Fatalf("loading manifest: %v", err)
			}
			if man.Spec.Preset == nil {
				t.Fatal("manifest does not record which preset produced it")
			}
			if man.Spec.Preset.Name != p.Name || man.Spec.Preset.Version != p.Version {
				t.Errorf("manifest records preset %+v, want %s v%d", man.Spec.Preset, p.Name, p.Version)
			}
			if man.Spec.Preset.Modified {
				t.Error("an unmodified preset run is recorded as modified")
			}
			if man.Spec.Algorithm != p.Spec.Algorithm || man.Spec.ChainDepth != p.Spec.ChainDepth {
				t.Errorf("manifest spec = %+v, want the preset's algorithm and depth", man.Spec)
			}
			if man.Spec.SizeEnvelope.MinChainBytes != p.MinChainBytes() {
				t.Errorf("manifest floor = %d, want %d", man.Spec.SizeEnvelope.MinChainBytes, p.MinChainBytes())
			}

			// The promise is about bytes, so measure the bytes.
			total := 0
			for _, a := range man.Artifacts {
				if a.Kind == manifest.KindCertificate && a.Encoding == manifest.EncodingDER {
					total += a.Bytes
				}
			}
			if total < p.MinChainBytes() {
				t.Errorf("%s produced %d bytes of DER certificates, below its %d-byte floor",
					name, total, p.MinChainBytes())
			}
		})
	}
}

// TestGenPresetFlagsOverrideAndAreRecorded: a preset is a default, not a
// prison - but a run that departs from it must say so on stderr and in the
// manifest, or an old fixture set stops being interpretable.
func TestGenPresetFlagsOverrideAndAreRecorded(t *testing.T) {
	eng := testengine.Locate(t)
	t.Setenv(engine.EnvOverride, eng.Path)

	outDir := filepath.Join(t.TempDir(), "testdata")
	code, _, stderr := run("gen", "--preset", "deep-chain", "--chain", "2", "--out", outDir, "--quiet")
	if code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "warning:") || !strings.Contains(stderr, "--chain") {
		t.Errorf("stderr does not report that --chain overrode the preset:\n%s", stderr)
	}

	man, err := manifest.Load(filepath.Join(outDir, manifest.FileName))
	if err != nil {
		t.Fatalf("loading manifest: %v", err)
	}
	if man.Spec.ChainDepth != 2 {
		t.Errorf("chainDepth = %d, want the flag's 2", man.Spec.ChainDepth)
	}
	if man.Spec.Preset == nil || !man.Spec.Preset.Modified {
		t.Errorf("manifest preset = %+v, want deep-chain recorded as modified", man.Spec.Preset)
	}
	if man.Spec.Algorithm != "ml-dsa-87" {
		t.Errorf("algorithm = %q, want the preset's ml-dsa-87 to survive", man.Spec.Algorithm)
	}
}

func TestGenRejectsUnknownPreset(t *testing.T) {
	code, _, stderr := run("gen", "--preset", "no-such-preset", "--out", t.TempDir())
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown preset") {
		t.Errorf("stderr does not name the problem:\n%s", stderr)
	}
}
