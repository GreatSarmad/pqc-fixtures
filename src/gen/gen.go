// Package gen is the core (design-dossier §7): it resolves a generation
// request into a FixtureSpec, plans the work, drives an engine adapter through
// it, asserts the results against the AlgorithmProfile registry, and writes
// the Manifest. It contains no cryptography and no OpenSSL knowledge beyond
// the narrow Engine interface below.
package gen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GreatSarmad/pqc-fixtures/src/engine"
	"github.com/GreatSarmad/pqc-fixtures/src/manifest"
	"github.com/GreatSarmad/pqc-fixtures/src/profile"
)

// MaxValidityDays caps how long a fixture stays valid. Short-lived
// certificates are one of the three safety markers of design-dossier §9: a
// fixture that escapes into something real stops working within a month.
const MaxValidityDays = 30

// MaxChainDepth bounds --chain. Deeper chains are a size-stress feature, not
// an unbounded knob; the cap keeps a typo from generating for minutes.
const MaxChainDepth = 16

// DefaultSANs make the leaf usable as a local TLS server certificate
// (design-dossier §5).
var DefaultSANs = []string{"DNS:localhost", "IP:127.0.0.1"}

// Engine is the seam between the core and the cryptographic engine
// (design-dossier §7). One implementation exists: the vendored OpenSSL
// subprocess in src/engine.
//
// The request types are the engine package's own. That is a deliberate
// simplification for a single-implementation seam - notably CertRequest's
// Extensions are OpenSSL extension lines. If a second adapter ever arrives
// (ADR-002's liboqs escape hatch), extensions become a structured type; that
// is a contained change because nothing above this interface builds them.
type Engine interface {
	GenerateKey(ctx context.Context, req engine.KeyRequest) error
	IssueCert(ctx context.Context, req engine.CertRequest) error
	ConvertCert(ctx context.Context, pemPath, derPath string) error
	ConvertKey(ctx context.Context, pemPath, derPath string) error
	VerifyChain(ctx context.Context, rootPath string, untrusted []string, leafPath string) error
	Version(ctx context.Context) (string, error)
}

// Options is a generation request as the CLI receives it, before resolution.
type Options struct {
	Algorithm    string
	ChainDepth   int
	OutDir       string
	ValidityDays int
	Formats      string
	SeedHex      string
	SANs         []string
	Force        bool
}

// Spec is a fully resolved, validated generation request (the FixtureSpec of
// design-dossier §6).
type Spec struct {
	Profile      profile.Profile
	ChainDepth   int
	OutDir       string
	ValidityDays int
	Formats      []string
	Seed         []byte
	SANs         []string
	Force        bool
	// Warnings are non-fatal notes raised during resolution, surfaced to the
	// user before generation starts.
	Warnings []string
}

// Seeded reports whether this run produces byte-identical keys.
func (s *Spec) Seeded() bool { return len(s.Seed) > 0 && s.Profile.Seedable() }

// wants reports whether an encoding was requested.
func (s *Spec) wants(encoding string) bool {
	for _, f := range s.Formats {
		if f == encoding {
			return true
		}
	}
	return false
}

// Resolve validates an Options and fills in defaults.
func Resolve(opts Options) (*Spec, error) {
	prof, err := profile.Lookup(opts.Algorithm)
	if err != nil {
		return nil, err
	}
	if prof.Kind != profile.KindSignature {
		return nil, fmt.Errorf("%s is a key-encapsulation algorithm and cannot sign certificates; "+
			"gen currently issues certificate chains, so pass one of: %s",
			prof.ID, strings.Join(profile.SignatureIDs(), ", "))
	}

	if opts.ChainDepth < 1 || opts.ChainDepth > MaxChainDepth {
		return nil, fmt.Errorf("--chain must be between 1 and %d, got %d", MaxChainDepth, opts.ChainDepth)
	}
	if opts.ValidityDays < 1 || opts.ValidityDays > MaxValidityDays {
		return nil, fmt.Errorf("--days must be between 1 and %d (fixtures are deliberately short-lived), got %d",
			MaxValidityDays, opts.ValidityDays)
	}
	if strings.TrimSpace(opts.OutDir) == "" {
		return nil, fmt.Errorf("--out is required")
	}

	formats, err := resolveFormats(opts.Formats)
	if err != nil {
		return nil, err
	}

	spec := &Spec{
		Profile:      prof,
		ChainDepth:   opts.ChainDepth,
		OutDir:       opts.OutDir,
		ValidityDays: opts.ValidityDays,
		Formats:      formats,
		SANs:         opts.SANs,
		Force:        opts.Force,
	}
	if spec.SANs == nil {
		spec.SANs = DefaultSANs
	}

	if opts.SeedHex != "" {
		seed, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(opts.SeedHex), "0x"))
		if err != nil {
			return nil, fmt.Errorf("--seed must be hex digits: %w", err)
		}
		if len(seed) < 16 {
			return nil, fmt.Errorf("--seed must be at least 16 bytes (32 hex digits), got %d", len(seed))
		}
		spec.Seed = seed
		if !prof.Seedable() {
			spec.Warnings = append(spec.Warnings, fmt.Sprintf(
				"%s cannot be generated from a seed, so --seed is ignored for its keys and this run is "+
					"not reproducible (ADR-002); seeded generation covers ML-DSA and ML-KEM only",
				prof.EngineName))
		}
	}

	return spec, nil
}

// resolveFormats normalizes --formats into a deduplicated, ordered list.
func resolveFormats(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{manifest.EncodingPEM, manifest.EncodingDER}, nil
	}
	seen := map[string]bool{}
	for _, f := range strings.Split(raw, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		switch f {
		case manifest.EncodingPEM, manifest.EncodingDER:
			seen[f] = true
		case "":
			continue
		default:
			return nil, fmt.Errorf("unknown format %q; --formats accepts pem, der, or pem,der", f)
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("--formats must name at least one of pem, der")
	}
	var formats []string
	for _, f := range []string{manifest.EncodingPEM, manifest.EncodingDER} {
		if seen[f] {
			formats = append(formats, f)
		}
	}
	return formats, nil
}

// Result reports a completed run.
type Result struct {
	Manifest *manifest.Manifest
	OutDir   string
	Duration time.Duration
}

// Generate executes a resolved Spec.
//
// Everything is written to a temporary directory beside the destination and
// moved into place only once the chain verifies and every size assertion
// passes, so an interrupted or failed run never leaves a half-built fixture
// set behind (design-dossier §9).
func Generate(ctx context.Context, spec *Spec, eng Engine, progress io.Writer) (*Result, error) {
	start := time.Now()

	outDir, err := filepath.Abs(spec.OutDir)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(outDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", parent, err)
	}
	if err := checkDestination(outDir, spec.Force); err != nil {
		return nil, err
	}

	engineVersion, err := eng.Version(ctx)
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp(parent, ".pqc-fixtures-tmp-")
	if err != nil {
		return nil, fmt.Errorf("creating staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmpDir)
		}
	}()

	plan := Plan(spec)
	logf(progress, "generating %d-certificate %s chain with OpenSSL %s\n",
		len(plan), spec.Profile.EngineName, engineVersion)

	facts := make([]certFacts, len(plan))
	for i, r := range plan {
		keyPEM := filepath.Join(tmpDir, r.KeyFile(manifest.EncodingPEM))
		certPEM := filepath.Join(tmpDir, r.CertFile(manifest.EncodingPEM))
		certDER := filepath.Join(tmpDir, r.CertFile(manifest.EncodingDER))

		seedHex := ""
		if spec.Seeded() {
			seedHex = deriveSeed(spec.Seed, r.Role, spec.Profile.SeedBytes)
		}
		if err := eng.GenerateKey(ctx, engine.KeyRequest{
			Algorithm: spec.Profile.EngineName,
			OutPath:   keyPEM,
			SeedHex:   seedHex,
		}); err != nil {
			return nil, err
		}

		serial, err := serialFor(spec, r.Role)
		if err != nil {
			return nil, err
		}
		req := engine.CertRequest{
			KeyPath:    keyPEM,
			Subject:    r.Subject,
			Days:       spec.ValidityDays,
			SerialHex:  serial,
			Extensions: r.Extensions,
			OutPath:    certPEM,
		}
		if r.IssuerRole != "" {
			issuer := plan[i-1]
			req.CACertPath = filepath.Join(tmpDir, issuer.CertFile(manifest.EncodingPEM))
			req.CAKeyPath = filepath.Join(tmpDir, issuer.KeyFile(manifest.EncodingPEM))
		}
		if err := eng.IssueCert(ctx, req); err != nil {
			return nil, err
		}

		// DER is produced unconditionally: the size assertions below read the
		// certificate back from it. It is removed again if the user did not
		// ask for DER output.
		if err := eng.ConvertCert(ctx, certPEM, certDER); err != nil {
			return nil, err
		}
		f, err := inspectCert(certDER)
		if err != nil {
			return nil, err
		}
		if err := assertSizes(spec.Profile, r.Role, f, engineVersion); err != nil {
			return nil, err
		}
		facts[i] = f

		if spec.wants(manifest.EncodingDER) {
			if err := eng.ConvertKey(ctx, keyPEM, filepath.Join(tmpDir, r.KeyFile(manifest.EncodingDER))); err != nil {
				return nil, err
			}
		}

		logf(progress, "  [%d/%d] %-16s signature %s B, public key %s B\n",
			i+1, len(plan), r.Role, thousands(f.signatureBytes), thousands(f.publicKeyBytes))
	}

	if err := writeChain(tmpDir, plan); err != nil {
		return nil, err
	}

	// design-dossier §8 criterion 2: the chain must verify against its own
	// root, using the same engine that produced it.
	rootPEM := filepath.Join(tmpDir, plan[0].CertFile(manifest.EncodingPEM))
	leafPEM := filepath.Join(tmpDir, plan[len(plan)-1].CertFile(manifest.EncodingPEM))
	untrusted := intermediatePaths(tmpDir, plan)
	if err := eng.VerifyChain(ctx, rootPEM, untrusted, leafPEM); err != nil {
		return nil, fmt.Errorf("generated chain failed verification: %w", err)
	}
	logf(progress, "  chain verifies against its own root\n")

	if err := os.WriteFile(filepath.Join(tmpDir, NoticeFile), []byte(noticeText(spec)), 0o644); err != nil {
		return nil, fmt.Errorf("writing notice: %w", err)
	}

	if !spec.wants(manifest.EncodingPEM) {
		if err := dropPEMs(tmpDir, plan); err != nil {
			return nil, err
		}
	}
	if !spec.wants(manifest.EncodingDER) {
		if err := dropDERs(tmpDir, plan); err != nil {
			return nil, err
		}
	}

	man, err := buildManifest(spec, plan, facts, engineVersion, tmpDir)
	if err != nil {
		return nil, err
	}
	if err := man.WriteFile(filepath.Join(tmpDir, manifest.FileName)); err != nil {
		return nil, err
	}

	if err := commit(tmpDir, outDir, spec.Force); err != nil {
		return nil, err
	}
	committed = true

	logf(progress, "wrote %d files to %s\n", len(man.Artifacts)+1, outDir)
	return &Result{Manifest: man, OutDir: outDir, Duration: time.Since(start)}, nil
}

// assertSizes enforces design-dossier §8 criterion 3. A mismatch means the
// engine is not the one we think it is, so the message names the version.
func assertSizes(prof profile.Profile, roleName string, f certFacts, engineVersion string) error {
	if f.signatureBytes != prof.SignatureBytes {
		return fmt.Errorf("%s certificate: signature is %d bytes, but %s specifies %d "+
			"(engine OpenSSL %s) - refusing to emit a fixture with the wrong size envelope",
			roleName, f.signatureBytes, prof.EngineName, prof.SignatureBytes, engineVersion)
	}
	if f.publicKeyBytes != prof.PublicKeyBytes {
		return fmt.Errorf("%s certificate: public key is %d bytes, but %s specifies %d "+
			"(engine OpenSSL %s)",
			roleName, f.publicKeyBytes, prof.EngineName, prof.PublicKeyBytes, engineVersion)
	}
	return nil
}

// intermediatePaths lists the CA certificates between root and leaf, which
// `openssl verify` needs as untrusted input.
func intermediatePaths(dir string, plan []PlannedCertificate) []string {
	if len(plan) < 3 {
		return nil
	}
	var paths []string
	for _, r := range plan[1 : len(plan)-1] {
		paths = append(paths, filepath.Join(dir, r.CertFile(manifest.EncodingPEM)))
	}
	return paths
}

// writeChain concatenates the certificates leaf-first into ChainFile.
func writeChain(dir string, plan []PlannedCertificate) error {
	var buf strings.Builder
	for i := len(plan) - 1; i >= 0; i-- {
		pem, err := os.ReadFile(filepath.Join(dir, plan[i].CertFile(manifest.EncodingPEM)))
		if err != nil {
			return err
		}
		buf.Write(pem)
	}
	return os.WriteFile(filepath.Join(dir, ChainFile), []byte(buf.String()), 0o644)
}

// dropPEMs and dropDERs remove the encodings the user did not ask for. The
// concatenated chain is always PEM: DER has no representation for a sequence
// of certificates.
func dropPEMs(dir string, plan []PlannedCertificate) error {
	for _, r := range plan {
		for _, name := range []string{r.KeyFile(manifest.EncodingPEM), r.CertFile(manifest.EncodingPEM)} {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func dropDERs(dir string, plan []PlannedCertificate) error {
	for _, r := range plan {
		if err := os.Remove(filepath.Join(dir, r.CertFile(manifest.EncodingDER))); err != nil {
			return err
		}
	}
	return nil
}

// serialFor produces a positive 16-byte serial: derived from the seed when the
// run is seeded, so chain structure is reproducible, and random otherwise.
func serialFor(spec *Spec, roleName string) (string, error) {
	var raw []byte
	if spec.Seeded() {
		derived, err := hex.DecodeString(deriveSeed(spec.Seed, "serial/"+roleName, 16))
		if err != nil {
			return "", err
		}
		raw = derived
	} else {
		raw = make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("generating serial number: %w", err)
		}
	}
	// Clear the top nibble so the DER integer is unambiguously positive and
	// stays within the 20-byte serial limit of RFC 5280.
	raw[0] &= 0x0f
	if raw[0] == 0 {
		raw[0] = 1
	}
	return hex.EncodeToString(raw), nil
}

// checkDestination fails before any work happens if the output directory is
// not safe to write.
func checkDestination(outDir string, force bool) error {
	entries, err := os.ReadDir(outDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if !force {
		return fmt.Errorf("%s is not empty; pass --force to replace a previous fixture set", outDir)
	}
	// --force replaces a previous run, never arbitrary user data.
	if _, err := os.Stat(filepath.Join(outDir, manifest.FileName)); err != nil {
		return fmt.Errorf("%s is not empty and does not contain %s, so it was not produced by pqc-fixtures; "+
			"refusing to replace it even with --force", outDir, manifest.FileName)
	}
	man, err := manifest.Load(filepath.Join(outDir, manifest.FileName))
	if err != nil || man.Tool.Name != "pqc-fixtures" {
		return fmt.Errorf("%s contains a %s that pqc-fixtures did not write; refusing to replace it",
			outDir, manifest.FileName)
	}
	return nil
}

// commit moves the staging directory into place.
func commit(tmpDir, outDir string, force bool) error {
	// MkdirTemp creates 0700; the fixture directory itself is not secret.
	if err := os.Chmod(tmpDir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(outDir); err == nil {
		if err := checkDestination(outDir, force); err != nil {
			return err
		}
		retired := outDir + ".replaced-" + fmt.Sprint(time.Now().UTC().UnixNano())
		if err := os.Rename(outDir, retired); err != nil {
			return fmt.Errorf("replacing %s: %w", outDir, err)
		}
		if err := os.Rename(tmpDir, outDir); err != nil {
			// Put the previous fixture set back rather than leaving nothing.
			os.Rename(retired, outDir)
			return fmt.Errorf("moving fixtures into %s: %w", outDir, err)
		}
		return os.RemoveAll(retired)
	}
	if err := os.Rename(tmpDir, outDir); err != nil {
		return fmt.Errorf("moving fixtures into %s: %w", outDir, err)
	}
	return nil
}

// buildManifest records every file that survived into the output directory.
func buildManifest(spec *Spec, plan []PlannedCertificate, facts []certFacts, engineVersion, dir string) (*manifest.Manifest, error) {
	man := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Warning:       manifest.Warning,
		Tool:          manifest.Tool{Name: "pqc-fixtures", Version: ToolVersion},
		Engine: manifest.Engine{
			Name:          "openssl",
			Version:       engineVersion,
			PinnedVersion: engine.PinnedVersion,
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Spec: manifest.Spec{
			Algorithm:       spec.Profile.ID,
			ChainDepth:      spec.ChainDepth,
			ValidityDays:    spec.ValidityDays,
			Formats:         spec.Formats,
			Seeded:          spec.Seeded(),
			SubjectAltNames: spec.SANs,
			SizeEnvelope: manifest.Envelope{
				PublicKeyBytes: spec.Profile.PublicKeyBytes,
				SignatureBytes: spec.Profile.SignatureBytes,
			},
		},
	}

	add := func(name, kind, encoding, roleName string, key *manifest.KeyDetail, cert *manifest.CertDetail) error {
		size, sum, err := fileFacts(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		man.Artifacts = append(man.Artifacts, manifest.Artifact{
			Path: name, Kind: kind, Encoding: encoding, Role: roleName,
			Bytes: size, SHA256: sum, Key: key, Certificate: cert,
		})
		return nil
	}

	for i, r := range plan {
		f := facts[i]
		key := &manifest.KeyDetail{Algorithm: spec.Profile.ID, Seeded: spec.Seeded()}
		cert := &manifest.CertDetail{
			Algorithm:      spec.Profile.ID,
			Subject:        f.subject,
			Issuer:         f.issuer,
			SerialNumber:   f.serialNumber,
			NotBefore:      f.notBefore.Format(time.RFC3339),
			NotAfter:       f.notAfter.Format(time.RFC3339),
			IsCA:           f.isCA,
			SignatureBytes: f.signatureBytes,
			PublicKeyBytes: f.publicKeyBytes,
		}
		for _, enc := range spec.Formats {
			if err := add(r.KeyFile(enc), manifest.KindPrivateKey, enc, r.Role, key, nil); err != nil {
				return nil, err
			}
			if err := add(r.CertFile(enc), manifest.KindCertificate, enc, r.Role, nil, cert); err != nil {
				return nil, err
			}
		}
	}
	if err := add(ChainFile, manifest.KindChain, manifest.EncodingPEM, "chain", nil, nil); err != nil {
		return nil, err
	}
	if err := add(NoticeFile, manifest.KindNotice, manifest.EncodingText, "chain", nil, nil); err != nil {
		return nil, err
	}

	sort.SliceStable(man.Artifacts, func(i, j int) bool {
		return man.Artifacts[i].Path < man.Artifacts[j].Path
	})
	return man, nil
}

// ToolVersion is stamped into every manifest. The CLI sets it at startup so
// this package does not depend on the CLI.
var ToolVersion = "dev"

// noticeText is the warning left beside the fixtures for whoever finds the
// directory without reading the manifest.
func noticeText(spec *Spec) string {
	var b strings.Builder
	b.WriteString("INSECURE TEST FIXTURES - DO NOT USE FOR ANYTHING REAL\n")
	b.WriteString("=====================================================\n\n")
	b.WriteString("Generated by pqc-fixtures (" + ToolVersion + ") to test whether software\n")
	b.WriteString("survives post-quantum artifact sizes.\n\n")
	b.WriteString("- Every private key here is unencrypted and publicly reproducible.\n")
	b.WriteString(fmt.Sprintf("- Every certificate expires within %d days and carries a\n", spec.ValidityDays))
	b.WriteString("  \"" + DNMarker + "\" distinguished name.\n")
	b.WriteString("- Nothing here chains to any real trust store; the root is generated\n")
	b.WriteString("  locally and trusted by nothing.\n\n")
	b.WriteString("Algorithm: " + spec.Profile.EngineName + "\n")
	b.WriteString(fmt.Sprintf("Chain depth: %d\n", spec.ChainDepth))
	b.WriteString("Machine-readable details: " + manifest.FileName + "\n")
	return b.String()
}

// logf writes progress output, tolerating a nil writer for quiet runs.
func logf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...)
}

// thousands formats a byte count with separators, because the whole point of
// this tool is that the numbers are big.
func thousands(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, digit := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, digit)
	}
	return string(out)
}
