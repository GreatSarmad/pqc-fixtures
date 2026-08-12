package gen_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GreatSarmad/pqc-fixtures/src/gen"
	"github.com/GreatSarmad/pqc-fixtures/src/manifest"
	"github.com/GreatSarmad/pqc-fixtures/src/profile"
	"github.com/GreatSarmad/pqc-fixtures/tests/internal/schemacheck"
	"github.com/GreatSarmad/pqc-fixtures/tests/internal/testengine"
)

// These tests are the executable form of design-dossier §8 criteria 1-6. They
// need a real engine and skip without one; the Engine workflow runs them on
// macOS arm64 and Linux x86_64/arm64 against the pinned build (criterion 9).

// runGen generates into a fresh directory and returns it with its manifest.
func runGen(t *testing.T, mutate func(*gen.Options)) (string, *manifest.Manifest) {
	t.Helper()
	eng := testengine.Locate(t)

	outDir := filepath.Join(t.TempDir(), "testdata")
	spec := resolveInto(t, outDir, mutate)

	result, err := gen.Generate(context.Background(), spec, eng, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return result.OutDir, result.Manifest
}

// parseCert reads a generated certificate, from either encoding.
func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if strings.HasSuffix(path, ".pem") {
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("%s is not PEM", path)
		}
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return cert
}

// TestGeneratedChainVerifies is criterion 2: the chain verifies against its
// own root, checked with the same pinned engine that produced it.
func TestGeneratedChainVerifies(t *testing.T) {
	eng := testengine.Locate(t)
	dir, _ := runGen(t, func(o *gen.Options) { o.ChainDepth = 4 })

	root := filepath.Join(dir, "INSECURE-TEST-root.cert.pem")
	leaf := filepath.Join(dir, "INSECURE-TEST-leaf.cert.pem")
	untrusted := []string{
		filepath.Join(dir, "INSECURE-TEST-intermediate-1.cert.pem"),
		filepath.Join(dir, "INSECURE-TEST-intermediate-2.cert.pem"),
	}
	if err := eng.VerifyChain(context.Background(), root, untrusted, leaf); err != nil {
		t.Fatalf("openssl verify rejected the generated chain: %v", err)
	}

	// The chain must actually be a chain: each certificate's issuer is the
	// subject of the one above it, and only the root is self-issued.
	names := []string{"root", "intermediate-1", "intermediate-2", "leaf"}
	var certs []*x509.Certificate
	for _, name := range names {
		certs = append(certs, parseCert(t, filepath.Join(dir, "INSECURE-TEST-"+name+".cert.pem")))
	}
	if certs[0].Subject.String() != certs[0].Issuer.String() {
		t.Error("root is not self-issued")
	}
	for i := 1; i < len(certs); i++ {
		if certs[i].Issuer.String() != certs[i-1].Subject.String() {
			t.Errorf("%s is issued by %q, want %q", names[i], certs[i].Issuer, certs[i-1].Subject)
		}
	}
	if !certs[2].IsCA || certs[3].IsCA {
		t.Errorf("basic constraints are wrong: intermediate-2 IsCA=%v, leaf IsCA=%v", certs[2].IsCA, certs[3].IsCA)
	}
}

// TestFullChainFileHoldsEveryCertificate: the concatenated file is what users
// hand to a TLS server, so it must be complete and leaf-first.
func TestFullChainFileHoldsEveryCertificate(t *testing.T) {
	dir, _ := runGen(t, func(o *gen.Options) { o.ChainDepth = 3 })

	raw, err := os.ReadFile(filepath.Join(dir, gen.ChainFile))
	if err != nil {
		t.Fatalf("reading chain: %v", err)
	}
	var subjects []string
	for rest := raw; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing a certificate from the chain: %v", err)
		}
		subjects = append(subjects, cert.Subject.CommonName)
	}
	if len(subjects) != 3 {
		t.Fatalf("chain holds %d certificates, want 3: %v", len(subjects), subjects)
	}
	if !strings.Contains(subjects[0], "Leaf") || !strings.Contains(subjects[2], "Root") {
		t.Errorf("chain is not leaf-first: %v", subjects)
	}
}

// TestSizeFidelity is criterion 3: generated artifacts match the
// AlgorithmProfile envelope exactly, for every ML-DSA parameter set.
func TestSizeFidelity(t *testing.T) {
	for _, algo := range []string{"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"} {
		t.Run(algo, func(t *testing.T) {
			prof, err := profile.Lookup(algo)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			dir, man := runGen(t, func(o *gen.Options) {
				o.Algorithm = algo
				o.ChainDepth = 2
			})

			for _, role := range []string{"root", "leaf"} {
				cert := parseCert(t, filepath.Join(dir, "INSECURE-TEST-"+role+".cert.pem"))
				if len(cert.Signature) != prof.SignatureBytes {
					t.Errorf("%s signature = %d bytes, want %d (FIPS 204)",
						role, len(cert.Signature), prof.SignatureBytes)
				}
			}

			if man.Spec.SizeEnvelope.SignatureBytes != prof.SignatureBytes ||
				man.Spec.SizeEnvelope.PublicKeyBytes != prof.PublicKeyBytes {
				t.Errorf("manifest envelope = %+v, want signature %d / public key %d",
					man.Spec.SizeEnvelope, prof.SignatureBytes, prof.PublicKeyBytes)
			}
			for _, artifact := range man.Artifacts {
				if artifact.Certificate == nil {
					continue
				}
				if artifact.Certificate.SignatureBytes != prof.SignatureBytes {
					t.Errorf("%s records signature %d, want %d",
						artifact.Path, artifact.Certificate.SignatureBytes, prof.SignatureBytes)
				}
				if artifact.Certificate.PublicKeyBytes != prof.PublicKeyBytes {
					t.Errorf("%s records public key %d, want %d",
						artifact.Path, artifact.Certificate.PublicKeyBytes, prof.PublicKeyBytes)
				}
			}
		})
	}
}

// TestSLHDSAReachesTheJumboSize checks the parameter set behind the `jumbo`
// preset: a 49,856-byte signature is the number the demo is built on.
func TestSLHDSAReachesTheJumboSize(t *testing.T) {
	dir, _ := runGen(t, func(o *gen.Options) {
		o.Algorithm = "slh-dsa-sha2-256f"
		o.ChainDepth = 2
	})
	cert := parseCert(t, filepath.Join(dir, "INSECURE-TEST-leaf.cert.pem"))
	if len(cert.Signature) != 49856 {
		t.Errorf("SLH-DSA-SHA2-256f signature = %d bytes, want 49856 (FIPS 205)", len(cert.Signature))
	}

	info, err := os.Stat(filepath.Join(dir, gen.ChainFile))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() < 45*1024 {
		t.Errorf("chain is %d bytes; the jumbo preset targets at least 45 KB", info.Size())
	}
}

// TestManifestDescribesEveryFile is criterion 4: the manifest validates
// against the published schema, every hash matches the file on disk, and
// nothing on disk is undeclared.
func TestManifestDescribesEveryFile(t *testing.T) {
	dir, man := runGen(t, nil)

	encoded, err := os.ReadFile(filepath.Join(dir, manifest.FileName))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	if err := schemacheck.Validate(manifest.Schema(), encoded); err != nil {
		t.Fatal(err)
	}

	declared := map[string]bool{manifest.FileName: true}
	for _, artifact := range man.Artifacts {
		declared[artifact.Path] = true

		content, err := os.ReadFile(filepath.Join(dir, artifact.Path))
		if err != nil {
			t.Errorf("manifest lists %s, which is not on disk: %v", artifact.Path, err)
			continue
		}
		if len(content) != artifact.Bytes {
			t.Errorf("%s: manifest says %d bytes, file is %d", artifact.Path, artifact.Bytes, len(content))
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != artifact.SHA256 {
			t.Errorf("%s: manifest hash %s, file hash %s", artifact.Path, artifact.SHA256, got)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if !declared[entry.Name()] {
			t.Errorf("%s is in the output directory but not in the manifest", entry.Name())
		}
	}

	if man.Engine.Version == "" || man.Engine.PinnedVersion == "" {
		t.Errorf("manifest does not record the engine: %+v", man.Engine)
	}
	if man.Tool.Name != "pqc-fixtures" {
		t.Errorf("manifest tool = %+v", man.Tool)
	}
}

// TestSafetyMarkers is criterion 6: TEST ONLY names, short validity, insecure
// filenames, and nothing that chains to a system trust store.
func TestSafetyMarkers(t *testing.T) {
	dir, man := runGen(t, func(o *gen.Options) { o.ChainDepth = 3 })

	for _, role := range []string{"root", "intermediate-1", "leaf"} {
		cert := parseCert(t, filepath.Join(dir, "INSECURE-TEST-"+role+".cert.pem"))

		if !strings.Contains(cert.Subject.String(), gen.DNMarker) {
			t.Errorf("%s subject %q lacks the TEST ONLY marker", role, cert.Subject)
		}
		if !strings.Contains(cert.Issuer.String(), gen.DNMarker) {
			t.Errorf("%s issuer %q lacks the TEST ONLY marker", role, cert.Issuer)
		}

		lifetime := cert.NotAfter.Sub(cert.NotBefore)
		if lifetime > time.Duration(gen.MaxValidityDays)*24*time.Hour {
			t.Errorf("%s is valid for %s, longer than the %d-day cap", role, lifetime, gen.MaxValidityDays)
		}
		if cert.NotAfter.Before(time.Now()) {
			t.Errorf("%s is already expired (NotAfter %s)", role, cert.NotAfter)
		}
	}

	for _, artifact := range man.Artifacts {
		if artifact.Path == manifest.FileName {
			continue
		}
		if !strings.HasPrefix(artifact.Path, gen.FilePrefix) {
			t.Errorf("%s does not carry the %s filename marker", artifact.Path, gen.FilePrefix)
		}
	}

	notice, err := os.ReadFile(filepath.Join(dir, gen.NoticeFile))
	if err != nil {
		t.Fatalf("reading notice: %v", err)
	}
	if !strings.Contains(string(notice), "DO NOT USE") {
		t.Errorf("notice file does not warn loudly:\n%s", notice)
	}

	assertNotInSystemTrustStore(t, parseCert(t, filepath.Join(dir, "INSECURE-TEST-root.cert.pem")))
}

// assertNotInSystemTrustStore checks that the generated root is unknown to the
// machine's trust store, so nothing generated here can chain to a real CA.
func assertNotInSystemTrustStore(t *testing.T, root *x509.Certificate) {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system trust store available on this platform: %v", err)
	}
	for _, subject := range pool.Subjects() { //nolint:staticcheck // the deprecated accessor is the only way to enumerate
		if string(subject) == string(root.RawSubject) {
			t.Fatalf("the generated root %q is present in the system trust store", root.Subject)
		}
	}
	if _, err := root.Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatalf("the generated root %q verifies against the system trust store", root.Subject)
	}
}

// TestGenerationIsFastEnough is the measurable half of criterion 1: the gen
// step itself stays well inside 30 seconds for ML-DSA chains.
func TestGenerationIsFastEnough(t *testing.T) {
	eng := testengine.Locate(t)
	outDir := filepath.Join(t.TempDir(), "testdata")
	spec := resolveInto(t, outDir, func(o *gen.Options) { o.ChainDepth = 3 })

	result, err := gen.Generate(context.Background(), spec, eng, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if result.Duration > 30*time.Second {
		t.Errorf("generation took %s, longer than the 30 s budget", result.Duration)
	}
}

// TestSeededRunsAreReproducible is ADR-002: the same seed produces
// byte-identical keys for every certificate in the chain.
func TestSeededRunsAreReproducible(t *testing.T) {
	const seed = "00112233445566778899aabbccddeeff"
	seeded := func(o *gen.Options) { o.SeedHex = seed; o.ChainDepth = 3 }

	firstDir, firstMan := runGen(t, seeded)
	secondDir, secondMan := runGen(t, seeded)

	if !firstMan.Spec.Seeded || !secondMan.Spec.Seeded {
		t.Error("seeded runs are not marked seeded in the manifest")
	}
	for _, role := range []string{"root", "intermediate-1", "leaf"} {
		name := "INSECURE-TEST-" + role + ".key.pem"
		first, err := os.ReadFile(filepath.Join(firstDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		second, err := os.ReadFile(filepath.Join(secondDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if string(first) != string(second) {
			t.Errorf("%s differs between two runs with the same seed", name)
		}
	}

	// Distinct roles must not share a key, or the "chain" would be one key
	// wearing three hats.
	rootKey, err := os.ReadFile(filepath.Join(firstDir, "INSECURE-TEST-root.key.pem"))
	if err != nil {
		t.Fatalf("reading root key: %v", err)
	}
	leafKey, err := os.ReadFile(filepath.Join(firstDir, "INSECURE-TEST-leaf.key.pem"))
	if err != nil {
		t.Fatalf("reading leaf key: %v", err)
	}
	if string(rootKey) == string(leafKey) {
		t.Error("root and leaf share a private key")
	}
}

func TestUnseededRunsDiffer(t *testing.T) {
	firstDir, _ := runGen(t, func(o *gen.Options) { o.ChainDepth = 2 })
	secondDir, _ := runGen(t, func(o *gen.Options) { o.ChainDepth = 2 })

	first, err := os.ReadFile(filepath.Join(firstDir, "INSECURE-TEST-leaf.key.pem"))
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(secondDir, "INSECURE-TEST-leaf.key.pem"))
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	if string(first) == string(second) {
		t.Error("two unseeded runs produced the same private key")
	}
}

func TestFormatsSelectWhatIsWritten(t *testing.T) {
	for _, tc := range []struct {
		formats string
		want    []string
		absent  []string
	}{
		{"pem", []string{"INSECURE-TEST-leaf.cert.pem"}, []string{"INSECURE-TEST-leaf.cert.der"}},
		{"der", []string{"INSECURE-TEST-leaf.cert.der"}, []string{"INSECURE-TEST-leaf.cert.pem"}},
		{"pem,der", []string{"INSECURE-TEST-leaf.cert.pem", "INSECURE-TEST-leaf.cert.der"}, nil},
	} {
		t.Run(tc.formats, func(t *testing.T) {
			dir, _ := runGen(t, func(o *gen.Options) {
				o.Formats = tc.formats
				o.ChainDepth = 2
			})
			for _, name := range tc.want {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Errorf("--formats %s did not write %s", tc.formats, name)
				}
			}
			for _, name := range tc.absent {
				if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
					t.Errorf("--formats %s wrote %s anyway", tc.formats, name)
				}
			}
			// The concatenated chain is PEM in every case: DER cannot hold a
			// sequence of certificates.
			if _, err := os.Stat(filepath.Join(dir, gen.ChainFile)); err != nil {
				t.Errorf("--formats %s did not write %s", tc.formats, gen.ChainFile)
			}
		})
	}
}

// TestSelfSignedDepthOne: a one-certificate chain is a self-signed server
// certificate that still anchors its own verification.
func TestSelfSignedDepthOne(t *testing.T) {
	eng := testengine.Locate(t)
	dir, man := runGen(t, func(o *gen.Options) { o.ChainDepth = 1 })

	only := filepath.Join(dir, "INSECURE-TEST-root.cert.pem")
	if err := eng.VerifyChain(context.Background(), only, nil, only); err != nil {
		t.Fatalf("self-signed certificate does not verify against itself: %v", err)
	}
	cert := parseCert(t, only)
	if !cert.IsCA {
		t.Error("a depth-1 certificate must be a CA to anchor its own chain")
	}
	if len(cert.DNSNames) == 0 {
		t.Error("a depth-1 certificate must carry the leaf's SANs to be usable as a server certificate")
	}
	if man.Spec.ChainDepth != 1 {
		t.Errorf("manifest chainDepth = %d, want 1", man.Spec.ChainDepth)
	}
}

// TestForceReplacesAPreviousRun completes the --force story that
// atomic_test.go covers for the failure paths.
func TestForceReplacesAPreviousRun(t *testing.T) {
	eng := testengine.Locate(t)
	outDir := filepath.Join(t.TempDir(), "testdata")

	first, err := gen.Generate(context.Background(), resolveInto(t, outDir, nil), eng, nil)
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	second, err := gen.Generate(context.Background(),
		resolveInto(t, outDir, func(o *gen.Options) { o.Force = true; o.ChainDepth = 2 }), eng, nil)
	if err != nil {
		t.Fatalf("forced Generate: %v", err)
	}

	if second.Manifest.Spec.ChainDepth != 2 {
		t.Errorf("replacement manifest describes a depth-%d chain", second.Manifest.Spec.ChainDepth)
	}
	if _, err := os.Stat(filepath.Join(outDir, "INSECURE-TEST-intermediate-1.cert.pem")); err == nil {
		t.Error("the previous run's intermediate survived --force")
	}
	if first.OutDir != second.OutDir {
		t.Errorf("output directory moved between runs: %s then %s", first.OutDir, second.OutDir)
	}
}
