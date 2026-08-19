package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/manifest"
	"github.com/GreatSarmad/pqc-fixtures/tests/internal/schemacheck"
)

// sample is a fully populated manifest: every optional field set, so the
// schema check below exercises the whole contract.
func sample() *manifest.Manifest {
	return &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Warning:       manifest.Warning,
		Tool:          manifest.Tool{Name: "pqc-fixtures", Version: "v0.0.1"},
		Engine:        manifest.Engine{Name: "openssl", Version: "3.5.7", PinnedVersion: "3.5.7"},
		GeneratedAt:   "2026-08-12T05:43:43Z",
		Spec: manifest.Spec{
			Algorithm:       "ml-dsa-65",
			ChainDepth:      3,
			ValidityDays:    30,
			Formats:         []string{"pem", "der"},
			Seeded:          true,
			SubjectAltNames: []string{"DNS:localhost", "IP:127.0.0.1"},
			SizeEnvelope: manifest.Envelope{
				PublicKeyBytes: 1952, SignatureBytes: 3309, MinChainBytes: 3 * (1952 + 3309),
			},
			Preset: &manifest.PresetRef{Name: "example", Version: 1},
		},
		Artifacts: []manifest.Artifact{
			{
				Path: "INSECURE-TEST-root.key.pem", Kind: manifest.KindPrivateKey,
				Encoding: manifest.EncodingPEM, Role: "root", Bytes: 5604,
				SHA256: strings.Repeat("ab", 32),
				Key:    &manifest.KeyDetail{Algorithm: "ml-dsa-65", Seeded: true},
			},
			{
				Path: "INSECURE-TEST-root.cert.der", Kind: manifest.KindCertificate,
				Encoding: manifest.EncodingDER, Role: "root", Bytes: 5600,
				SHA256: strings.Repeat("0f", 32),
				Certificate: &manifest.CertDetail{
					Algorithm: "ml-dsa-65", Subject: "CN=PQC-FIXTURES TEST ONLY Root CA",
					Issuer: "CN=PQC-FIXTURES TEST ONLY Root CA", SerialNumber: "0a1b2c",
					NotBefore: "2026-08-12T05:43:43Z", NotAfter: "2026-09-11T05:43:43Z",
					IsCA: true, SignatureBytes: 3309, PublicKeyBytes: 1952,
				},
			},
			{
				Path: "INSECURE-TEST-fullchain.pem", Kind: manifest.KindChain,
				Encoding: manifest.EncodingPEM, Role: "chain", Bytes: 23088,
				SHA256: strings.Repeat("cd", 32),
			},
			{
				Path: "INSECURE-TEST-README.txt", Kind: manifest.KindNotice,
				Encoding: manifest.EncodingText, Role: "chain", Bytes: 556,
				SHA256: strings.Repeat("ef", 32),
			},
		},
	}
}

// TestSchemaIsPublishedAndValid guards the contract itself: the schema ships
// inside the binary (so `pqc-fixtures schema` works offline) and is parseable.
func TestSchemaIsPublishedAndValid(t *testing.T) {
	raw := manifest.Schema()
	if len(raw) == 0 {
		t.Fatal("no schema embedded in the binary")
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}
	if got := schema["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v, want the 2020-12 dialect", got)
	}
}

// TestSampleManifestValidatesAgainstSchema is design-dossier §8 criterion 4 at
// the unit level; tests/gen asserts it again for real generated output.
func TestSampleManifestValidatesAgainstSchema(t *testing.T) {
	encoded, err := sample().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := schemacheck.Validate(manifest.Schema(), encoded); err != nil {
		t.Fatal(err)
	}
}

// TestSchemaRejectsMalformedManifests proves the check above can fail - a
// validator that accepts everything would silently retire the criterion.
func TestSchemaRejectsMalformedManifests(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"missing required field": func(m map[string]any) { delete(m, "engine") },
		"wrong type": func(m map[string]any) {
			m["spec"].(map[string]any)["chainDepth"] = "three"
		},
		"undeclared property": func(m map[string]any) { m["telemetryEndpoint"] = "https://example.invalid" },
		"bad enum value": func(m map[string]any) {
			m["artifacts"].([]any)[0].(map[string]any)["kind"] = "somethingElse"
		},
		"malformed hash": func(m map[string]any) {
			m["artifacts"].([]any)[0].(map[string]any)["sha256"] = "not-a-hash"
		},
		"wrong tool name": func(m map[string]any) {
			m["tool"].(map[string]any)["name"] = "someone-elses-tool"
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := sample().Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			var doc map[string]any
			if err := json.Unmarshal(encoded, &doc); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			mutate(doc)
			mutated, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if err := schemacheck.Validate(manifest.Schema(), mutated); err == nil {
				t.Error("schema validation accepted a manifest it should have rejected")
			}
		})
	}
}

func TestWriteAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), manifest.FileName)
	original := sample()
	if err := original.WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	before, _ := original.Encode()
	after, _ := loaded.Encode()
	if string(before) != string(after) {
		t.Errorf("round trip changed the manifest:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestLoadRejectsUnknownFields keeps the manifest a contract rather than a
// bag: a file with fields we do not know is not one of ours.
func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), manifest.FileName)
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"mystery":true}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := manifest.Load(path); err == nil {
		t.Error("Load accepted a manifest with an unknown field")
	}
}

// TestWarningIsLoud - the manifest is the machine-readable contract, so the
// "do not use this" statement has to travel inside it.
func TestWarningIsLoud(t *testing.T) {
	if !strings.Contains(manifest.Warning, "INSECURE") {
		t.Errorf("manifest warning %q does not say the fixtures are insecure", manifest.Warning)
	}
}
