// Package manifest defines the Manifest - the machine-readable record of one
// generation run and, per design-dossier §6, the only contract between the CLI
// and everything downstream of it (serve, the GitHub Action, later report
// generation).
//
// The JSON Schema in manifest.schema.json is part of the published contract:
// it ships inside the binary so `pqc-fixtures schema` can print it offline,
// and tests validate every generated Manifest against it (design-dossier §8
// criterion 4).
package manifest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
)

// SchemaVersion is the current manifest format version.
const SchemaVersion = 1

// FileName is the manifest's filename inside an output directory.
const FileName = "manifest.json"

// ToolName is stamped into every manifest as tool.name. Ownership checks
// (gen's --force) compare against it.
const ToolName = "pqc-fixtures"

// Warning is stamped into every manifest. Anything reading a manifest sees, in
// its own data, that the artifacts are not safe for any real use.
const Warning = "INSECURE TEST FIXTURES. Every key and certificate listed here is generated for " +
	"testing post-quantum artifact sizes and must never be used to protect anything. " +
	"Private keys are unencrypted; certificates are short-lived and chain only to their own test root."

//go:embed manifest.schema.json
var schemaJSON []byte

// Schema returns the published JSON Schema for this manifest format.
func Schema() []byte { return schemaJSON }

// Manifest is one generation run.
type Manifest struct {
	SchemaVersion int        `json:"schemaVersion"`
	Warning       string     `json:"warning"`
	Tool          Tool       `json:"tool"`
	Engine        Engine     `json:"engine"`
	GeneratedAt   string     `json:"generatedAt"`
	Spec          Spec       `json:"spec"`
	Artifacts     []Artifact `json:"artifacts"`
}

// Tool identifies the generator.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Engine identifies the cryptographic engine that produced the artifacts.
type Engine struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	PinnedVersion string `json:"pinnedVersion"`
}

// Spec is the fully resolved generation request.
type Spec struct {
	Algorithm       string   `json:"algorithm"`
	ChainDepth      int      `json:"chainDepth"`
	ValidityDays    int      `json:"validityDays"`
	Formats         []string `json:"formats"`
	Seeded          bool     `json:"seeded"`
	SubjectAltNames []string `json:"subjectAltNames"`
	SizeEnvelope    Envelope `json:"sizeEnvelope"`
	// Preset names the shipped preset this run came from, absent when the
	// request was assembled from flags alone. Presets are versioned data, so
	// recording which version produced a fixture set keeps an old CI run
	// interpretable after the preset itself has moved on (design-dossier §10).
	Preset *PresetRef `json:"preset,omitempty"`
}

// PresetRef identifies the preset a run was generated from.
type PresetRef struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	// Modified reports that a flag overrode something the preset specified, so
	// this run is attributed to the preset but is not what the preset alone
	// would have produced.
	Modified bool `json:"modified"`
}

// Envelope is the AlgorithmProfile's expected raw sizes for this run.
type Envelope struct {
	PublicKeyBytes int `json:"publicKeyBytes"`
	SignatureBytes int `json:"signatureBytes"`
	// MinChainBytes is the smallest total DER certificate-chain size this
	// request can produce: every certificate carries at least its own
	// signature and public key, so chainDepth x (signature + public key) is a
	// floor. gen asserts the real output against it.
	MinChainBytes int `json:"minChainBytes"`
}

// Artifact is one generated file.
type Artifact struct {
	Path        string      `json:"path"`
	Kind        string      `json:"kind"`
	Encoding    string      `json:"encoding"`
	Role        string      `json:"role"`
	Bytes       int         `json:"bytes"`
	SHA256      string      `json:"sha256"`
	Key         *KeyDetail  `json:"key,omitempty"`
	Certificate *CertDetail `json:"certificate,omitempty"`
}

// Artifact kinds. gen emits private keys and certificates only; a public-key
// kind returns with F3's bare ML-KEM artifacts.
const (
	KindPrivateKey  = "privateKey"
	KindCertificate = "certificate"
	KindChain       = "chain"
	KindNotice      = "notice"
)

// Artifact encodings.
const (
	EncodingPEM  = "pem"
	EncodingDER  = "der"
	EncodingText = "text"
)

// KeyDetail carries key-specific metadata.
type KeyDetail struct {
	Algorithm string `json:"algorithm"`
	// Seeded reports determinism per artifact rather than per run, because
	// --seed applies to ML-DSA and ML-KEM but not SLH-DSA (ADR-002).
	Seeded bool `json:"seeded"`
}

// CertDetail carries certificate-specific metadata, including the two sizes
// that design-dossier §8 criterion 3 asserts.
type CertDetail struct {
	Algorithm      string `json:"algorithm"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	SerialNumber   string `json:"serialNumber"`
	NotBefore      string `json:"notBefore"`
	NotAfter       string `json:"notAfter"`
	IsCA           bool   `json:"isCA"`
	SignatureBytes int    `json:"signatureBytes"`
	PublicKeyBytes int    `json:"publicKeyBytes"`
}

// Encode renders the manifest as indented JSON with a trailing newline.
func (m *Manifest) Encode() ([]byte, error) {
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	return append(out, '\n'), nil
}

// WriteFile writes the manifest to path.
func (m *Manifest) WriteFile(path string) error {
	out, err := m.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	return nil
}

// GeneratedBy reads only the generating tool's name from a manifest file,
// tolerating fields this build does not know about. The ownership question -
// "did pqc-fixtures write this directory?" - must be answerable across
// versions: fields are added to the manifest over time and stay additive
// within a schemaVersion (ADR-011), so a strict decode here would make an
// older binary disown a directory a newer binary wrote and wrongly refuse to
// --force-replace it. Load below stays strict for consumers of the full
// format.
func GeneratedBy(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var probe struct {
		Tool struct {
			Name string `json:"name"`
		} `json:"tool"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("decoding %s: %w", path, err)
	}
	return probe.Tool.Name, nil
}

// Load reads and decodes a manifest. It rejects unknown fields: a document
// with fields this build does not know is not one this build can faithfully
// consume. For the looser "is this ours at all" question, use GeneratedBy.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return &m, nil
}
