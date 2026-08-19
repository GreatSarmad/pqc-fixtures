package gen

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// certFacts is what the core needs to know about a certificate the engine just
// produced. Reading it back from the DER rather than trusting the request is
// deliberate: the size assertions of design-dossier §8 criterion 3 are only
// meaningful if they measure the actual output.
//
// Parsing uses the Go standard library, which tolerates signature and public
// key algorithms it does not implement - it records the raw bytes and skips
// interpretation. That is exactly the level of understanding we need, and it
// keeps the promise that this project implements no cryptography (§3).
type certFacts struct {
	subject        string
	issuer         string
	serialNumber   string
	notBefore      time.Time
	notAfter       time.Time
	isCA           bool
	signatureBytes int
	publicKeyBytes int
	// derBytes is the certificate's own DER length - what it costs on the
	// wire, as distinct from the signature and key it carries.
	derBytes   int
	rawSubject []byte
	rawIssuer  []byte
}

// inspectCert parses a DER certificate.
func inspectCert(derPath string) (certFacts, error) {
	der, err := os.ReadFile(derPath)
	if err != nil {
		return certFacts{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return certFacts{}, fmt.Errorf("parsing %s: %w", derPath, err)
	}
	pubBytes, err := rawPublicKeyLen(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return certFacts{}, fmt.Errorf("reading public key of %s: %w", derPath, err)
	}
	return certFacts{
		subject:        cert.Subject.String(),
		issuer:         cert.Issuer.String(),
		serialNumber:   cert.SerialNumber.Text(16),
		notBefore:      cert.NotBefore.UTC(),
		notAfter:       cert.NotAfter.UTC(),
		isCA:           cert.IsCA,
		signatureBytes: len(cert.Signature),
		publicKeyBytes: pubBytes,
		derBytes:       len(der),
		rawSubject:     cert.RawSubject,
		rawIssuer:      cert.RawIssuer,
	}, nil
}

// rawPublicKeyLen returns the length of the raw key inside a
// SubjectPublicKeyInfo, without interpreting it. For ML-DSA and SLH-DSA the
// BIT STRING holds the FIPS-defined public key verbatim, so its length is the
// number design-dossier §8 criterion 3 asserts.
func rawPublicKeyLen(spki []byte) (int, error) {
	var info struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return 0, err
	}
	return len(info.PublicKey.Bytes), nil
}

// fileFacts is a generated file's size and hash, for the manifest.
func fileFacts(path string) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return int(n), hex.EncodeToString(h.Sum(nil)), nil
}
