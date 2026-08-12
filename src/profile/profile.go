// Package profile is the AlgorithmProfile registry (design-dossier §6): the
// static, versioned source of truth for each parameter set's exact size
// envelope. Size assertions in tests and the byte counts stamped into a
// Manifest both resolve through here, so a divergence between what FIPS
// 203/204/205 specify and what the engine emits fails loudly rather than
// silently shipping a fixture of the wrong size.
//
// The numbers are the standards' own, not measurements: FIPS 204 Table 2
// (ML-DSA), FIPS 205 Table 8 (SLH-DSA), FIPS 203 Table 3 (ML-KEM). They were
// confirmed against a real engine during the S1 spike (docs/spike-notes.md).
package profile

import (
	"fmt"
	"sort"
	"strings"
)

// Kind distinguishes what an algorithm can be used for. It decides which
// artifacts a profile can appear in: only signature algorithms can sign a
// certificate.
type Kind string

const (
	// KindSignature is a digital-signature algorithm (ML-DSA, SLH-DSA).
	KindSignature Kind = "signature"
	// KindKEM is a key-encapsulation mechanism (ML-KEM). KEM keys never sign,
	// so they are emitted as bare keys, never as certificates.
	KindKEM Kind = "kem"
)

// Profile is one parameter set and its size envelope, in bytes.
type Profile struct {
	// ID is the lowercase identifier users pass to --algo.
	ID string
	// EngineName is the algorithm name the OpenSSL engine expects.
	EngineName string
	// Family groups parameter sets that share keygen mechanics (notably seed
	// handling), e.g. "ML-DSA".
	Family string
	// Kind is what the algorithm can do.
	Kind Kind
	// PublicKeyBytes is the raw public key length (FIPS "pk" / ML-KEM "ek").
	PublicKeyBytes int
	// PrivateKeyBytes is the raw private key length (FIPS "sk" / ML-KEM "dk").
	// Recorded for documentation; it is deliberately not asserted against file
	// sizes, because a PKCS#8 file wraps (and, for seeded keys, may replace)
	// the raw key.
	PrivateKeyBytes int
	// SignatureBytes is the raw signature length; zero for KEMs.
	SignatureBytes int
	// CiphertextBytes is the encapsulation length; zero for signature
	// algorithms.
	CiphertextBytes int
	// SeedBytes is the length of the keygen seed this family accepts, or zero
	// if the algorithm cannot be seeded. The length is family-specific: FIPS
	// 204 takes a 32-byte xi, FIPS 203 takes d‖z (64 bytes), and SLH-DSA
	// exposes no seed-shaped keygen parameter at all (ADR-002, S1 spike).
	SeedBytes int
}

// Seedable reports whether --seed produces byte-identical keys for this
// algorithm (ADR-002).
func (p Profile) Seedable() bool { return p.SeedBytes > 0 }

// registry is keyed by Profile.ID.
var registry = map[string]Profile{
	"ml-dsa-44": {
		ID: "ml-dsa-44", EngineName: "ML-DSA-44", Family: "ML-DSA", Kind: KindSignature,
		PublicKeyBytes: 1312, PrivateKeyBytes: 2560, SignatureBytes: 2420, SeedBytes: 32,
	},
	"ml-dsa-65": {
		ID: "ml-dsa-65", EngineName: "ML-DSA-65", Family: "ML-DSA", Kind: KindSignature,
		PublicKeyBytes: 1952, PrivateKeyBytes: 4032, SignatureBytes: 3309, SeedBytes: 32,
	},
	"ml-dsa-87": {
		ID: "ml-dsa-87", EngineName: "ML-DSA-87", Family: "ML-DSA", Kind: KindSignature,
		PublicKeyBytes: 2592, PrivateKeyBytes: 4896, SignatureBytes: 4627, SeedBytes: 32,
	},
	"slh-dsa-sha2-256f": {
		ID: "slh-dsa-sha2-256f", EngineName: "SLH-DSA-SHA2-256f", Family: "SLH-DSA", Kind: KindSignature,
		PublicKeyBytes: 64, PrivateKeyBytes: 128, SignatureBytes: 49856, SeedBytes: 0,
	},
	"ml-kem-512": {
		ID: "ml-kem-512", EngineName: "ML-KEM-512", Family: "ML-KEM", Kind: KindKEM,
		PublicKeyBytes: 800, PrivateKeyBytes: 1632, CiphertextBytes: 768, SeedBytes: 64,
	},
	"ml-kem-768": {
		ID: "ml-kem-768", EngineName: "ML-KEM-768", Family: "ML-KEM", Kind: KindKEM,
		PublicKeyBytes: 1184, PrivateKeyBytes: 2400, CiphertextBytes: 1088, SeedBytes: 64,
	},
	"ml-kem-1024": {
		ID: "ml-kem-1024", EngineName: "ML-KEM-1024", Family: "ML-KEM", Kind: KindKEM,
		PublicKeyBytes: 1568, PrivateKeyBytes: 3168, CiphertextBytes: 1568, SeedBytes: 64,
	},
}

// Lookup resolves an --algo value. Matching is case-insensitive so both
// "ml-dsa-65" and the FIPS spelling "ML-DSA-65" work.
func Lookup(id string) (Profile, error) {
	p, ok := registry[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return Profile{}, fmt.Errorf("unknown algorithm %q; known algorithms: %s",
			id, strings.Join(IDs(), ", "))
	}
	return p, nil
}

// IDs lists every registered algorithm ID, sorted, for help text and errors.
func IDs() []string {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// SignatureIDs lists the algorithms that can sign a certificate, sorted.
func SignatureIDs() []string {
	var ids []string
	for id, p := range registry {
		if p.Kind == KindSignature {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
