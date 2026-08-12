package profile_test

import (
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/profile"
)

// TestRegistryMatchesStandards pins every size envelope to the published
// standard. These numbers are the product: if one drifts, every size
// assertion downstream is measuring the wrong thing.
func TestRegistryMatchesStandards(t *testing.T) {
	want := []profile.Profile{
		// FIPS 204 Table 2.
		{ID: "ml-dsa-44", EngineName: "ML-DSA-44", Family: "ML-DSA", Kind: profile.KindSignature,
			PublicKeyBytes: 1312, PrivateKeyBytes: 2560, SignatureBytes: 2420, SeedBytes: 32},
		{ID: "ml-dsa-65", EngineName: "ML-DSA-65", Family: "ML-DSA", Kind: profile.KindSignature,
			PublicKeyBytes: 1952, PrivateKeyBytes: 4032, SignatureBytes: 3309, SeedBytes: 32},
		{ID: "ml-dsa-87", EngineName: "ML-DSA-87", Family: "ML-DSA", Kind: profile.KindSignature,
			PublicKeyBytes: 2592, PrivateKeyBytes: 4896, SignatureBytes: 4627, SeedBytes: 32},
		// FIPS 205 Table 8.
		{ID: "slh-dsa-sha2-256f", EngineName: "SLH-DSA-SHA2-256f", Family: "SLH-DSA", Kind: profile.KindSignature,
			PublicKeyBytes: 64, PrivateKeyBytes: 128, SignatureBytes: 49856, SeedBytes: 0},
		// FIPS 203 Table 3.
		{ID: "ml-kem-512", EngineName: "ML-KEM-512", Family: "ML-KEM", Kind: profile.KindKEM,
			PublicKeyBytes: 800, PrivateKeyBytes: 1632, CiphertextBytes: 768, SeedBytes: 64},
		{ID: "ml-kem-768", EngineName: "ML-KEM-768", Family: "ML-KEM", Kind: profile.KindKEM,
			PublicKeyBytes: 1184, PrivateKeyBytes: 2400, CiphertextBytes: 1088, SeedBytes: 64},
		{ID: "ml-kem-1024", EngineName: "ML-KEM-1024", Family: "ML-KEM", Kind: profile.KindKEM,
			PublicKeyBytes: 1568, PrivateKeyBytes: 3168, CiphertextBytes: 1568, SeedBytes: 64},
	}

	for _, expected := range want {
		got, err := profile.Lookup(expected.ID)
		if err != nil {
			t.Errorf("Lookup(%q): %v", expected.ID, err)
			continue
		}
		if got != expected {
			t.Errorf("Lookup(%q) = %+v, want %+v", expected.ID, got, expected)
		}
	}

	if len(profile.IDs()) != len(want) {
		t.Errorf("registry has %d algorithms, test covers %d - add the new one here",
			len(profile.IDs()), len(want))
	}
}

// TestSeedability encodes the S1 spike finding behind ADR-002: seed length is
// family-specific, and SLH-DSA has no seed at all.
func TestSeedability(t *testing.T) {
	for _, tc := range []struct {
		id       string
		seedable bool
		seedLen  int
	}{
		{"ml-dsa-65", true, 32},
		{"ml-kem-768", true, 64},
		{"slh-dsa-sha2-256f", false, 0},
	} {
		p, err := profile.Lookup(tc.id)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", tc.id, err)
		}
		if p.Seedable() != tc.seedable {
			t.Errorf("%s: Seedable() = %v, want %v", tc.id, p.Seedable(), tc.seedable)
		}
		if p.SeedBytes != tc.seedLen {
			t.Errorf("%s: SeedBytes = %d, want %d", tc.id, p.SeedBytes, tc.seedLen)
		}
	}
}

func TestLookupIsCaseInsensitive(t *testing.T) {
	for _, id := range []string{"ML-DSA-65", "  ml-dsa-65 ", "Ml-Dsa-65"} {
		p, err := profile.Lookup(id)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", id, err)
		}
		if p.ID != "ml-dsa-65" {
			t.Errorf("Lookup(%q).ID = %q, want ml-dsa-65", id, p.ID)
		}
	}
}

func TestLookupUnknownListsAlternatives(t *testing.T) {
	_, err := profile.Lookup("rsa-4096")
	if err == nil {
		t.Fatal("expected an error for an unknown algorithm")
	}
	if !strings.Contains(err.Error(), "ml-dsa-65") {
		t.Errorf("error %q does not suggest a known algorithm", err)
	}
}

func TestSignatureIDsExcludeKEMs(t *testing.T) {
	for _, id := range profile.SignatureIDs() {
		p, err := profile.Lookup(id)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", id, err)
		}
		if p.Kind != profile.KindSignature {
			t.Errorf("SignatureIDs includes %q, which is a %s algorithm", id, p.Kind)
		}
	}
	if len(profile.SignatureIDs()) >= len(profile.IDs()) {
		t.Error("SignatureIDs should be a strict subset of IDs (the registry has KEMs)")
	}
}
