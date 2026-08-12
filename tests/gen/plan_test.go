package gen_test

import (
	"strings"
	"testing"

	"github.com/GreatSarmad/pqc-fixtures/src/gen"
)

func planFor(t *testing.T, depth int) []gen.PlannedCertificate {
	t.Helper()
	opts := validOptions()
	opts.ChainDepth = depth
	spec, err := gen.Resolve(opts)
	if err != nil {
		t.Fatalf("Resolve(chain=%d): %v", depth, err)
	}
	return gen.Plan(spec)
}

func TestPlanShapes(t *testing.T) {
	for depth, wantRoles := range map[int][]string{
		1: {"root"},
		2: {"root", "leaf"},
		3: {"root", "intermediate-1", "leaf"},
		5: {"root", "intermediate-1", "intermediate-2", "intermediate-3", "leaf"},
	} {
		plan := planFor(t, depth)
		var roles []string
		for _, c := range plan {
			roles = append(roles, c.Role)
		}
		if strings.Join(roles, ",") != strings.Join(wantRoles, ",") {
			t.Errorf("chain=%d roles = %v, want %v", depth, roles, wantRoles)
		}
	}
}

// TestPlanIssuerChain: every certificate but the first is issued by the one
// above it, and only the root is self-signed.
func TestPlanIssuerChain(t *testing.T) {
	plan := planFor(t, 4)
	if plan[0].IssuerRole != "" {
		t.Errorf("root IssuerRole = %q, want empty (self-signed)", plan[0].IssuerRole)
	}
	for i := 1; i < len(plan); i++ {
		if plan[i].IssuerRole != plan[i-1].Role {
			t.Errorf("%s is issued by %q, want %q", plan[i].Role, plan[i].IssuerRole, plan[i-1].Role)
		}
	}
}

// TestPlanPathLengths: each CA's pathlen is exactly the number of CAs below
// it, so the generated chain cannot be extended past the requested depth.
func TestPlanPathLengths(t *testing.T) {
	plan := planFor(t, 5) // root, 3 intermediates, leaf
	wantPathLen := map[string]int{
		"root": 3, "intermediate-1": 2, "intermediate-2": 1, "intermediate-3": 0, "leaf": -1,
	}
	for _, c := range plan {
		if got := c.PathLen; got != wantPathLen[c.Role] {
			t.Errorf("%s PathLen = %d, want %d", c.Role, got, wantPathLen[c.Role])
		}
	}
}

// TestPlanRolesAndUsages: CAs sign certificates, the end entity serves TLS,
// and a depth-1 chain does both with one certificate.
func TestPlanRolesAndUsages(t *testing.T) {
	deep := planFor(t, 3)
	for _, c := range deep[:len(deep)-1] {
		if !c.IsCA || c.IsEndEntity {
			t.Errorf("%s: IsCA=%v IsEndEntity=%v, want a pure CA", c.Role, c.IsCA, c.IsEndEntity)
		}
	}
	leaf := deep[len(deep)-1]
	if leaf.IsCA || !leaf.IsEndEntity {
		t.Errorf("leaf: IsCA=%v IsEndEntity=%v, want a pure end entity", leaf.IsCA, leaf.IsEndEntity)
	}

	single := planFor(t, 1)
	if !single[0].IsCA || !single[0].IsEndEntity {
		t.Errorf("depth-1 certificate must anchor the chain and serve TLS, got IsCA=%v IsEndEntity=%v",
			single[0].IsCA, single[0].IsEndEntity)
	}
}

func TestPlanExtensions(t *testing.T) {
	plan := planFor(t, 3)
	exts := func(c gen.PlannedCertificate) string { return strings.Join(c.Extensions, "\n") }

	root, intermediate, leaf := plan[0], plan[1], plan[2]

	for _, ca := range []gen.PlannedCertificate{root, intermediate} {
		e := exts(ca)
		if !strings.Contains(e, "basicConstraints=critical,CA:true") {
			t.Errorf("%s is missing a critical CA:true basicConstraints:\n%s", ca.Role, e)
		}
		if !strings.Contains(e, "keyUsage=critical,keyCertSign,cRLSign") {
			t.Errorf("%s is missing keyCertSign:\n%s", ca.Role, e)
		}
		if strings.Contains(e, "subjectAltName") {
			t.Errorf("%s carries SANs; only the end entity should:\n%s", ca.Role, e)
		}
	}

	e := exts(leaf)
	for _, want := range []string{
		"basicConstraints=critical,CA:false",
		"keyUsage=critical,digitalSignature",
		"extendedKeyUsage=serverAuth",
		"subjectAltName=DNS:localhost,IP:127.0.0.1",
		"authorityKeyIdentifier=keyid:always",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("leaf is missing %q:\n%s", want, e)
		}
	}

	// A self-signed certificate has no issuer certificate to copy a key
	// identifier from.
	if strings.Contains(exts(root), "authorityKeyIdentifier") {
		t.Errorf("self-signed root should not request an authorityKeyIdentifier:\n%s", exts(root))
	}
}

// TestPlanSafetyMarkers is the planning half of design-dossier §8 criterion 6;
// tests/gen/generate_test.go asserts the same markers on real output.
func TestPlanSafetyMarkers(t *testing.T) {
	for _, depth := range []int{1, 2, 3, 6} {
		for _, c := range planFor(t, depth) {
			if !strings.Contains(c.Subject, gen.DNMarker) {
				t.Errorf("chain=%d %s subject %q lacks the TEST ONLY marker", depth, c.Role, c.Subject)
			}
			if !strings.HasPrefix(c.KeyFile("pem"), gen.FilePrefix) ||
				!strings.HasPrefix(c.CertFile("der"), gen.FilePrefix) {
				t.Errorf("chain=%d %s filenames lack the %s prefix: %s, %s",
					depth, c.Role, gen.FilePrefix, c.KeyFile("pem"), c.CertFile("der"))
			}
		}
	}
	if !strings.HasPrefix(gen.ChainFile, gen.FilePrefix) || !strings.HasPrefix(gen.NoticeFile, gen.FilePrefix) {
		t.Errorf("aggregate files lack the %s prefix: %s, %s", gen.FilePrefix, gen.ChainFile, gen.NoticeFile)
	}
}

func TestPlanFileNames(t *testing.T) {
	plan := planFor(t, 3)
	if got := plan[1].KeyFile("pem"); got != "INSECURE-TEST-intermediate-1.key.pem" {
		t.Errorf("KeyFile = %q", got)
	}
	if got := plan[1].CertFile("der"); got != "INSECURE-TEST-intermediate-1.cert.der" {
		t.Errorf("CertFile = %q", got)
	}
}

// TestPlanHonoursCustomSANs: --sans replaces the defaults on the end entity.
func TestPlanHonoursCustomSANs(t *testing.T) {
	opts := validOptions()
	opts.SANs = []string{"DNS:app.internal"}
	spec, err := gen.Resolve(opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	plan := gen.Plan(spec)
	leaf := strings.Join(plan[len(plan)-1].Extensions, "\n")
	if !strings.Contains(leaf, "subjectAltName=DNS:app.internal") {
		t.Errorf("custom SAN missing:\n%s", leaf)
	}
	if strings.Contains(leaf, "localhost") {
		t.Errorf("default SANs survived alongside a custom list:\n%s", leaf)
	}
}
