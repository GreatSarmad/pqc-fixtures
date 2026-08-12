package gen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// FilePrefix marks every generated file as unusable in production. It is one
// of the three safety markers required by design-dossier §9 (the others are
// the TEST ONLY distinguished names below and the ≤30-day validity cap).
const FilePrefix = "INSECURE-TEST-"

// DNMarker appears in the Subject of every certificate we issue - and
// therefore in the Issuer of every certificate below it in the chain
// (design-dossier §8 criterion 6).
const DNMarker = "PQC-FIXTURES TEST ONLY"

// ChainFile is the concatenated chain, leaf first - the file most TLS servers
// want handed to them. It is always PEM: DER has no representation for a
// sequence of certificates.
const ChainFile = FilePrefix + "fullchain.pem"

// NoticeFile is the plain-text warning dropped beside the fixtures, so the
// danger is visible to someone who finds the directory without the manifest.
const NoticeFile = FilePrefix + "README.txt"

// PlannedCertificate is one certificate in a planned chain: everything decided
// before the engine is invoked. Planning is separated from execution so the
// shape of a run can be inspected and tested without generating anything.
type PlannedCertificate struct {
	// Role is the manifest role and the filename stem, e.g. "intermediate-1".
	Role string
	// Subject is the OpenSSL subject string.
	Subject string
	// IsCA reports whether this certificate may sign other certificates.
	IsCA bool
	// IsEndEntity reports whether it carries the TLS server identity (SANs and
	// serverAuth). A depth-1 chain has a single certificate that is both.
	IsEndEntity bool
	// PathLen is the BasicConstraints pathlen for CAs; -1 omits it.
	PathLen int
	// IssuerRole is the Role of the issuing certificate, empty when
	// self-signed.
	IssuerRole string
	// Extensions are the OpenSSL extension lines for this certificate.
	Extensions []string

	// parent indexes the issuer within the same plan; -1 means self-signed.
	parent int
}

// KeyFile and CertFile name this certificate's artifacts, relative to the
// output directory.
func (p PlannedCertificate) KeyFile(encoding string) string {
	return FilePrefix + p.Role + ".key." + encoding
}

func (p PlannedCertificate) CertFile(encoding string) string {
	return FilePrefix + p.Role + ".cert." + encoding
}

// Plan lays out the chain a Spec asks for, root first.
//
// Depth 1 is a single self-signed certificate that both anchors the chain and
// serves as the end entity; depth 2 is root + leaf; deeper chains insert
// intermediates numbered from the root down. Each CA's pathlen is exactly the
// number of CAs beneath it, so a chain cannot be extended past the depth the
// user asked for.
func Plan(spec *Spec) []PlannedCertificate {
	if spec.ChainDepth == 1 {
		only := PlannedCertificate{
			Role:        "root",
			IsCA:        true,
			IsEndEntity: true,
			PathLen:     -1,
			parent:      -1,
			Subject:     subjectFor(DNMarker + " Self-Signed"),
		}
		only.Extensions = extensionsFor(only, spec.SANs)
		return []PlannedCertificate{only}
	}

	intermediates := spec.ChainDepth - 2
	plan := make([]PlannedCertificate, 0, spec.ChainDepth)

	root := PlannedCertificate{
		Role:    "root",
		IsCA:    true,
		PathLen: intermediates,
		parent:  -1,
		Subject: subjectFor(DNMarker + " Root CA"),
	}
	root.Extensions = extensionsFor(root, spec.SANs)
	plan = append(plan, root)

	for i := 1; i <= intermediates; i++ {
		ca := PlannedCertificate{
			Role:       fmt.Sprintf("intermediate-%d", i),
			IsCA:       true,
			PathLen:    intermediates - i,
			parent:     len(plan) - 1,
			IssuerRole: plan[len(plan)-1].Role,
			Subject:    subjectFor(fmt.Sprintf("%s Intermediate CA %d", DNMarker, i)),
		}
		ca.Extensions = extensionsFor(ca, spec.SANs)
		plan = append(plan, ca)
	}

	leaf := PlannedCertificate{
		Role:        "leaf",
		IsEndEntity: true,
		PathLen:     -1,
		parent:      len(plan) - 1,
		IssuerRole:  plan[len(plan)-1].Role,
		Subject:     subjectFor(DNMarker + " Leaf"),
	}
	leaf.Extensions = extensionsFor(leaf, spec.SANs)
	return append(plan, leaf)
}

// subjectFor puts the marker in both the O and the CN, so it survives tooling
// that displays only one of them.
func subjectFor(commonName string) string {
	return "/O=" + DNMarker + "/CN=" + commonName
}

// extensionsFor renders the OpenSSL extension lines for one planned
// certificate. Self-signed certificates omit authorityKeyIdentifier: there is
// no issuer certificate to take a key identifier from at signing time.
func extensionsFor(p PlannedCertificate, sans []string) []string {
	var exts []string

	basic := "basicConstraints=critical,CA:"
	if p.IsCA {
		basic += "true"
		if p.PathLen >= 0 {
			basic += fmt.Sprintf(",pathlen:%d", p.PathLen)
		}
	} else {
		basic += "false"
	}
	exts = append(exts, basic)

	var usages []string
	if p.IsCA {
		usages = append(usages, "keyCertSign", "cRLSign")
	}
	if p.IsEndEntity {
		usages = append(usages, "digitalSignature")
	}
	exts = append(exts, "keyUsage=critical,"+strings.Join(usages, ","))

	if p.IsEndEntity {
		exts = append(exts, "extendedKeyUsage=serverAuth")
		if len(sans) > 0 {
			exts = append(exts, "subjectAltName="+strings.Join(sans, ","))
		}
	}

	exts = append(exts, "subjectKeyIdentifier=hash")
	if p.parent >= 0 {
		exts = append(exts, "authorityKeyIdentifier=keyid:always")
	}
	return exts
}

// deriveSeed produces one artifact's keygen seed from the run's master seed.
//
// A chain needs a distinct key per certificate, but a user supplies one
// --seed; sub-seeds are derived so the whole chain is reproducible from that
// one value (ADR-002). This is domain-separated hashing for label uniqueness,
// not a security construction - the resulting keys protect nothing (see
// design-dossier §3: this project implements no cryptography).
func deriveSeed(master []byte, label string, length int) string {
	const domain = "pqc-fixtures/v1 keygen seed"
	out := make([]byte, 0, length+sha256.Size)
	for counter := byte(1); len(out) < length; counter++ {
		h := sha256.New()
		h.Write([]byte(domain))
		h.Write([]byte{0})
		h.Write(master)
		h.Write([]byte{0})
		h.Write([]byte(label))
		h.Write([]byte{counter})
		out = h.Sum(out)
	}
	return hex.EncodeToString(out[:length])
}
