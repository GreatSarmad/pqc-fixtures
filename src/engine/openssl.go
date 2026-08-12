package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// This file is the engine adapter proper (design-dossier §7): the only place in
// the codebase that knows the OpenSSL command line. Everything above it works
// in terms of keys, CSRs and certificates. Nothing here decides *what* to
// generate - that is the core's job (src/gen).
//
// Two invariants hold for every invocation:
//
//  1. OPENSSL_CONF=/dev/null, so a stray system openssl.cnf can never change
//     what we emit (ADR-008 part 3).
//  2. No argument is ever a URL or a hostname. The tool is offline by
//     construction (design-dossier §8 criterion 5).

// KeyRequest describes one key to generate.
type KeyRequest struct {
	// Algorithm is the engine's algorithm name, e.g. "ML-DSA-65".
	Algorithm string
	// OutPath is where the PKCS#8 PEM private key is written.
	OutPath string
	// SeedHex, when non-empty, requests deterministic keygen from that seed
	// (ADR-002). The caller is responsible for supplying a seed of the length
	// the algorithm family requires; the engine rejects any other length.
	SeedHex string
}

// CertRequest describes one certificate to issue. When CAKeyPath is empty the
// certificate is self-signed with KeyPath (a root); otherwise KeyPath's public
// key is certified by the CA.
type CertRequest struct {
	// KeyPath is the subject's private key.
	KeyPath string
	// Subject is an OpenSSL subject string, e.g. "/O=.../CN=...".
	Subject string
	// Days is the validity period in days from now.
	Days int
	// SerialHex is the certificate serial as hex digits, without a 0x prefix.
	SerialHex string
	// Extensions are OpenSSL extension lines, e.g.
	// "basicConstraints=critical,CA:true".
	Extensions []string
	// CACertPath and CAKeyPath name the issuer. Empty for a self-signed root.
	CACertPath string
	CAKeyPath  string
	// OutPath is where the PEM certificate is written.
	OutPath string
}

// GenerateKey runs `openssl genpkey`.
func (e *Engine) GenerateKey(ctx context.Context, req KeyRequest) error {
	args := []string{"genpkey", "-algorithm", req.Algorithm, "-out", req.OutPath}
	if req.SeedHex != "" {
		args = append(args, "-pkeyopt", "hexseed:"+req.SeedHex)
	}
	_, err := e.run(ctx, args...)
	return err
}

// IssueCert issues one certificate, self-signed or CA-signed.
func (e *Engine) IssueCert(ctx context.Context, req CertRequest) error {
	if req.CAKeyPath == "" {
		return e.selfSign(ctx, req)
	}
	return e.caSign(ctx, req)
}

// selfSign runs `openssl req -x509`, which generates and signs in one step.
func (e *Engine) selfSign(ctx context.Context, req CertRequest) error {
	args := []string{
		"req", "-x509", "-new",
		"-key", req.KeyPath,
		"-out", req.OutPath,
		"-days", fmt.Sprint(req.Days),
		"-set_serial", "0x" + req.SerialHex,
		"-subj", req.Subject,
	}
	for _, ext := range req.Extensions {
		args = append(args, "-addext", ext)
	}
	_, err := e.run(ctx, args...)
	return err
}

// caSign runs `openssl req -new` to build a CSR, then `openssl x509 -req` to
// certify it. Extensions come from a temp file rather than the CSR:
// -copy_extensions none guarantees a CSR can never smuggle an extension we did
// not ask for.
func (e *Engine) caSign(ctx context.Context, req CertRequest) error {
	dir := filepath.Dir(req.OutPath)
	csrPath := filepath.Join(dir, filepath.Base(req.OutPath)+".csr")
	defer os.Remove(csrPath)

	if _, err := e.run(ctx,
		"req", "-new",
		"-key", req.KeyPath,
		"-out", csrPath,
		"-subj", req.Subject,
	); err != nil {
		return err
	}

	extPath := filepath.Join(dir, filepath.Base(req.OutPath)+".ext")
	defer os.Remove(extPath)
	extensions := strings.Join(req.Extensions, "\n") + "\n"
	if err := os.WriteFile(extPath, []byte(extensions), 0o600); err != nil {
		return fmt.Errorf("writing extension file: %w", err)
	}

	_, err := e.run(ctx,
		"x509", "-req",
		"-in", csrPath,
		"-CA", req.CACertPath,
		"-CAkey", req.CAKeyPath,
		"-out", req.OutPath,
		"-days", fmt.Sprint(req.Days),
		"-set_serial", "0x"+req.SerialHex,
		"-copy_extensions", "none",
		"-extfile", extPath,
	)
	return err
}

// ConvertCert re-encodes a PEM certificate as DER.
func (e *Engine) ConvertCert(ctx context.Context, pemPath, derPath string) error {
	_, err := e.run(ctx, "x509", "-in", pemPath, "-outform", "DER", "-out", derPath)
	return err
}

// ConvertKey re-encodes a PEM private key as DER (PKCS#8).
func (e *Engine) ConvertKey(ctx context.Context, pemPath, derPath string) error {
	_, err := e.run(ctx, "pkey", "-in", pemPath, "-outform", "DER", "-out", derPath)
	return err
}

// PublicKey writes the SubjectPublicKeyInfo of a private key as PEM.
func (e *Engine) PublicKey(ctx context.Context, keyPath, outPath string) error {
	_, err := e.run(ctx, "pkey", "-in", keyPath, "-pubout", "-out", outPath)
	return err
}

// VerifyChain runs `openssl verify` with an explicit trust anchor - the
// generated root, never a system store. It is the executable form of
// design-dossier §8 criterion 2.
func (e *Engine) VerifyChain(ctx context.Context, rootPath string, untrusted []string, leafPath string) error {
	args := []string{"verify", "-CAfile", rootPath}
	for _, u := range untrusted {
		args = append(args, "-untrusted", u)
	}
	args = append(args, leafPath)
	_, err := e.run(ctx, args...)
	return err
}

// run executes the engine and returns its stdout. Diagnostics are folded into
// the error because a failed subprocess with a swallowed stderr is the least
// debuggable failure this tool can produce.
func (e *Engine) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, e.Path, args...)
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("engine %s: %w\ncommand: openssl %s\n%s",
			filepath.Base(e.Path), err, strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
