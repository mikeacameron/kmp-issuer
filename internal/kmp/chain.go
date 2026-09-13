/*
Copyright 2026 The kmp-issuer Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kmp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// pemCertificateType is the PEM block type of an X.509 certificate.
const pemCertificateType = "CERTIFICATE"

// Bundle is the issued certificate together with the chain that validates it.
type Bundle struct {
	// ChainPEM is the issued certificate followed by the certificates that
	// validate it, PEM encoded, leaf first and ending at the root when Key
	// Manager Plus returned one.
	//
	// cert-manager splits this into the certificate chain and the CA with
	// pki.ParseSingleCertificateChainPEM, which rejects a bundle that is not a
	// single chain. BuildBundle therefore returns only the certificates that
	// form the chain of the issued certificate.
	ChainPEM []byte
}

// certificatesFromStrings extracts every distinct X.509 certificate found in
// the given strings, accepting both PEM blocks and bare base64 encoded DER.
// Strings that hold no certificate are skipped, so the whole response body can
// be handed in without knowing which field carries the payload.
func certificatesFromStrings(values []string) ([]*x509.Certificate, error) {
	var (
		certs    []*x509.Certificate
		seen     = map[string]struct{}{}
		firstErr error
	)

	add := func(cert *x509.Certificate) {
		key := string(cert.Raw)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		certs = append(certs, cert)
	}

	for _, value := range values {
		if strings.Contains(value, "-----BEGIN") {
			parsed, err := parsePEMCertificates([]byte(value))
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for _, cert := range parsed {
				add(cert)
			}
			continue
		}
		if cert, ok := parseBase64Certificate(value); ok {
			add(cert)
		}
	}

	if len(certs) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return certs, nil
}

// parsePEMCertificates parses every CERTIFICATE block in a PEM document. Other
// block types, such as the private key some Key Manager Plus exports include,
// are ignored.
func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemCertificateType {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseBase64Certificate tries to read a bare base64 encoded DER certificate,
// tolerating the line breaks Key Manager Plus inserts.
func parseBase64Certificate(value string) (*x509.Certificate, bool) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		}
		return r
	}, value)
	// A DER encoded certificate is never this short; skipping small strings
	// keeps the scan from decoding identifiers and messages.
	if len(compact) < 128 {
		return nil, false
	}
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	return cert, true
}

// publicKeyMatcher is implemented by the public key types crypto/x509 returns.
type publicKeyMatcher interface {
	Equal(crypto.PublicKey) bool
}

// BuildBundle picks the certificate issued for csrPublicKey out of certs and
// orders the chain above it, leaf first. Certificates in the input that are not
// part of that chain are dropped, so unrelated entries in a Key Manager Plus
// response cannot leak into the issued bundle.
func BuildBundle(certs []*x509.Certificate, csrPublicKey crypto.PublicKey) (*Bundle, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates to build a chain from")
	}

	leaf, err := findLeaf(certs, csrPublicKey)
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{leaf}
	remaining := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if !bytes.Equal(cert.Raw, leaf.Raw) {
			remaining = append(remaining, cert)
		}
	}

	current := leaf
	for len(remaining) > 0 {
		issuer, rest := popIssuer(remaining, current)
		if issuer == nil {
			break
		}
		chain = append(chain, issuer)
		remaining = rest
		current = issuer
		if isSelfSigned(issuer) {
			break
		}
	}

	return &Bundle{ChainPEM: encodeCertificates(chain...)}, nil
}

// findLeaf returns the certificate carrying the public key of the CSR.
func findLeaf(certs []*x509.Certificate, csrPublicKey crypto.PublicKey) (*x509.Certificate, error) {
	if csrPublicKey == nil {
		return certs[0], nil
	}
	matcher, ok := csrPublicKey.(publicKeyMatcher)
	if !ok {
		return certs[0], nil
	}
	for _, cert := range certs {
		if matcher.Equal(cert.PublicKey) {
			return cert, nil
		}
	}
	return nil, errors.New("none of the returned certificates matches the public key of the request")
}

// popIssuer finds the certificate that signed child and returns it along with
// the remaining candidates.
func popIssuer(candidates []*x509.Certificate, child *x509.Certificate) (*x509.Certificate, []*x509.Certificate) {
	for i, candidate := range candidates {
		if !bytes.Equal(candidate.RawSubject, child.RawIssuer) {
			continue
		}
		if child.CheckSignatureFrom(candidate) != nil {
			continue
		}
		rest := make([]*x509.Certificate, 0, len(candidates)-1)
		rest = append(rest, candidates[:i]...)
		rest = append(rest, candidates[i+1:]...)
		return candidate, rest
	}
	return nil, candidates
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
}

// encodeCertificates PEM encodes certificates in the given order.
func encodeCertificates(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: pemCertificateType, Bytes: cert.Raw})
	}
	return buf.Bytes()
}

// ParseCSR decodes a PEM encoded certificate signing request and checks its
// self-signature, which is what a CA does before accepting it.
func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("the request is not PEM encoded")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected a CERTIFICATE REQUEST PEM block, got %q", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("checking the signature of the certificate request: %w", err)
	}
	return csr, nil
}
