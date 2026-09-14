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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// testPKI is a small CA hierarchy used to produce realistic API responses.
type testPKI struct {
	rootCert  *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	return newNamedTestPKI(t, "kmp-test")
}

// newNamedTestPKI builds a hierarchy whose subject names carry the given prefix,
// so that two independent hierarchies can be told apart in a test.
func newNamedTestPKI(t *testing.T, prefix string) *testPKI {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: prefix + "-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	rootCert := mustCreateCert(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: prefix + "-issuing-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	interCert := mustCreateCert(t, interTemplate, rootCert, &interKey.PublicKey, rootKey)

	return &testPKI{rootCert: rootCert, rootKey: rootKey, interCert: interCert, interKey: interKey}
}

// issue signs csr with the intermediate CA, as Key Manager Plus would.
func (p *testPKI) issue(t *testing.T, csr *x509.CertificateRequest, serial int64) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return mustCreateCert(t, template, p.interCert, csr.PublicKey, p.interKey)
}

func mustCreateCert(t *testing.T, template, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", template.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing created certificate: %v", err)
	}
	return cert
}

// newTestCSR returns a PEM encoded CSR and its parsed form.
func newTestCSR(t *testing.T, commonName string, dnsNames ...string) ([]byte, *x509.CertificateRequest) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), csr
}

func pemString(certs ...*x509.Certificate) string {
	return string(encodeCertificates(certs...))
}

// newDetailedTestCSR returns the kind of request cert-manager builds from a
// Certificate that names an organization, an organizational unit, a location
// and IP addresses, so that the subject can be followed end to end.
func newDetailedTestCSR(t *testing.T) ([]byte, *x509.CertificateRequest) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "app.corp.example.com",
			Organization:       []string{"Example Company Inc"},
			OrganizationalUnit: []string{"Platform Engineering"},
			Locality:           []string{"Ottawa"},
			Province:           []string{"Ontario"},
			Country:            []string{"CA"},
		},
		DNSNames:    []string{"app.corp.example.com", "app.internal"},
		IPAddresses: []net.IP{net.ParseIP("10.0.2.24"), net.ParseIP("192.168.10.5")},
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), csr
}
