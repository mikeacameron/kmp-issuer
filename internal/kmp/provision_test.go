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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// escrowedKMP models the flow where Key Manager Plus owns the key: createCSR
// generates it, getCertificate returns a certificate for it, and exportCSR
// hands the key back.
type escrowedKMP struct {
	fake *fakeKMP
	pki  *testPKI
	key  *ecdsa.PrivateKey
}

func newEscrowedKMP(t *testing.T) *escrowedKMP {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the key Key Manager Plus would generate: %v", err)
	}
	escrow := &escrowedKMP{fake: newFakeKMP(t), pki: newTestPKI(t), key: key}

	escrow.fake.respond(opCreateCSR, `{"Status":"Success","Message":"CSR created successfully","CSR_ID":"304"}`)
	escrow.fake.respond(opSignCSR, `{"Status":"Success","commonName":"app.corp.example.com","serialNumber":"4242","Certificate_ID":"31"}`)
	escrow.fake.on(opGetCertificate, func(w http.ResponseWriter, _ *http.Request) {
		details := escrow.fake.requestFor(opCreateCSR).InputData
		leaf := escrow.issue(t, details)
		body, err := json.Marshal(map[string]any{
			"Status":  "Success",
			"Details": map[string]any{"certificate": pemString(leaf, escrow.pki.interCert, escrow.pki.rootCert)},
		})
		if err != nil {
			t.Errorf("building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
	escrow.fake.on(opExportCSR, func(w http.ResponseWriter, _ *http.Request) {
		der, err := x509.MarshalPKCS8PrivateKey(escrow.key)
		if err != nil {
			t.Errorf("marshalling the escrowed key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	return escrow
}

// issue mints the certificate Key Manager Plus would return, from the subject
// that was sent to createCSR.
func (e *escrowedKMP) issue(t *testing.T, details map[string]any) *x509.Certificate {
	t.Helper()

	text := func(key string) string {
		value, _ := details[key].(string)
		return value
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         text("CNAME"),
			Organization:       nonEmpty(text("ORG")),
			OrganizationalUnit: nonEmpty(text("ORGUNIT")),
			Locality:           nonEmpty(text("LOCATION")),
			Province:           nonEmpty(text("STATE")),
			Country:            nonEmpty(text("COUNTRY")),
		},
	}
	for _, name := range strings.Split(text("ALT_NAMES"), ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, name)
	}

	csr := &x509.CertificateRequest{PublicKey: e.key.Public()}
	return e.pki.issueAs(t, csr, 4242, template)
}

func nonEmpty(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func (e *escrowedKMP) signer(t *testing.T) *Signer {
	t.Helper()
	signer, err := NewSigner(e.fake.client(t), SigningOptions{
		ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func provisionRequest() ProvisionRequest {
	return ProvisionRequest{
		CommonName:         "app.corp.example.com",
		AltNames:           []string{"app.corp.example.com", "app.internal", "10.0.2.24"},
		Organization:       "Example Company Inc",
		OrganizationalUnit: "Platform Engineering",
		Location:           "Ottawa",
		State:              "Ontario",
		Country:            "CA",
		KeyAlgorithm:       "RSA",
		KeyLength:          2048,
		SignatureAlgorithm: "SHA256",
		StoreType:          "PKCS12",
		Password:           "s3cret-store-password",
	}
}

func TestProvision(t *testing.T) {
	escrow := newEscrowedKMP(t)

	provisioned, err := escrow.signer(t).Provision(context.Background(), provisionRequest())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Key Manager Plus was asked for the subject that was requested.
	details := escrow.fake.requestFor(opCreateCSR).InputData
	for key, want := range map[string]string{
		"CNAME":     "app.corp.example.com",
		"ALT_NAMES": "app.corp.example.com,app.internal,10.0.2.24",
		"ORG":       "Example Company Inc",
		"ORGUNIT":   "Platform Engineering",
		"LOCATION":  "Ottawa",
		"STATE":     "Ontario",
		"COUNTRY":   "CA",
		"ALG":       "RSA",
		"LEN":       "2048",
		"SIGALG":    "SHA256",
		"StoreType": "PKCS12",
		"PASSWORD":  "s3cret-store-password",
	} {
		if got := details[key]; got != want {
			t.Errorf("createCSR %s = %#v, want %q", key, got, want)
		}
	}

	// The export was asked for the key, by the id createCSR reported.
	export := escrow.fake.requestFor(opExportCSR).InputData
	if export["CSR_ID"] != "304" || export["fileType"] != FileTypePrivateKey {
		t.Errorf("exportCSR Details = %v, want the private key of CSR 304", export)
	}

	// The pair has to be usable together.
	if _, err := tlsPair(provisioned); err != nil {
		t.Errorf("the returned certificate and key are not a usable pair: %v", err)
	}
	if provisioned.CSRID != "304" || provisioned.SerialNumber != "4242" {
		t.Errorf("provisioned = %+v, want the Key Manager Plus identifiers", provisioned)
	}

	chain, err := parsePEMCertificates(provisioned.Bundle.ChainPEM)
	if err != nil {
		t.Fatalf("parsing the chain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain has %d certificates, want the leaf, the intermediate and the root", len(chain))
	}
	if got := chain[0].Subject.Organization; len(got) != 1 || got[0] != "Example Company Inc" {
		t.Errorf("organization = %v, want the one that was requested", got)
	}
	if len(chain[0].IPAddresses) != 1 || !chain[0].IPAddresses[0].Equal(net.ParseIP("10.0.2.24")) {
		t.Errorf("IP addresses = %v, want 10.0.2.24", chain[0].IPAddresses)
	}
}

// tlsPair checks that the certificate and the key belong together, the way a
// TLS server would.
func tlsPair(provisioned *ProvisionedCertificate) (bool, error) {
	block, _ := pem.Decode(provisioned.PrivateKeyPEM)
	if block == nil {
		return false, errNoPrivateKey
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false, err
	}
	if !(&PrivateKey{Key: key}).MatchesCertificate(provisioned.Bundle.Leaf) {
		return false, errNoPrivateKey
	}
	return true, nil
}

func TestProvisionRejectsAMismatchedKey(t *testing.T) {
	escrow := newEscrowedKMP(t)
	// The export returns a key that has nothing to do with the certificate.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	escrow.fake.on(opExportCSR, func(w http.ResponseWriter, _ *http.Request) {
		der, err := x509.MarshalPKCS8PrivateKey(other)
		if err != nil {
			t.Errorf("marshalling the key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})

	_, err = escrow.signer(t).Provision(context.Background(), provisionRequest())
	if err == nil {
		t.Fatal("Provision returned a certificate and key that do not match")
	}
	if !IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true", err)
	}
}

func TestProvisionRejectsAStrippedSubject(t *testing.T) {
	escrow := newEscrowedKMP(t)
	escrow.fake.on(opGetCertificate, func(w http.ResponseWriter, _ *http.Request) {
		leaf := escrow.pki.issueAs(t, &x509.CertificateRequest{PublicKey: escrow.key.Public()}, 4242,
			&x509.Certificate{Subject: pkix.Name{CommonName: "app01.ad.corp.example.com"}})
		body, err := json.Marshal(map[string]any{
			"Status":  "Success",
			"Details": map[string]any{"certificate": pemString(leaf, escrow.pki.interCert, escrow.pki.rootCert)},
		})
		if err != nil {
			t.Errorf("building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})

	_, err := escrow.signer(t).Provision(context.Background(), provisionRequest())
	if err == nil {
		t.Fatal("Provision accepted a certificate that drops the requested names")
	}
	for _, want := range []string{"app.corp.example.com", "10.0.2.24"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestProvisionValidatesTheRequest(t *testing.T) {
	escrow := newEscrowedKMP(t)
	signer := escrow.signer(t)

	withoutName := provisionRequest()
	withoutName.CommonName = ""
	if _, err := signer.Provision(context.Background(), withoutName); err == nil {
		t.Error("Provision accepted a request without a common name")
	}

	withoutPassword := provisionRequest()
	withoutPassword.Password = ""
	if _, err := signer.Provision(context.Background(), withoutPassword); err == nil {
		t.Error("Provision accepted a request without a key store password")
	}
	if len(escrow.fake.requests) != 0 {
		t.Errorf("an invalid request reached Key Manager Plus: %v", escrow.fake.requests)
	}
}

func TestExportCSRReportsAFailure(t *testing.T) {
	escrow := newEscrowedKMP(t)
	escrow.fake.on(opExportCSR, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Status":"Failed","Message":"Invalid password"}`)
	})

	_, err := escrow.signer(t).Provision(context.Background(), provisionRequest())
	if err == nil {
		t.Fatal("Provision succeeded although the export failed")
	}
	if !strings.Contains(err.Error(), "Invalid password") {
		t.Errorf("error %q does not report what Key Manager Plus said", err)
	}
}
