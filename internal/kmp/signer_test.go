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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSigningOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    SigningOptions
		wantErr string
	}{
		{
			name: "microsoft CA is complete",
			opts: SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"},
		},
		{
			name:    "microsoft CA misses the template",
			opts:    SigningOptions{SignType: SignTypeMSCA, ServerName: "ca1", CAName: "ca1-ca"},
			wantErr: "signing.templateName",
		},
		{
			name:    "agent signing misses the agent",
			opts:    SigningOptions{SignType: SignTypeMSCAUsingAgent, ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"},
			wantErr: "signing.agentName",
		},
		{
			name: "root signing is complete",
			opts: SigningOptions{SignType: SignTypeWithRoot, RootCertificateCommonName: "root"},
		},
		{
			name:    "root signing misses the root",
			opts:    SigningOptions{SignType: SignTypeWithRoot},
			wantErr: "signing.rootCertificateCommonName",
		},
		{
			name:    "unknown sign type",
			opts:    SigningOptions{SignType: "LetsEncrypt"},
			wantErr: "unknown signType",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate succeeded, want an error mentioning %q", tc.wantErr)
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error %v does not wrap ErrInvalidConfig", err)
			}
			if !IsPermanent(err) {
				t.Errorf("IsPermanent(%v) = false, want true", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// serveSigning wires a fake Key Manager Plus that signs with the test PKI.
func serveSigning(t *testing.T, fake *fakeKMP, pki *testPKI, extra ...*x509.Certificate) {
	t.Helper()

	fake.respond(opImportCSR, `{"Status":"Success","Message":"CSR saved successfully","CSR_ID":"9"}`)
	fake.respond(opSignCSR, `{"Status":"Success","commonName":"app.example.com","serialNumber":"4242","Certificate_ID":"31"}`)
	// The certificate is minted from the CSR that was uploaded, so that a test
	// may replace the importCSR response without losing the signing behaviour.
	fake.on(opGetCertificate, func(w http.ResponseWriter, _ *http.Request) {
		csr, err := ParseCSR([]byte(fake.uploadedCSR()))
		if err != nil {
			t.Errorf("the uploaded CSR does not parse: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		certs := append([]*x509.Certificate{pki.issue(t, csr, 4242), pki.interCert, pki.rootCert}, extra...)
		body, err := json.Marshal(map[string]any{
			"Status":  "Success",
			"Details": map[string]any{"certificate": pemString(certs...)},
		})
		if err != nil {
			t.Errorf("building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
}

func TestSignerSign(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)

	signer, err := NewSigner(fake.client(t), SigningOptions{
		ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer", Email: "pki@example.com",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, csr := newTestCSR(t, "app.example.com", "app.example.com")
	bundle, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	chain, err := parsePEMCertificates(bundle.ChainPEM)
	if err != nil {
		t.Fatalf("parsing the issued chain: %v", err)
	}
	// The chain is ordered leaf first and ends at the root; cert-manager splits
	// the root off into the CA of the issued Secret.
	want := []string{"app.example.com", "kmp-test-issuing-ca", "kmp-test-root"}
	if len(chain) != len(want) {
		t.Fatalf("chain has %d certificates, want %d", len(chain), len(want))
	}
	for i, cert := range chain {
		if cert.Subject.CommonName != want[i] {
			t.Errorf("chain[%d] common name = %q, want %q", i, cert.Subject.CommonName, want[i])
		}
	}
	if !chain[0].PublicKey.(publicKeyMatcher).Equal(csr.PublicKey) {
		t.Error("the leaf does not carry the public key of the request")
	}

	// The leaf must verify against the returned chain.
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the issued certificate does not verify against the returned chain: %v", err)
	}
}

func TestSignerSignIgnoresUnrelatedCertificates(t *testing.T) {
	pki := newTestPKI(t)
	stranger := newNamedTestPKI(t, "stranger") // a second hierarchy that must not leak into the bundle
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki, stranger.rootCert, stranger.interCert)

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newTestCSR(t, "app.example.com")
	bundle, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	chain, err := parsePEMCertificates(bundle.ChainPEM)
	if err != nil {
		t.Fatalf("parsing the issued chain: %v", err)
	}
	// Only the chain of the issued certificate may appear: a second hierarchy
	// in the response would make the bundle unparsable as a single chain.
	want := []string{"app.example.com", "kmp-test-issuing-ca", "kmp-test-root"}
	if len(chain) != len(want) {
		t.Fatalf("chain has %d certificates, want %d", len(chain), len(want))
	}
	for i, cert := range chain {
		if cert.Subject.CommonName != want[i] {
			t.Errorf("chain[%d] common name = %q, want %q", i, cert.Subject.CommonName, want[i])
		}
	}
}

func TestSignerSignRejectsAForeignCertificate(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	fake.respond(opImportCSR, `{"Status":"Success","CSR_ID":"9"}`)
	fake.respond(opSignCSR, `{"Status":"Success","commonName":"app.example.com","serialNumber":"1"}`)

	// Key Manager Plus answers with a certificate for a different key.
	_, otherCSR := newTestCSR(t, "other.example.com")
	other := pki.issue(t, otherCSR, 77)
	fake.respond(opGetCertificate, fmt.Sprintf(`{"Status":"Success","Details":{"certificate":%q}}`, pemString(other, pki.interCert, pki.rootCert)))

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	csrPEM, _ := newTestCSR(t, "app.example.com")
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM}); err == nil {
		t.Fatal("Sign succeeded with a certificate for another key, want an error")
	}
}

func TestSignerSignRejectsAnUnparsableCSR(t *testing.T) {
	fake := newFakeKMP(t)
	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	_, err = signer.Sign(context.Background(), Request{CSRPEM: []byte("not a CSR")})
	if err == nil {
		t.Fatal("Sign succeeded on a malformed request, want an error")
	}
	if !IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true", err)
	}
	if len(fake.requests) != 0 {
		t.Errorf("the malformed request reached key manager plus: %v", fake.requests)
	}
}

func TestSignerRootSigningUsesTheRequestedDuration(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)

	signer, err := NewSigner(fake.client(t), SigningOptions{
		SignType:                  SignTypeWithRoot,
		RootCertificateCommonName: "kmp-test-root",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newTestCSR(t, "app.example.com")
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM, Duration: 90 * 24 * time.Hour, IsCA: true}); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	details := fake.requestFor(opSignCSR).InputData
	if details["Validity"] != "90" {
		t.Errorf("Validity = %#v, want \"90\"", details["Validity"])
	}
	if details["isIntermediate"] != true {
		t.Errorf("isIntermediate = %#v, want true", details["isIntermediate"])
	}
	if details["rootCertificateCommonName"] != "kmp-test-root" {
		t.Errorf("rootCertificateCommonName = %#v, want the configured root", details["rootCertificateCommonName"])
	}
}

func TestSignerRootSigningPrefersTheIssuerValidity(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)

	validity := int32(30)
	signer, err := NewSigner(fake.client(t), SigningOptions{
		SignType:                  SignTypeWithRoot,
		RootCertificateCommonName: "kmp-test-root",
		ValidityDays:              &validity,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newTestCSR(t, "app.example.com")
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM, Duration: 90 * 24 * time.Hour}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := fake.requestFor(opSignCSR).InputData["Validity"]; got != "30" {
		t.Errorf("Validity = %#v, want the issuer setting \"30\"", got)
	}
}

func TestSignerWaitsForTheCertificate(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)

	// The first lookup finds nothing, as it can while the CA publishes the
	// certificate; the second succeeds.
	published := fake.handlers[opGetCertificate]
	attempts := 0
	fake.on(opGetCertificate, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			_, _ = io.WriteString(w, `{"Status":"Success","Details":[]}`)
			return
		}
		published(w, r)
	})

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signer.PollInterval = 10 * time.Millisecond
	signer.PollTimeout = 2 * time.Second

	csrPEM, _ := newTestCSR(t, "app.example.com")
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if attempts != 2 {
		t.Errorf("getCertificate was called %d times, want 2", attempts)
	}
}

func TestSignerGivesUpWhenTheCertificateNeverAppears(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)
	fake.respond(opGetCertificate, `{"Status":"Success","Details":[]}`)

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signer.PollInterval = 5 * time.Millisecond
	signer.PollTimeout = 30 * time.Millisecond

	csrPEM, _ := newTestCSR(t, "app.example.com")
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM}); err == nil {
		t.Fatal("Sign succeeded without a certificate, want an error")
	}
}

func TestSignerHonoursContextCancellation(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)
	fake.respond(opGetCertificate, `{"Status":"Success","Details":[]}`)

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signer.PollInterval = 50 * time.Millisecond
	signer.PollTimeout = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	csrPEM, _ := newTestCSR(t, "app.example.com")
	start := time.Now()
	if _, err := signer.Sign(ctx, Request{CSRPEM: csrPEM}); err == nil {
		t.Fatal("Sign succeeded, want a cancellation error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Sign returned after %s, want it to stop when the context expired", elapsed)
	}
}

func TestSignerResolvesTheCSRIDByLookup(t *testing.T) {
	const lookupOperation = "getCSRs"

	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)
	// The documented import response reports no id, so it has to be looked up.
	fake.respond(opImportCSR, `{"result":{"message":"CSR app.example.com imported successfully.","status":"Success"},"name":"importCSR"}`)
	fake.respond(lookupOperation, `{"Status":"Success","Details":[{"CSR_ID":"512","commonName":"app.example.com"}]}`)

	signer, err := NewSigner(fake.client(t), SigningOptions{
		ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer",
		CSRLookupOperation: lookupOperation,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newTestCSR(t, "app.example.com")
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := fake.requestFor(opSignCSR).InputData["CSR_ID"]; got != "512" {
		t.Errorf("CSR_ID = %#v, want the id from the lookup", got)
	}
}

func TestSignerExplainsAMissingCSRID(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)
	fake.respond(opImportCSR, `{"result":{"message":"CSR app.example.com imported successfully.","status":"Success"},"name":"importCSR"}`)

	signer, err := NewSigner(fake.client(t), SigningOptions{
		ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newTestCSR(t, "app.example.com")
	_, err = signer.Sign(context.Background(), Request{CSRPEM: csrPEM})
	if err == nil {
		t.Fatal("Sign succeeded without a CSR id, want an error")
	}
	if !IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true: retrying cannot find the id", err)
	}
	for _, want := range []string{"csrLookupOperation", "imported successfully"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	// Signing must not be attempted with an empty id.
	for _, req := range fake.requests {
		if req.Path == opSignCSR {
			t.Error("signCSR was called although the CSR id is unknown")
		}
	}
}

func TestSignerCarriesTheFullSubjectToTheCertificate(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)

	signer, err := NewSigner(fake.client(t), SigningOptions{
		ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, csr := newDetailedTestCSR(t)
	bundle, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	chain, err := parsePEMCertificates(bundle.ChainPEM)
	if err != nil {
		t.Fatalf("parsing the issued chain: %v", err)
	}
	leaf := chain[0]
	if leaf.Subject.CommonName != csr.Subject.CommonName {
		t.Errorf("common name = %q, want %q", leaf.Subject.CommonName, csr.Subject.CommonName)
	}
	if strings.Join(leaf.Subject.Organization, ",") != strings.Join(csr.Subject.Organization, ",") {
		t.Errorf("organization = %v, want %v", leaf.Subject.Organization, csr.Subject.Organization)
	}
	if strings.Join(leaf.Subject.OrganizationalUnit, ",") != strings.Join(csr.Subject.OrganizationalUnit, ",") {
		t.Errorf("organizational unit = %v, want %v", leaf.Subject.OrganizationalUnit, csr.Subject.OrganizationalUnit)
	}
	if strings.Join(leaf.Subject.Country, ",") != strings.Join(csr.Subject.Country, ",") {
		t.Errorf("country = %v, want %v", leaf.Subject.Country, csr.Subject.Country)
	}
	if len(leaf.IPAddresses) != len(csr.IPAddresses) {
		t.Fatalf("%d IP addresses in the certificate, want %d", len(leaf.IPAddresses), len(csr.IPAddresses))
	}
	for i, ip := range csr.IPAddresses {
		if !leaf.IPAddresses[i].Equal(ip) {
			t.Errorf("IP address %d = %s, want %s", i, leaf.IPAddresses[i], ip)
		}
	}
}

// serveIssuedCertificate answers getCertificate with a certificate the caller
// shapes from the uploaded CSR.
func serveIssuedCertificate(t *testing.T, fake *fakeKMP, pki *testPKI, shape func(*x509.CertificateRequest) *x509.Certificate) {
	t.Helper()
	fake.on(opGetCertificate, func(w http.ResponseWriter, _ *http.Request) {
		csr, err := ParseCSR([]byte(fake.uploadedCSR()))
		if err != nil {
			t.Errorf("the uploaded CSR does not parse: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		issued := pki.issueAs(t, csr, 4242, shape(csr))
		body, err := json.Marshal(map[string]any{
			"Status":  "Success",
			"Details": map[string]any{"certificate": pemString(issued, pki.interCert, pki.rootCert)},
		})
		if err != nil {
			t.Errorf("building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
}

func TestSignerRefusesACertificateMissingRequestedNames(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)
	// A Microsoft CA template that builds the subject from Active Directory
	// drops the common name and the SANs the request asked for.
	serveIssuedCertificate(t, fake, pki, func(*x509.CertificateRequest) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: "app01.ad.corp.example.com"}}
	})

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newDetailedTestCSR(t)
	_, err = signer.Sign(context.Background(), Request{CSRPEM: csrPEM})
	if err == nil {
		t.Fatal("Sign published a certificate that does not carry the requested names, want an error")
	}
	if !IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true: retrying cannot change the template", err)
	}
	for _, want := range []string{"app.corp.example.com", "10.0.2.24", "supply them from the request"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestSignerAcceptsExtraAndDifferentlyCasedNames(t *testing.T) {
	pki := newTestPKI(t)
	fake := newFakeKMP(t)
	serveSigning(t, fake, pki)
	// A CA may upper-case host names and add names of its own; neither loses
	// anything the request asked for.
	serveIssuedCertificate(t, fake, pki, func(csr *x509.CertificateRequest) *x509.Certificate {
		upper := make([]string, 0, len(csr.DNSNames)+1)
		for _, name := range csr.DNSNames {
			upper = append(upper, strings.ToUpper(name))
		}
		upper = append(upper, "added-by-the-ca.example.com")
		return &x509.Certificate{
			Subject:     csr.Subject,
			DNSNames:    upper,
			IPAddresses: csr.IPAddresses,
		}
	})

	signer, err := NewSigner(fake.client(t), SigningOptions{ServerName: "ca1", CAName: "ca1-ca", TemplateName: "WebServer"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	csrPEM, _ := newDetailedTestCSR(t)
	if _, err := signer.Sign(context.Background(), Request{CSRPEM: csrPEM}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestVerifyRequestedNames(t *testing.T) {
	pki := newTestPKI(t)
	csrPEM, csr := newDetailedTestCSR(t)
	_ = csrPEM

	t.Run("everything requested is present", func(t *testing.T) {
		leaf := pki.issue(t, csr, 1)
		if err := verifyRequestedNames(csr, leaf); err != nil {
			t.Errorf("verifyRequestedNames: %v", err)
		}
	})

	t.Run("one IP address is dropped", func(t *testing.T) {
		leaf := pki.issueAs(t, csr, 2, &x509.Certificate{
			Subject:     csr.Subject,
			DNSNames:    csr.DNSNames,
			IPAddresses: csr.IPAddresses[:1],
		})
		err := verifyRequestedNames(csr, leaf)
		if err == nil {
			t.Fatal("verifyRequestedNames accepted a certificate missing an IP address")
		}
		if !strings.Contains(err.Error(), csr.IPAddresses[1].String()) {
			t.Errorf("error %q does not name the missing IP address", err)
		}
	})

	t.Run("the common name is replaced", func(t *testing.T) {
		leaf := pki.issueAs(t, csr, 3, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "something.else"},
			DNSNames:    csr.DNSNames,
			IPAddresses: csr.IPAddresses,
		})
		err := verifyRequestedNames(csr, leaf)
		if err == nil {
			t.Fatal("verifyRequestedNames accepted a rewritten common name")
		}
		if !strings.Contains(err.Error(), "something.else") {
			t.Errorf("error %q does not report the common name that was issued", err)
		}
	})
}
