package kmp

import (
	"context"
	"crypto/x509"
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

	var issued *x509.Certificate
	fake.on(opImportCSR, func(w http.ResponseWriter, r *http.Request) {
		csrPEM := []byte(fake.requests[len(fake.requests)-1].CSR)
		csr, err := ParseCSR(csrPEM)
		if err != nil {
			t.Errorf("the uploaded CSR does not parse: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		issued = pki.issue(t, csr, 4242)
		_, _ = io.WriteString(w, `{"Status":"Success","Message":"CSR saved successfully","CSR_ID":"9"}`)
	})
	fake.respond(opSignCSR, `{"Status":"Success","commonName":"app.example.com","serialNumber":"4242","Certificate_ID":"31"}`)
	fake.on(opGetCertificate, func(w http.ResponseWriter, _ *http.Request) {
		certs := append([]*x509.Certificate{issued, pki.interCert, pki.rootCert}, extra...)
		body, err := json.Marshal(map[string]any{
			"Status":  "Success",
			"Details": map[string]any{"certificate": pemString(certs...)},
		})
		if err != nil {
			t.Fatalf("building the response: %v", err)
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

	chain, err := parsePEMCertificates(bundle.Certificate)
	if err != nil {
		t.Fatalf("parsing the issued chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain has %d certificates, want the leaf and one intermediate", len(chain))
	}
	if chain[0].Subject.CommonName != "app.example.com" {
		t.Errorf("chain[0] common name = %q, want the leaf", chain[0].Subject.CommonName)
	}
	if !chain[0].PublicKey.(publicKeyMatcher).Equal(csr.PublicKey) {
		t.Error("the leaf does not carry the public key of the request")
	}
	if chain[1].Subject.CommonName != "kmp-test-issuing-ca" {
		t.Errorf("chain[1] common name = %q, want the intermediate", chain[1].Subject.CommonName)
	}

	root, err := parsePEMCertificates(bundle.CA)
	if err != nil {
		t.Fatalf("parsing the CA: %v", err)
	}
	if len(root) != 1 || root[0].Subject.CommonName != "kmp-test-root" {
		t.Fatalf("CA = %v, want the root certificate", root)
	}

	// The leaf must verify against the returned chain.
	roots := x509.NewCertPool()
	roots.AddCert(root[0])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the issued certificate does not verify against the returned chain: %v", err)
	}
}

func TestSignerSignIgnoresUnrelatedCertificates(t *testing.T) {
	pki := newTestPKI(t)
	stranger := newTestPKI(t) // a second hierarchy that must not leak into the bundle
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
	chain, err := parsePEMCertificates(bundle.Certificate)
	if err != nil {
		t.Fatalf("parsing the issued chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain has %d certificates, want the leaf and one intermediate", len(chain))
	}
	want := []string{"app.example.com", "kmp-test-issuing-ca"}
	for i, cert := range chain {
		if cert.Subject.CommonName != want[i] {
			t.Errorf("chain[%d] common name = %q, want %q", i, cert.Subject.CommonName, want[i])
		}
	}
	if !strings.Contains(string(bundle.CA), "-----BEGIN CERTIFICATE-----") {
		t.Error("no root certificate was returned")
	}
	roots, err := parsePEMCertificates(bundle.CA)
	if err != nil {
		t.Fatalf("parsing the CA: %v", err)
	}
	if len(roots) != 1 || roots[0].Subject.CommonName != "kmp-test-root" {
		t.Errorf("CA = %v, want only the root of the issuing hierarchy", roots)
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
