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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func mustMarshalPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	return der
}

func TestParseExportedPrivateKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating an EC key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an RSA key: %v", err)
	}
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshalling the EC key: %v", err)
	}

	jsonWrapped, err := json.Marshal(map[string]any{
		"Status":  "Success",
		"Details": map[string]any{"privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, ecKey)}))},
	})
	if err != nil {
		t.Fatalf("building the response: %v", err)
	}

	tests := []struct {
		name     string
		export   []byte
		password string
	}{
		{
			name:   "PKCS#8 PEM",
			export: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, ecKey)}),
		},
		{
			name:   "PKCS#1 RSA PEM",
			export: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}),
		},
		{
			name:   "SEC 1 EC PEM",
			export: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecSEC1}),
		},
		{
			name:   "bare base64 DER",
			export: []byte(base64.StdEncoding.EncodeToString(mustMarshalPKCS8(t, ecKey))),
		},
		{
			name:   "wrapped in a JSON envelope",
			export: jsonWrapped,
		},
		{
			name:   "PEM with a leading message",
			export: append([]byte("Private key exported successfully\n"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, ecKey)})...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseExportedPrivateKey(tc.export, tc.password)
			if err != nil {
				t.Fatalf("ParseExportedPrivateKey: %v", err)
			}
			if !strings.Contains(string(key.PEM), "-----BEGIN PRIVATE KEY-----") {
				t.Errorf("the key was not normalised to a PKCS#8 PEM block: %q", key.PEM)
			}
			// The normalised form must parse back to the same key.
			block, _ := pem.Decode(key.PEM)
			if block == nil {
				t.Fatal("the normalised key is not PEM")
			}
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				t.Errorf("the normalised key does not parse: %v", err)
			}
		})
	}
}

func TestParseExportedPrivateKeyEncrypted(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	//nolint:staticcheck // Exercising the legacy encryption Key Manager Plus emits.
	block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", mustMarshalPKCS8(t, ecKey), []byte("s3cret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypting the key: %v", err)
	}
	encrypted := pem.EncodeToMemory(block)

	if _, err := ParseExportedPrivateKey(encrypted, "s3cret"); err != nil {
		t.Errorf("ParseExportedPrivateKey with the right password: %v", err)
	}
	if _, err := ParseExportedPrivateKey(encrypted, "wrong"); err == nil {
		t.Error("ParseExportedPrivateKey succeeded with the wrong password")
	}
	if _, err := ParseExportedPrivateKey(encrypted, ""); err == nil {
		t.Error("ParseExportedPrivateKey succeeded without a password")
	}
}

func TestParseExportedPrivateKeyRejectsKeyStores(t *testing.T) {
	jks := append([]byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02}, make([]byte, 64)...)
	_, err := ParseExportedPrivateKey(jks, "s3cret")
	if err == nil {
		t.Fatal("ParseExportedPrivateKey accepted a Java key store")
	}
	if !strings.Contains(err.Error(), "PrivateKey file type") {
		t.Errorf("error %q does not say how to get a usable export", err)
	}
}

func TestParseExportedPrivateKeyRejectsRubbish(t *testing.T) {
	for _, export := range [][]byte{nil, []byte(""), []byte("no key here"), []byte(`{"Status":"Success"}`)} {
		if _, err := ParseExportedPrivateKey(export, ""); err == nil {
			t.Errorf("ParseExportedPrivateKey(%q) succeeded, want an error", export)
		}
	}
}

func TestPrivateKeyMatchesCertificate(t *testing.T) {
	pki := newTestPKI(t)
	csrPEM, csr := newTestCSR(t, "app.example.com")
	_ = csrPEM
	leaf := pki.issue(t, csr, 9)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	mismatched := &PrivateKey{Key: other}
	if mismatched.MatchesCertificate(leaf) {
		t.Error("MatchesCertificate accepted a key that did not sign the certificate")
	}
}
