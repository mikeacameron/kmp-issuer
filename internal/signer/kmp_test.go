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

package signer

import (
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kmpissuerapi "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

func validSpec() *kmpissuerapi.IssuerSpec {
	return &kmpissuerapi.IssuerSpec{
		URL:            "https://kmp.example.com:6565",
		AuthSecretName: "kmp-credentials",
		Signing: kmpissuerapi.SigningSpec{
			SignType:     kmpissuerapi.SignTypeMSCA,
			ServerName:   "ca1",
			CAName:       "ca1-ca",
			TemplateName: "WebServer",
		},
	}
}

func validSecretData() map[string][]byte {
	return map[string][]byte{kmpissuerapi.AuthSecretTokenKey: []byte("A3164150-4C15-4AA4-918E-F258F38149F8")}
}

func TestSignerFromIssuerAndSecretData(t *testing.T) {
	tests := []struct {
		name       string
		spec       func() *kmpissuerapi.IssuerSpec
		secretData map[string][]byte
		wantErr    string
	}{
		{
			name:       "complete configuration",
			spec:       validSpec,
			secretData: validSecretData(),
		},
		{
			name:       "auth token missing from the Secret",
			spec:       validSpec,
			secretData: map[string][]byte{"wrong-key": []byte("token")},
			wantErr:    kmpissuerapi.AuthSecretTokenKey,
		},
		{
			name:       "auth token is blank",
			spec:       validSpec,
			secretData: map[string][]byte{kmpissuerapi.AuthSecretTokenKey: []byte("  \n")},
			wantErr:    kmpissuerapi.AuthSecretTokenKey,
		},
		{
			name: "URL is not usable",
			spec: func() *kmpissuerapi.IssuerSpec {
				spec := validSpec()
				spec.URL = "kmp.example.com:6565"
				return spec
			},
			secretData: validSecretData(),
			wantErr:    "http or https",
		},
		{
			name: "microsoft CA signing misses the template",
			spec: func() *kmpissuerapi.IssuerSpec {
				spec := validSpec()
				spec.Signing.TemplateName = ""
				return spec
			},
			secretData: validSecretData(),
			wantErr:    "signing.templateName",
		},
		{
			name: "root signing misses the root certificate",
			spec: func() *kmpissuerapi.IssuerSpec {
				spec := validSpec()
				spec.Signing = kmpissuerapi.SigningSpec{SignType: kmpissuerapi.SignTypeWithRoot}
				return spec
			},
			secretData: validSecretData(),
			wantErr:    "signing.rootCertificateCommonName",
		},
		{
			name: "CA bundle in the Secret is not PEM",
			spec: validSpec,
			secretData: map[string][]byte{
				kmpissuerapi.AuthSecretTokenKey:    []byte("token"),
				kmpissuerapi.AuthSecretCABundleKey: []byte("not a certificate"),
			},
			wantErr: "CA bundle",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signerFromIssuerAndSecretData(tc.spec(), tc.secretData)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("signerFromIssuerAndSecretData: %v", err)
				}
				if got == nil || got.client == nil || got.signer == nil {
					t.Fatal("the signer was not fully built")
				}
				return
			}
			if err == nil {
				t.Fatalf("signerFromIssuerAndSecretData succeeded, want an error mentioning %q", tc.wantErr)
			}
			if !errors.Is(err, kmp.ErrInvalidConfig) {
				t.Errorf("error %v does not wrap ErrInvalidConfig, so it would be retried forever", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildersReturnUsableInterfaces(t *testing.T) {
	checker, err := KMPHealthCheckerFromIssuerAndSecretData(validSpec(), validSecretData())
	if err != nil {
		t.Fatalf("KMPHealthCheckerFromIssuerAndSecretData: %v", err)
	}
	if checker == nil {
		t.Error("no health checker was returned")
	}

	kmpSigner, err := KMPSignerFromIssuerAndSecretData(validSpec(), validSecretData())
	if err != nil {
		t.Fatalf("KMPSignerFromIssuerAndSecretData: %v", err)
	}
	if kmpSigner == nil {
		t.Error("no signer was returned")
	}

	// A failed build must not hand back a non-nil interface holding a nil
	// pointer, which would panic on first use.
	if checker, err := KMPHealthCheckerFromIssuerAndSecretData(validSpec(), nil); err == nil {
		t.Error("KMPHealthCheckerFromIssuerAndSecretData succeeded without credentials")
	} else if checker != nil {
		t.Error("a health checker was returned alongside an error")
	}
	if kmpSigner, err := KMPSignerFromIssuerAndSecretData(validSpec(), nil); err == nil {
		t.Error("KMPSignerFromIssuerAndSecretData succeeded without credentials")
	} else if kmpSigner != nil {
		t.Error("a signer was returned alongside an error")
	}
}

func TestSigningOptionsAreTakenFromTheSpec(t *testing.T) {
	agentTimeout := int32(90)
	validity := int32(30)
	isIntermediate := true

	spec := &kmpissuerapi.IssuerSpec{
		URL: "https://kmp.example.com:6565",
		Signing: kmpissuerapi.SigningSpec{
			SignType:                    kmpissuerapi.SignTypeMSCAUsingAgent,
			ServerName:                  "ca1",
			CAName:                      "ca1-ca",
			TemplateName:                "WebServer",
			AgentName:                   "agent-1",
			AgentResponseTimeoutSeconds: &agentTimeout,
			RootCertificateCommonName:   "root",
			RootCertificateSerialNumber: "0A0B",
			ValidityDays:                &validity,
			IsIntermediate:              &isIntermediate,
			Email:                       "pki@example.com",
		},
	}

	got := signingOptions(spec)
	want := kmp.SigningOptions{
		SignType:                    "MSCAusingAgent",
		ServerName:                  "ca1",
		CAName:                      "ca1-ca",
		TemplateName:                "WebServer",
		AgentName:                   "agent-1",
		AgentResponseTimeoutSeconds: &agentTimeout,
		RootCertificateCommonName:   "root",
		RootCertificateSerialNumber: "0A0B",
		ValidityDays:                &validity,
		IsIntermediate:              &isIntermediate,
		Email:                       "pki@example.com",
	}
	if got != want {
		t.Errorf("signingOptions = %+v, want %+v", got, want)
	}
}

func TestRequestTimeout(t *testing.T) {
	if got := requestTimeout(&kmpissuerapi.IssuerSpec{}); got != 0 {
		t.Errorf("requestTimeout without a setting = %s, want 0 so the client default applies", got)
	}
	spec := &kmpissuerapi.IssuerSpec{RequestTimeout: &metav1.Duration{Duration: 45_000_000_000}}
	if got := requestTimeout(spec); got.Seconds() != 45 {
		t.Errorf("requestTimeout = %s, want 45s", got)
	}
}
