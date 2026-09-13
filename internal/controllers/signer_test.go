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

package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kmpissuerapi "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

func TestGetIssuerDetails(t *testing.T) {
	issuer := &Issuer{ClusterResourceNamespace: "kmp-issuer-system"}

	namespaced := &kmpissuerapi.KMPIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "kmp", Namespace: "app"},
		Spec:       kmpissuerapi.IssuerSpec{URL: "https://kmp.example.com:6565"},
	}
	spec, namespace, err := issuer.getIssuerDetails(namespaced)
	if err != nil {
		t.Fatalf("getIssuerDetails for a KMPIssuer: %v", err)
	}
	if namespace != "app" {
		t.Errorf("namespace = %q, want the namespace of the issuer", namespace)
	}
	if spec.URL != namespaced.Spec.URL {
		t.Errorf("spec = %+v, want the spec of the issuer", spec)
	}

	clusterScoped := &kmpissuerapi.KMPClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "kmp"},
		Spec:       kmpissuerapi.IssuerSpec{URL: "https://kmp.example.com:6565"},
	}
	_, namespace, err = issuer.getIssuerDetails(clusterScoped)
	if err != nil {
		t.Fatalf("getIssuerDetails for a KMPClusterIssuer: %v", err)
	}
	if namespace != "kmp-issuer-system" {
		t.Errorf("namespace = %q, want the cluster resource namespace", namespace)
	}
}

// unknownIssuer is an Issuer implementation this controller does not own.
type unknownIssuer struct {
	issuerapi.Issuer
}

func TestGetIssuerDetailsRejectsUnknownTypes(t *testing.T) {
	issuer := &Issuer{}
	_, _, err := issuer.getIssuerDetails(&unknownIssuer{})
	if err == nil {
		t.Fatal("getIssuerDetails accepted an unknown issuer type")
	}
	var permanent signer.PermanentError
	if !errors.As(err, &permanent) {
		t.Errorf("error %v is not a PermanentError, so the issuer would be retried forever", err)
	}
}

func TestPermanentIfUnrecoverable(t *testing.T) {
	tests := []struct {
		name          string
		cause         error
		wantPermanent bool
	}{
		{
			name:          "rejected by key manager plus",
			cause:         &kmp.Error{Op: "signCSR", StatusCode: http.StatusBadRequest, Message: "Template not found", Permanent: true},
			wantPermanent: true,
		},
		{
			name:          "misconfigured issuer",
			cause:         fmt.Errorf("%w: signType MSCA requires signing.caName", kmp.ErrInvalidConfig),
			wantPermanent: true,
		},
		{
			name:  "key manager plus is unavailable",
			cause: &kmp.Error{Op: "signCSR", StatusCode: http.StatusServiceUnavailable},
		},
		{
			name:  "connection failed",
			cause: errors.New("dial tcp: connection refused"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := permanentIfUnrecoverable(fmt.Errorf("%w: %v", errSignerSign, tc.cause), tc.cause)

			var permanent signer.PermanentError
			if got := errors.As(err, &permanent); got != tc.wantPermanent {
				t.Errorf("errors.As(%v, PermanentError) = %v, want %v", err, got, tc.wantPermanent)
			}
			if !errors.Is(err, errSignerSign) {
				t.Errorf("error %v no longer identifies the failed step", err)
			}
		})
	}
}
