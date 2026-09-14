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

// Package signer wires an issuer spec and its credentials to the ManageEngine
// Key Manager Plus REST API.
package signer

import (
	"context"
	"fmt"
	"strings"
	"time"

	libsigner "github.com/cert-manager/issuer-lib/controllers/signer"

	kmpissuerapi "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/controllers"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

// userAgent identifies this controller to Key Manager Plus.
const userAgent = "kmp-issuer"

// KMPHealthCheckerFromIssuerAndSecretData builds the health checker used to
// decide whether an issuer is ready.
func KMPHealthCheckerFromIssuerAndSecretData(spec *kmpissuerapi.IssuerSpec, secretData map[string][]byte) (controllers.HealthChecker, error) {
	kmpSigner, err := signerFromIssuerAndSecretData(spec, secretData)
	if err != nil {
		return nil, err
	}
	return kmpSigner, nil
}

// KMPProvisionerFromIssuerAndSecretData builds the client used by
// KMPCertificate resources, where Key Manager Plus generates and keeps the key.
func KMPProvisionerFromIssuerAndSecretData(spec *kmpissuerapi.IssuerSpec, secretData map[string][]byte) (controllers.Provisioner, error) {
	kmpSigner, err := signerFromIssuerAndSecretData(spec, secretData)
	if err != nil {
		return nil, err
	}
	return kmpSigner, nil
}

// KMPSignerFromIssuerAndSecretData builds the signer used to fulfil requests.
func KMPSignerFromIssuerAndSecretData(spec *kmpissuerapi.IssuerSpec, secretData map[string][]byte) (controllers.Signer, error) {
	kmpSigner, err := signerFromIssuerAndSecretData(spec, secretData)
	if err != nil {
		return nil, err
	}
	return kmpSigner, nil
}

// kmpSigner talks to one Key Manager Plus server with one issuer's
// configuration. It serves as both the health checker and the signer, because
// the two need the same client.
type kmpSigner struct {
	client *kmp.Client
	signer *kmp.Signer
}

func signerFromIssuerAndSecretData(spec *kmpissuerapi.IssuerSpec, secretData map[string][]byte) (*kmpSigner, error) {
	if spec == nil {
		return nil, fmt.Errorf("%w: no issuer spec", kmp.ErrInvalidConfig)
	}

	authToken := strings.TrimSpace(string(secretData[kmpissuerapi.AuthSecretTokenKey]))
	if authToken == "" {
		return nil, fmt.Errorf("%w: the auth Secret has no non-empty %q key",
			kmp.ErrInvalidConfig, kmpissuerapi.AuthSecretTokenKey)
	}

	client, err := kmp.NewClient(kmp.Config{
		BaseURL:               spec.URL,
		AuthToken:             authToken,
		CABundle:              secretData[kmpissuerapi.AuthSecretCABundleKey],
		InsecureSkipTLSVerify: spec.InsecureSkipTLSVerify,
		Timeout:               requestTimeout(spec),
		UserAgent:             userAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", kmp.ErrInvalidConfig, err)
	}

	inner, err := kmp.NewSigner(client, signingOptions(spec))
	if err != nil {
		return nil, err
	}
	return &kmpSigner{client: client, signer: inner}, nil
}

// Check verifies that Key Manager Plus is reachable and the auth token is
// accepted.
func (o *kmpSigner) Check(ctx context.Context) error {
	return o.client.Ping(ctx)
}

// Sign hands the certificate signing request to Key Manager Plus and returns
// the issued certificate with the chain above it, leaf first.
func (o *kmpSigner) Sign(ctx context.Context, details libsigner.CertificateDetails) ([]byte, error) {
	bundle, err := o.signer.Sign(ctx, kmp.Request{
		CSRPEM:   details.CSR,
		Duration: details.Duration,
		IsCA:     details.IsCA,
	})
	if err != nil {
		return nil, err
	}
	return bundle.ChainPEM, nil
}

// Provision has Key Manager Plus generate a key pair, sign a certificate for it
// and return both.
func (o *kmpSigner) Provision(ctx context.Context, req kmp.ProvisionRequest) (*kmp.ProvisionedCertificate, error) {
	return o.signer.Provision(ctx, req)
}

// signingOptions translates the API type into the client's options.
func signingOptions(spec *kmpissuerapi.IssuerSpec) kmp.SigningOptions {
	return kmp.SigningOptions{
		SignType:                    string(spec.Signing.SignType),
		ServerName:                  spec.Signing.ServerName,
		CAName:                      spec.Signing.CAName,
		TemplateName:                spec.Signing.TemplateName,
		AgentName:                   spec.Signing.AgentName,
		AgentResponseTimeoutSeconds: spec.Signing.AgentResponseTimeoutSeconds,
		RootCertificateCommonName:   spec.Signing.RootCertificateCommonName,
		RootCertificateSerialNumber: spec.Signing.RootCertificateSerialNumber,
		ValidityDays:                spec.Signing.ValidityDays,
		IsIntermediate:              spec.Signing.IsIntermediate,
		Email:                       spec.Signing.Email,
		CSRLookupOperation:          spec.Signing.CSRLookupOperation,
	}
}

func requestTimeout(spec *kmpissuerapi.IssuerSpec) time.Duration {
	if spec.RequestTimeout == nil {
		return 0
	}
	return spec.RequestTimeout.Duration
}
