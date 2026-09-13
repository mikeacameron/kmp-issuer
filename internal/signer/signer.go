// Package signer adapts a KMPIssuer spec and its credentials to the Key
// Manager Plus client, and defines the interface the controllers depend on so
// that they can be tested without a Key Manager Plus server.
package signer

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

// Credentials are the secret values an issuer needs, read from the Secrets its
// spec references.
type Credentials struct {
	// AuthToken is the Key Manager Plus AUTHTOKEN.
	AuthToken string
	// CABundle verifies the Key Manager Plus server certificate. It may be
	// empty, in which case the system roots are used.
	CABundle []byte
}

// Signer issues certificates for one issuer and reports whether its back end is
// usable.
type Signer interface {
	// Sign returns the signed certificate and its chain.
	Sign(ctx context.Context, req kmp.Request) (*kmp.Bundle, error)
	// Check verifies that Key Manager Plus is reachable and the credentials are
	// accepted.
	Check(ctx context.Context) error
}

// Builder constructs a Signer from an issuer spec and its credentials.
type Builder func(spec *api.IssuerSpec, creds Credentials) (Signer, error)

// userAgent identifies this controller to Key Manager Plus.
const userAgent = "kmp-issuer"

// KMPSigner is the production Signer, backed by the Key Manager Plus REST API.
type KMPSigner struct {
	client *kmp.Client
	signer *kmp.Signer
}

// NewKMPSigner builds a Signer for the given issuer spec. Configuration
// problems are reported as errors wrapping kmp.ErrInvalidConfig, which the
// controllers treat as permanent.
func NewKMPSigner(spec *api.IssuerSpec, creds Credentials) (Signer, error) {
	if spec == nil {
		return nil, fmt.Errorf("%w: no issuer spec", kmp.ErrInvalidConfig)
	}

	caBundle := creds.CABundle
	if len(spec.CABundle) > 0 {
		caBundle = append(append([]byte{}, spec.CABundle...), caBundle...)
	}

	client, err := kmp.NewClient(kmp.Config{
		BaseURL:               spec.URL,
		AuthToken:             creds.AuthToken,
		CABundle:              caBundle,
		InsecureSkipTLSVerify: spec.InsecureSkipTLSVerify,
		Timeout:               durationOrZero(spec.RequestTimeout),
		UserAgent:             userAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", kmp.ErrInvalidConfig, err)
	}

	inner, err := kmp.NewSigner(client, signingOptions(spec))
	if err != nil {
		return nil, err
	}
	return &KMPSigner{client: client, signer: inner}, nil
}

// signingOptions translates the API type into the client's options.
func signingOptions(spec *api.IssuerSpec) kmp.SigningOptions {
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
	}
}

// Sign issues a certificate for the request.
func (s *KMPSigner) Sign(ctx context.Context, req kmp.Request) (*kmp.Bundle, error) {
	return s.signer.Sign(ctx, req)
}

// Check verifies connectivity and credentials.
func (s *KMPSigner) Check(ctx context.Context) error {
	return s.client.Ping(ctx)
}

func durationOrZero(d *metav1.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.Duration
}
