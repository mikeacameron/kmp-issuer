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
	"errors"
	"fmt"
	"math"
	"time"
)

// ErrInvalidConfig marks a signing configuration that Key Manager Plus cannot
// act on, such as an MSCA sign type without a certificate template.
var ErrInvalidConfig = errors.New("invalid signing configuration")

// Sign types accepted by the Key Manager Plus signCSR operation.
const (
	SignTypeMSCA           = "MSCA"
	SignTypeMSCAUsingAgent = "MSCAusingAgent"
	SignTypeWithRoot       = "signWithRoot"
)

// SigningOptions is the issuer configuration a Signer applies to every request.
type SigningOptions struct {
	SignType     string
	ServerName   string
	CAName       string
	TemplateName string

	AgentName                   string
	AgentResponseTimeoutSeconds *int32

	RootCertificateCommonName   string
	RootCertificateSerialNumber string
	ValidityDays                *int32
	IsIntermediate              *bool

	Email string
}

// signType returns the configured sign type, defaulting to the Key Manager Plus
// default of MSCA.
func (o SigningOptions) signType() string {
	if o.SignType == "" {
		return SignTypeMSCA
	}
	return o.SignType
}

// Validate reports whether the options carry everything the chosen sign type
// needs. It returns errors wrapping ErrInvalidConfig, which callers treat as
// permanent.
func (o SigningOptions) Validate() error {
	switch o.signType() {
	case SignTypeMSCA:
		return requireMSCAFields(o)
	case SignTypeMSCAUsingAgent:
		if err := requireMSCAFields(o); err != nil {
			return err
		}
		if o.AgentName == "" {
			return fmt.Errorf("%w: signType %s requires signing.agentName", ErrInvalidConfig, SignTypeMSCAUsingAgent)
		}
		return nil
	case SignTypeWithRoot:
		if o.RootCertificateCommonName == "" {
			return fmt.Errorf("%w: signType %s requires signing.rootCertificateCommonName", ErrInvalidConfig, SignTypeWithRoot)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown signType %q, expected one of %s, %s, %s",
			ErrInvalidConfig, o.SignType, SignTypeMSCA, SignTypeMSCAUsingAgent, SignTypeWithRoot)
	}
}

func requireMSCAFields(o SigningOptions) error {
	var missing []string
	if o.ServerName == "" {
		missing = append(missing, "signing.serverName")
	}
	if o.CAName == "" {
		missing = append(missing, "signing.caName")
	}
	if o.TemplateName == "" {
		missing = append(missing, "signing.templateName")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: signType %s requires %v", ErrInvalidConfig, o.signType(), missing)
	}
	return nil
}

// Default polling behaviour while waiting for a signed certificate to become
// retrievable. Microsoft CA signing through Key Manager Plus is synchronous,
// but a certificate can take a moment to appear in the certificate store, and
// agent based signing waits on a round trip to the agent.
const (
	defaultPollInterval = 2 * time.Second
	defaultPollTimeout  = 60 * time.Second
)

// Signer turns certificate signing requests into signed certificates using one
// Key Manager Plus issuer configuration.
type Signer struct {
	client *Client
	opts   SigningOptions

	// PollInterval and PollTimeout govern the wait for the signed certificate
	// to become retrievable. Zero values select the defaults.
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// NewSigner validates the options and returns a Signer bound to client.
func NewSigner(client *Client, opts SigningOptions) (*Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: no key manager plus client", ErrInvalidConfig)
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &Signer{client: client, opts: opts}, nil
}

// Request is one certificate signing request to fulfil.
type Request struct {
	// CSRPEM is the PEM encoded certificate signing request.
	CSRPEM []byte

	// Duration is the certificate lifetime cert-manager asked for. It is only
	// honoured by the signWithRoot sign type, and only when the issuer does not
	// pin a validity itself; Microsoft CA templates define their own lifetime.
	Duration time.Duration

	// IsCA reports whether the request asks for a CA certificate. It selects
	// intermediate signing for the signWithRoot sign type unless the issuer
	// pins signing.isIntermediate.
	IsCA bool
}

// Sign imports the request into Key Manager Plus, signs it and returns the
// issued certificate with its chain.
func (s *Signer) Sign(ctx context.Context, req Request) (*Bundle, error) {
	csr, err := ParseCSR(req.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfig, err)
	}

	stored, err := s.client.ImportCSR(ctx, req.CSRPEM, s.opts.Email)
	if err != nil {
		return nil, fmt.Errorf("importing the certificate signing request: %w", err)
	}

	signReq := s.signRequest(stored.ID, req)
	result, err := s.client.SignCSR(ctx, signReq)
	if err != nil {
		return nil, fmt.Errorf("signing the certificate signing request: %w", err)
	}

	commonName := result.CommonName
	if commonName == "" {
		commonName = stored.CommonName
	}
	if commonName == "" {
		commonName = csr.Subject.CommonName
	}
	if commonName == "" && result.SerialNumber == "" {
		return nil, fmt.Errorf("%w: key manager plus signed the request but returned neither a common name nor a serial number to fetch it with", ErrInvalidConfig)
	}

	certs, err := s.fetchCertificate(ctx, commonName, result.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("fetching the signed certificate: %w", err)
	}

	bundle, err := BuildBundle(certs, csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("assembling the certificate chain: %w", err)
	}
	return bundle, nil
}

// signRequest merges the issuer options with the per-request hints.
func (s *Signer) signRequest(csrID string, req Request) SignRequest {
	signReq := SignRequest{
		CSRID:                       csrID,
		SignType:                    s.opts.signType(),
		ServerName:                  s.opts.ServerName,
		CAName:                      s.opts.CAName,
		TemplateName:                s.opts.TemplateName,
		AgentName:                   s.opts.AgentName,
		AgentResponseTimeoutSeconds: s.opts.AgentResponseTimeoutSeconds,
		RootCertificateCommonName:   s.opts.RootCertificateCommonName,
		RootCertificateSerialNumber: s.opts.RootCertificateSerialNumber,
		ValidityDays:                s.opts.ValidityDays,
		IsIntermediate:              s.opts.IsIntermediate,
	}
	if signReq.SignType != SignTypeWithRoot {
		return signReq
	}
	if signReq.ValidityDays == nil && req.Duration > 0 {
		days := int32(math.Ceil(req.Duration.Hours() / 24))
		if days < 1 {
			days = 1
		}
		signReq.ValidityDays = &days
	}
	if signReq.IsIntermediate == nil && req.IsCA {
		isCA := true
		signReq.IsIntermediate = &isCA
	}
	return signReq
}

// fetchCertificate retrieves the issued certificate, retrying while Key Manager
// Plus reports it as not yet available.
func (s *Signer) fetchCertificate(ctx context.Context, commonName, serialNumber string) ([]*x509.Certificate, error) {
	interval := s.PollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	timeout := s.PollTimeout
	if timeout <= 0 {
		timeout = defaultPollTimeout
	}

	deadline := time.Now().Add(timeout)
	for attempt := 0; ; attempt++ {
		certs, err := s.client.GetCertificate(ctx, commonName, serialNumber)
		if err == nil {
			return certs, nil
		}
		if IsPermanent(err) || time.Now().Add(interval).After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(err, ctx.Err())
		case <-time.After(interval):
		}
	}
}
