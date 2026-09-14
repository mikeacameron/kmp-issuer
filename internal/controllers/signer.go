/*
Copyright 2023 The cert-manager Authors.

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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmpissuerapi "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")

	errSignerBuilder = errors.New("failed to build the signer")
	errSignerSign    = errors.New("failed to sign")
)

// maxRetryDuration bounds how long a request may keep failing with retryable
// errors before issuer-lib marks it failed and cert-manager creates a
// replacement request.
const maxRetryDuration = 5 * time.Minute

// HealthChecker verifies that the Key Manager Plus API is reachable and that
// the configured credentials are accepted.
type HealthChecker interface {
	Check(ctx context.Context) error
}

type HealthCheckerBuilder func(*kmpissuerapi.IssuerSpec, map[string][]byte) (HealthChecker, error)

// Signer signs a certificate signing request.
//
// Unlike the local certificate authority in the upstream sample, Key Manager
// Plus is a remote CA: it consumes the X.509 CSR itself rather than a
// certificate template assembled by the controller, so the request is passed
// through as issuer-lib supplies it. The returned bytes are the PEM encoded
// certificate chain, leaf first.
type Signer interface {
	Sign(ctx context.Context, details signer.CertificateDetails) ([]byte, error)
}

type SignerBuilder func(*kmpissuerapi.IssuerSpec, map[string][]byte) (Signer, error)

type Issuer struct {
	HealthCheckerBuilder     HealthCheckerBuilder
	SignerBuilder            SignerBuilder
	ClusterResourceNamespace string

	client client.Client
}

// +kubebuilder:rbac:groups=kmp.cert-manager.io,resources=kmpclusterissuers;kmpissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=kmp.cert-manager.io,resources=kmpclusterissuers/status;kmpissuers/status,verbs=patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=kmpclusterissuers.kmp.cert-manager.io/*;kmpissuers.kmp.cert-manager.io/*

func (s Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.client = mgr.GetClient()

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&kmpissuerapi.KMPIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&kmpissuerapi.KMPClusterIssuer{}},

		FieldOwner:       "kmpissuer.cert-manager.io",
		MaxRetryDuration: maxRetryDuration,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorder("kmpissuer.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}

func (o *Issuer) getIssuerDetails(issuerObject issuerapi.Issuer) (*kmpissuerapi.IssuerSpec, string, error) {
	switch t := issuerObject.(type) {
	case *kmpissuerapi.KMPIssuer:
		return &t.Spec, issuerObject.GetNamespace(), nil
	case *kmpissuerapi.KMPClusterIssuer:
		return &t.Spec, o.ClusterResourceNamespace, nil
	default:
		// A permanent error will cause the Issuer to not retry until the
		// Issuer is updated.
		return nil, "", signer.PermanentError{
			Err: fmt.Errorf("unexpected issuer type: %t", issuerObject),
		}
	}
}

func (o *Issuer) getSecretData(ctx context.Context, issuerSpec *kmpissuerapi.IssuerSpec, namespace string) (map[string][]byte, error) {
	secretName := types.NamespacedName{
		Namespace: namespace,
		Name:      issuerSpec.AuthSecretName,
	}

	var secret corev1.Secret
	if err := o.client.Get(ctx, secretName, &secret); err != nil {
		return nil, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
	}

	checker, err := o.HealthCheckerBuilder(issuerSpec, secret.Data)
	if err != nil {
		return nil, permanentIfUnrecoverable(fmt.Errorf("%w: %v", errHealthCheckerBuilder, err), err)
	}

	if err := checker.Check(ctx); err != nil {
		return nil, permanentIfUnrecoverable(fmt.Errorf("%w: %v", errHealthCheckerCheck, err), err)
	}

	return secret.Data, nil
}

// Check checks that the CA it is available. Certificate requests will not be
// processed until this check passes.
func (o *Issuer) Check(ctx context.Context, issuerObject issuerapi.Issuer) error {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		return err
	}

	_, err = o.getSecretData(ctx, issuerSpec, namespace)
	return err
}

// Sign returns a signed certificate for the supplied CertificateRequestObject (a cert-manager CertificateRequest resource or
// a kubernetes CertificateSigningRequest resource). The CertificateRequestObject contains the raw CSR, which is handed to
// Key Manager Plus unchanged: it is the CA, so it decides the contents of the certificate from the CSR and the configured
// Microsoft CA template or root certificate.
// The Sign method returns a PEMBundle containing the signed certificate and any intermediate certificates (see the PEMBundle docs for more information).
// If the Sign method returns an error, the issuance will be retried until the MaxRetryDuration is reached.
// Special errors and cases can be found in the issuer-lib README: https://github.com/cert-manager/issuer-lib/tree/main?tab=readme-ov-file#how-it-works
func (o *Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		// Returning an IssuerError will change the status of the Issuer to Failed too.
		return signer.PEMBundle{}, signer.IssuerError{
			Err: err,
		}
	}

	secretData, err := o.getSecretData(ctx, issuerSpec, namespace)
	if err != nil {
		// Returning an IssuerError will change the status of the Issuer to Failed too.
		return signer.PEMBundle{}, signer.IssuerError{
			Err: err,
		}
	}

	certDetails, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	signerObj, err := o.SignerBuilder(issuerSpec, secretData)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{
			Err: fmt.Errorf("%w: %v", errSignerBuilder, err),
		}
	}

	signed, err := signerObj.Sign(ctx, certDetails)
	if err != nil {
		// A request Key Manager Plus rejected cannot succeed on a retry: only a
		// new request, or a change to the issuer, can resolve it.
		return signer.PEMBundle{}, permanentIfUnrecoverable(fmt.Errorf("%w: %v", errSignerSign, err), err)
	}

	bundle, err := pki.ParseSingleCertificateChainPEM(signed)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	return signer.PEMBundle(bundle), nil
}

// permanentIfUnrecoverable wraps err as a PermanentError when the underlying
// cause is a rejection or a misconfiguration, so that issuer-lib stops retrying
// something that cannot start working on its own. Timeouts, connection failures
// and server errors are returned unchanged and are retried.
func permanentIfUnrecoverable(err error, cause error) error {
	if kmp.IsPermanent(cause) {
		return signer.PermanentError{Err: err}
	}
	return err
}
