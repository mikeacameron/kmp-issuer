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
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	kmpissuerapi "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

// Provisioner asks Key Manager Plus for a key pair and a certificate for it.
type Provisioner interface {
	Provision(ctx context.Context, req kmp.ProvisionRequest) (*kmp.ProvisionedCertificate, error)
}

// ProvisionerBuilder constructs a Provisioner from an issuer and its
// credentials.
type ProvisionerBuilder func(*kmpissuerapi.IssuerSpec, map[string][]byte) (Provisioner, error)

const (
	// defaultKeyStorePasswordKey is the Secret key a supplied key store
	// password is read from.
	defaultKeyStorePasswordKey = "password"

	// renewalFraction is the part of a certificate's lifetime that is left when
	// renewal starts, when the spec does not say.
	renewalFraction = 3

	// issuanceFailureRequeue is how long to wait after a failure that may
	// resolve itself.
	issuanceFailureRequeue = time.Minute
)

// KMPCertificateReconciler keeps the Secret of a KMPCertificate holding a
// current certificate and the key Key Manager Plus generated for it.
type KMPCertificateReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// ClusterResourceNamespace is where the Secrets of cluster scoped issuers
	// live.
	ClusterResourceNamespace string

	// ProvisionerBuilder constructs the Key Manager Plus client.
	ProvisionerBuilder ProvisionerBuilder

	// Clock is swapped out in tests.
	Clock func() time.Time
}

// +kubebuilder:rbac:groups=kmp.cert-manager.io,resources=kmpcertificates,verbs=get;list;watch
// +kubebuilder:rbac:groups=kmp.cert-manager.io,resources=kmpcertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

// Reconcile issues or renews the certificate of one KMPCertificate.
func (r *KMPCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	var certificate kmpissuerapi.KMPCertificate
	if err := r.Get(ctx, req.NamespacedName, &certificate); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if certificate.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	before := certificate.Status.DeepCopy()
	defer func() {
		if equality.Semantic.DeepEqual(before, &certificate.Status) {
			return
		}
		if updateErr := r.Status().Update(ctx, &certificate); updateErr != nil {
			err = fmt.Errorf("updating the status of %s: %w", req.NamespacedName, updateErr)
			result = ctrl.Result{}
		}
	}()

	reason, renewAt, needed := r.issuanceNeeded(ctx, &certificate)
	if !needed {
		setCondition(&certificate.Status.Conditions, certificate.Generation, kmpissuerapi.KMPCertificateConditionReady,
			metav1.ConditionTrue, "Issued", "The Secret holds a current certificate")
		return ctrl.Result{RequeueAfter: r.until(renewAt)}, nil
	}

	log.Info("requesting a certificate from key manager plus", "reason", reason)
	if issueErr := r.issue(ctx, &certificate); issueErr != nil {
		setCondition(&certificate.Status.Conditions, certificate.Generation, kmpissuerapi.KMPCertificateConditionReady,
			metav1.ConditionFalse, "Failed", issueErr.Error())
		r.Recorder.Event(&certificate, corev1.EventTypeWarning, "Failed", issueErr.Error())

		if kmp.IsPermanent(issueErr) {
			// Only a change to the resource, the issuer or Key Manager Plus can
			// make this succeed.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: issuanceFailureRequeue}, issueErr
	}

	setCondition(&certificate.Status.Conditions, certificate.Generation, kmpissuerapi.KMPCertificateConditionReady,
		metav1.ConditionTrue, "Issued", "Key Manager Plus issued the certificate")
	r.Recorder.Event(&certificate, corev1.EventTypeNormal, "Issued", "Key Manager Plus issued the certificate")

	return ctrl.Result{RequeueAfter: r.until(certificate.Status.RenewalTime)}, nil
}

// issuanceNeeded reports whether a certificate has to be requested, and when
// the current one falls due for renewal.
func (r *KMPCertificateReconciler) issuanceNeeded(ctx context.Context, certificate *kmpissuerapi.KMPCertificate) (string, *metav1.Time, bool) {
	var secret corev1.Secret
	name := types.NamespacedName{Namespace: certificate.Namespace, Name: certificate.Spec.SecretName}
	if err := r.Get(ctx, name, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Sprintf("secret %s does not exist", name), nil, true
		}
		return fmt.Sprintf("secret %s could not be read: %s", name, err), nil, true
	}

	certPEM := secret.Data[corev1.TLSCertKey]
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Sprintf("secret %s holds no certificate and key", name), nil, true
	}

	leaf, err := leafOf(certPEM)
	if err != nil {
		return fmt.Sprintf("the certificate in secret %s could not be read: %s", name, err), nil, true
	}
	if mismatch := matchesSpec(leaf, certificate.Spec); mismatch != "" {
		return mismatch, nil, true
	}

	renewAt := renewalTime(leaf, certificate.Spec.RenewBefore)
	if !r.now().Before(renewAt.Time) {
		return fmt.Sprintf("the certificate is due for renewal at %s", renewAt.Format(time.RFC3339)), renewAt, true
	}
	return "", renewAt, false
}

// issue requests a new certificate and writes it, with its key, to the Secret.
func (r *KMPCertificateReconciler) issue(ctx context.Context, certificate *kmpissuerapi.KMPCertificate) error {
	issuerSpec, issuerNamespace, err := r.resolveIssuer(ctx, certificate)
	if err != nil {
		return err
	}

	var authSecret corev1.Secret
	authName := types.NamespacedName{Namespace: issuerNamespace, Name: issuerSpec.AuthSecretName}
	if err := r.Get(ctx, authName, &authSecret); err != nil {
		return fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, authName, err)
	}

	password, generated, err := r.keyStorePassword(ctx, certificate)
	if err != nil {
		return err
	}

	provisioner, err := r.ProvisionerBuilder(issuerSpec, authSecret.Data)
	if err != nil {
		return fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	provisioned, err := provisioner.Provision(ctx, provisionRequest(certificate, password))
	if err != nil {
		return err
	}

	bundle, err := pki.ParseSingleCertificateChainPEM(provisioned.Bundle.ChainPEM)
	if err != nil {
		return fmt.Errorf("%w: splitting the certificate chain: %v", kmp.ErrUnusableResponse, err)
	}

	if err := r.writeSecret(ctx, certificate, bundle.ChainPEM, bundle.CAPEM, provisioned.PrivateKeyPEM, password, generated); err != nil {
		return err
	}

	leaf := provisioned.Bundle.Leaf
	certificate.Status.SerialNumber = provisioned.SerialNumber
	certificate.Status.CSRID = provisioned.CSRID
	certificate.Status.NotBefore = &metav1.Time{Time: leaf.NotBefore}
	certificate.Status.NotAfter = &metav1.Time{Time: leaf.NotAfter}
	certificate.Status.RenewalTime = renewalTime(leaf, certificate.Spec.RenewBefore)
	return nil
}

// resolveIssuer returns the spec of the issuer a certificate names, and the
// namespace its credentials live in.
func (r *KMPCertificateReconciler) resolveIssuer(ctx context.Context, certificate *kmpissuerapi.KMPCertificate) (*kmpissuerapi.IssuerSpec, string, error) {
	kind := certificate.Spec.IssuerRef.Kind
	if kind == "" {
		kind = "KMPIssuer"
	}

	switch kind {
	case "KMPIssuer":
		var issuer kmpissuerapi.KMPIssuer
		name := types.NamespacedName{Namespace: certificate.Namespace, Name: certificate.Spec.IssuerRef.Name}
		if err := r.Get(ctx, name, &issuer); err != nil {
			return nil, "", fmt.Errorf("getting KMPIssuer %s: %w", name, err)
		}
		return &issuer.Spec, issuer.Namespace, nil
	case "KMPClusterIssuer":
		var issuer kmpissuerapi.KMPClusterIssuer
		name := types.NamespacedName{Name: certificate.Spec.IssuerRef.Name}
		if err := r.Get(ctx, name, &issuer); err != nil {
			return nil, "", fmt.Errorf("getting KMPClusterIssuer %s: %w", name, err)
		}
		return &issuer.Spec, r.ClusterResourceNamespace, nil
	default:
		return nil, "", fmt.Errorf("%w: unknown issuer kind %q", kmp.ErrInvalidConfig, kind)
	}
}

// keyStorePassword returns the password protecting the key inside Key Manager
// Plus, generating one when the spec does not supply it.
func (r *KMPCertificateReconciler) keyStorePassword(ctx context.Context, certificate *kmpissuerapi.KMPCertificate) (string, bool, error) {
	ref := certificate.Spec.KeyStorePasswordSecretRef
	if ref == nil {
		password, err := generatePassword()
		if err != nil {
			return "", false, err
		}
		return password, true, nil
	}

	key := ref.Key
	if key == "" {
		key = defaultKeyStorePasswordKey
	}
	var secret corev1.Secret
	name := types.NamespacedName{Namespace: certificate.Namespace, Name: ref.Name}
	if err := r.Get(ctx, name, &secret); err != nil {
		return "", false, fmt.Errorf("reading the key store password from secret %s: %w", name, err)
	}
	password := strings.TrimSpace(string(secret.Data[key]))
	if password == "" {
		return "", false, fmt.Errorf("%w: key %q of secret %s is empty", kmp.ErrInvalidConfig, key, name)
	}
	return password, false, nil
}

// writeSecret stores the certificate and the escrowed key, owned by the
// KMPCertificate so that both are removed with it.
func (r *KMPCertificateReconciler) writeSecret(ctx context.Context, certificate *kmpissuerapi.KMPCertificate, chainPEM, caPEM, keyPEM []byte, password string, generated bool) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certificate.Spec.SecretName,
			Namespace: certificate.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = corev1.SecretTypeTLS
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[corev1.TLSCertKey] = chainPEM
		secret.Data[corev1.TLSPrivateKeyKey] = keyPEM
		if len(caPEM) > 0 {
			secret.Data[cmMetaTLSCAKey] = caPEM
		}
		if generated {
			// Without this the escrowed key could not be recovered from Key
			// Manager Plus, which is the point of letting it hold the key.
			secret.Data[kmpissuerapi.KeyStorePasswordSecretKey] = []byte(password)
		}
		return controllerutil.SetControllerReference(certificate, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("writing secret %s/%s: %w", certificate.Namespace, certificate.Spec.SecretName, err)
	}
	return nil
}

// cmMetaTLSCAKey is the key cert-manager uses for the CA of a TLS Secret.
const cmMetaTLSCAKey = "ca.crt"

// provisionRequest turns the spec into a Key Manager Plus request.
func provisionRequest(certificate *kmpissuerapi.KMPCertificate, password string) kmp.ProvisionRequest {
	spec := certificate.Spec

	altNames := make([]string, 0, len(spec.DNSNames)+len(spec.IPAddresses))
	altNames = append(altNames, spec.DNSNames...)
	altNames = append(altNames, spec.IPAddresses...)

	req := kmp.ProvisionRequest{
		CommonName:         spec.CommonName,
		AltNames:           altNames,
		Organization:       spec.Subject.Organization,
		OrganizationalUnit: spec.Subject.OrganizationalUnit,
		Location:           spec.Subject.Locality,
		State:              spec.Subject.Province,
		Country:            spec.Subject.Country,
		KeyAlgorithm:       spec.PrivateKey.Algorithm,
		SignatureAlgorithm: spec.PrivateKey.SignatureAlgorithm,
		StoreType:          spec.PrivateKey.StoreType,
		ValidityType:       spec.ValidityType,
		ValidityDays:       spec.ValidityDays,
		Password:           password,
	}
	if spec.PrivateKey.Size != nil {
		req.KeyLength = *spec.PrivateKey.Size
	}
	return req
}

// matchesSpec reports the first way in which an issued certificate no longer
// matches what was asked for, or the empty string when it still does.
func matchesSpec(leaf *x509.Certificate, spec kmpissuerapi.KMPCertificateSpec) string {
	if !strings.EqualFold(leaf.Subject.CommonName, spec.CommonName) {
		return fmt.Sprintf("the certificate is for %q, not %q", leaf.Subject.CommonName, spec.CommonName)
	}
	for _, name := range spec.DNSNames {
		if !containsFold(leaf.DNSNames, name) {
			return fmt.Sprintf("the certificate does not cover DNS name %q", name)
		}
	}
	for _, address := range spec.IPAddresses {
		ip := net.ParseIP(address)
		if ip == nil {
			return fmt.Sprintf("%q is not an IP address", address)
		}
		found := false
		for _, issued := range leaf.IPAddresses {
			if issued.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("the certificate does not cover IP address %q", address)
		}
	}
	if want := spec.Subject.Organization; want != "" && !containsFold(leaf.Subject.Organization, want) {
		return fmt.Sprintf("the certificate is not for organization %q", want)
	}
	if want := spec.Subject.OrganizationalUnit; want != "" && !containsFold(leaf.Subject.OrganizationalUnit, want) {
		return fmt.Sprintf("the certificate is not for organizational unit %q", want)
	}
	return ""
}

// renewalTime is when a replacement should be requested.
func renewalTime(leaf *x509.Certificate, renewBefore *metav1.Duration) *metav1.Time {
	before := leaf.NotAfter.Sub(leaf.NotBefore) / renewalFraction
	if renewBefore != nil && renewBefore.Duration > 0 {
		before = renewBefore.Duration
	}
	return &metav1.Time{Time: leaf.NotAfter.Add(-before)}
}

// leafOf returns the first certificate of a PEM chain.
func leafOf(chainPEM []byte) (*x509.Certificate, error) {
	certs, err := pki.DecodeX509CertificateChainBytes(chainPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate in the chain")
	}
	return certs[0], nil
}

// generatePassword returns a random password for a key store.
func generatePassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating a key store password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (r *KMPCertificateReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// until returns how long to wait before the next check.
func (r *KMPCertificateReconciler) until(at *metav1.Time) time.Duration {
	if at == nil {
		return issuanceFailureRequeue
	}
	wait := at.Time.Sub(r.now())
	if wait < time.Second {
		return time.Second
	}
	return wait
}

// containsFold reports whether values holds want, ignoring case.
func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

// setCondition records a condition and reports whether anything changed.
func setCondition(conditions *[]metav1.Condition, generation int64, conditionType string, status metav1.ConditionStatus, reason, message string) bool {
	now := metav1.Now()
	for i := range *conditions {
		existing := &(*conditions)[i]
		if existing.Type != conditionType {
			continue
		}
		if existing.Status == status && existing.Reason == reason &&
			existing.Message == message && existing.ObservedGeneration == generation {
			return false
		}
		if existing.Status != status {
			existing.LastTransitionTime = now
		}
		existing.Status = status
		existing.Reason = reason
		existing.Message = message
		existing.ObservedGeneration = generation
		return true
	}

	*conditions = append(*conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: now,
	})
	return true
}

// SetupWithManager registers the reconciler.
func (r *KMPCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("kmpcertificate")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmpissuerapi.KMPCertificate{}).
		Owns(&corev1.Secret{}).
		Named("kmpcertificate").
		Complete(r)
}
