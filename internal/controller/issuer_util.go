// Package controller contains the reconcilers that connect cert-manager to
// ManageEngine Key Manager Plus.
package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
	"github.com/mikeacameron/kmp-issuer/internal/signer"
)

const (
	// KMPIssuerKind and KMPClusterIssuerKind are the kinds this controller
	// issues for.
	KMPIssuerKind        = "KMPIssuer"
	KMPClusterIssuerKind = "KMPClusterIssuer"

	// defaultAuthTokenKey is the Secret key read when the issuer does not name
	// one.
	defaultAuthTokenKey = "authtoken"

	// defaultCABundleKey is the Secret key read for a CA bundle when the issuer
	// does not name one.
	defaultCABundleKey = "ca.crt"

	// defaultHealthCheckInterval is how often an issuer is re-checked when its
	// spec does not say.
	defaultHealthCheckInterval = 5 * time.Minute
)

// newIssuer returns an empty object of the given issuer kind.
func newIssuer(kind string) (api.Issuer, error) {
	switch kind {
	case KMPIssuerKind:
		return &api.KMPIssuer{}, nil
	case KMPClusterIssuerKind:
		return &api.KMPClusterIssuer{}, nil
	default:
		return nil, fmt.Errorf("%w: unknown issuer kind %q", kmp.ErrInvalidConfig, kind)
	}
}

// secretNamespace returns the namespace the Secrets of an issuer live in.
// Cluster scoped issuers read them from the controller's resource namespace.
func secretNamespace(issuer api.Issuer, clusterResourceNamespace string) string {
	if issuer.GetNamespace() == "" {
		return clusterResourceNamespace
	}
	return issuer.GetNamespace()
}

// readCredentials loads the auth token and, when configured, the CA bundle of
// an issuer.
//
// A missing Secret is transient: it may be created moments later. A Secret that
// exists but lacks the referenced key is a configuration mistake and is
// reported as permanent.
func readCredentials(ctx context.Context, c client.Client, spec *api.IssuerSpec, namespace string) (signer.Credentials, error) {
	var creds signer.Credentials

	token, err := readSecretKey(ctx, c, namespace, spec.AuthTokenSecretRef, defaultAuthTokenKey)
	if err != nil {
		return creds, fmt.Errorf("reading the key manager plus auth token: %w", err)
	}
	creds.AuthToken = strings.TrimSpace(string(token))
	if creds.AuthToken == "" {
		return creds, fmt.Errorf("%w: the auth token in secret %s/%s is empty",
			kmp.ErrInvalidConfig, namespace, spec.AuthTokenSecretRef.Name)
	}

	if spec.CABundleSecretRef != nil {
		bundle, err := readSecretKey(ctx, c, namespace, *spec.CABundleSecretRef, defaultCABundleKey)
		if err != nil {
			return creds, fmt.Errorf("reading the CA bundle: %w", err)
		}
		creds.CABundle = bundle
	}
	return creds, nil
}

// readSecretKey returns one key of one Secret.
func readSecretKey(ctx context.Context, c client.Client, namespace string, ref api.SecretKeySelector, defaultKey string) ([]byte, error) {
	if ref.Name == "" {
		return nil, fmt.Errorf("%w: no secret name is set", kmp.ErrInvalidConfig)
	}
	key := ref.Key
	if key == "" {
		key = defaultKey
	}

	var secret corev1.Secret
	name := types.NamespacedName{Namespace: namespace, Name: ref.Name}
	if err := c.Get(ctx, name, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			// Transient: the Secret may still be created.
			return nil, fmt.Errorf("secret %s not found", name)
		}
		return nil, fmt.Errorf("getting secret %s: %w", name, err)
	}

	value, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("%w: secret %s has no key %q", kmp.ErrInvalidConfig, name, key)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: key %q of secret %s is empty", kmp.ErrInvalidConfig, key, name)
	}
	return value, nil
}

// setCondition records a condition on an issuer status and reports whether
// anything changed.
func setCondition(status *api.IssuerStatus, generation int64, conditionType string, conditionStatus metav1.ConditionStatus, reason, message string) bool {
	now := metav1.Now()
	for i := range status.Conditions {
		existing := &status.Conditions[i]
		if existing.Type != conditionType {
			continue
		}
		if existing.Status == conditionStatus &&
			existing.Reason == reason &&
			existing.Message == message &&
			existing.ObservedGeneration == generation {
			return false
		}
		if existing.Status != conditionStatus {
			existing.LastTransitionTime = now
		}
		existing.Status = conditionStatus
		existing.Reason = reason
		existing.Message = message
		existing.ObservedGeneration = generation
		return true
	}

	status.Conditions = append(status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: now,
	})
	return true
}

// isReady reports whether an issuer passed its last connectivity check.
func isReady(status *api.IssuerStatus) bool {
	for _, condition := range status.Conditions {
		if condition.Type == api.IssuerConditionReady {
			return condition.Status == metav1.ConditionTrue
		}
	}
	return false
}

// healthCheckInterval returns the re-check interval of an issuer.
func healthCheckInterval(spec *api.IssuerSpec, fallback time.Duration) time.Duration {
	if spec.HealthCheckInterval != nil && spec.HealthCheckInterval.Duration > 0 {
		return spec.HealthCheckInterval.Duration
	}
	if fallback > 0 {
		return fallback
	}
	return defaultHealthCheckInterval
}
