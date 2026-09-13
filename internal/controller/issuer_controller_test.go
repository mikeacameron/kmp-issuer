package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

func reconcileIssuer(t *testing.T, r *IssuerReconciler, c client.Client, name types.NamespacedName) (ctrl.Result, error) {
	t.Helper()
	r.Client = c
	if r.Recorder == nil {
		r.Recorder = record.NewFakeRecorder(16)
	}
	return r.Reconcile(context.Background(), ctrl.Request{NamespacedName: name})
}

func getIssuer(t *testing.T, c client.Client) *api.KMPIssuer {
	t.Helper()
	var issuer api.KMPIssuer
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testIssuerName}, &issuer); err != nil {
		t.Fatalf("getting the issuer: %v", err)
	}
	return &issuer
}

func issuerName() types.NamespacedName {
	return types.NamespacedName{Namespace: testNamespace, Name: testIssuerName}
}

func TestIssuerBecomesReady(t *testing.T) {
	c := newFakeClient(t, newTestIssuer(false), newTestSecret())
	r := &IssuerReconciler{Kind: KMPIssuerKind, SignerBuilder: builderFor(&fakeSigner{})}

	result, err := reconcileIssuer(t, r, c, issuerName())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter != defaultHealthCheckInterval {
		t.Errorf("RequeueAfter = %s, want the default health check interval %s", result.RequeueAfter, defaultHealthCheckInterval)
	}
	if !isReady(&getIssuer(t, c).Status) {
		t.Error("the issuer is not ready after a successful check")
	}
}

func TestIssuerHonoursItsHealthCheckInterval(t *testing.T) {
	issuer := newTestIssuer(false)
	issuer.Spec.HealthCheckInterval = &metav1.Duration{Duration: 90 * time.Second}
	c := newFakeClient(t, issuer, newTestSecret())
	r := &IssuerReconciler{Kind: KMPIssuerKind, SignerBuilder: builderFor(&fakeSigner{})}

	result, err := reconcileIssuer(t, r, c, issuerName())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter != 90*time.Second {
		t.Errorf("RequeueAfter = %s, want 90s", result.RequeueAfter)
	}
}

func TestIssuerReportsAnUnreachableServer(t *testing.T) {
	c := newFakeClient(t, newTestIssuer(true), newTestSecret())
	r := &IssuerReconciler{
		Kind:          KMPIssuerKind,
		SignerBuilder: builderFor(&fakeSigner{checkErr: errors.New("dial tcp: connection refused")}),
	}

	if _, err := reconcileIssuer(t, r, c, issuerName()); err == nil {
		t.Fatal("Reconcile succeeded although the check failed, want the error returned so the controller backs off")
	}
	issuer := getIssuer(t, c)
	if isReady(&issuer.Status) {
		t.Error("the issuer is still ready after a failed check")
	}
	if message := readyConditionMessage(&issuer.Status); !strings.Contains(message, "connection refused") {
		t.Errorf("ready message = %q, want it to mention the connection failure", message)
	}
}

func TestIssuerDoesNotRetryConfigurationErrors(t *testing.T) {
	c := newFakeClient(t, newTestIssuer(false), newTestSecret())
	r := &IssuerReconciler{
		Kind:          KMPIssuerKind,
		SignerBuilder: failingBuilder(fmt.Errorf("%w: signType MSCA requires signing.caName", kmp.ErrInvalidConfig)),
	}

	result, err := reconcileIssuer(t, r, c, issuerName())
	if err != nil {
		t.Fatalf("Reconcile returned an error for a configuration problem, want it recorded in the status instead: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %s, want no requeue until the spec changes", result.RequeueAfter)
	}
	if isReady(&getIssuer(t, c).Status) {
		t.Error("a misconfigured issuer is ready")
	}
}

func TestIssuerReportsAMissingSecret(t *testing.T) {
	c := newFakeClient(t, newTestIssuer(false)) // no Secret
	r := &IssuerReconciler{Kind: KMPIssuerKind, SignerBuilder: builderFor(&fakeSigner{})}

	if _, err := reconcileIssuer(t, r, c, issuerName()); err == nil {
		t.Fatal("Reconcile succeeded without the credentials Secret, want a retryable error")
	}
	if isReady(&getIssuer(t, c).Status) {
		t.Error("the issuer is ready although its Secret is missing")
	}
}

func TestIssuerIgnoresAMissingObject(t *testing.T) {
	c := newFakeClient(t)
	r := &IssuerReconciler{Kind: KMPIssuerKind, SignerBuilder: builderFor(&fakeSigner{})}

	if _, err := reconcileIssuer(t, r, c, issuerName()); err != nil {
		t.Fatalf("Reconcile of a deleted issuer: %v", err)
	}
}

func TestClusterIssuerReadsSecretsFromTheControllerNamespace(t *testing.T) {
	clusterIssuer := &api.KMPClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName},
		Spec:       newTestIssuerSpec(),
	}
	secret := newTestSecret()
	secret.Namespace = "cert-manager"

	c := newFakeClient(t, clusterIssuer, secret)
	r := &IssuerReconciler{
		Kind:                     KMPClusterIssuerKind,
		SignerBuilder:            builderFor(&fakeSigner{}),
		ClusterResourceNamespace: "cert-manager",
	}

	if _, err := reconcileIssuer(t, r, c, types.NamespacedName{Name: testIssuerName}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var got api.KMPClusterIssuer
	if err := c.Get(context.Background(), types.NamespacedName{Name: testIssuerName}, &got); err != nil {
		t.Fatalf("getting the cluster issuer: %v", err)
	}
	if !isReady(&got.Status) {
		t.Error("the cluster issuer is not ready after a successful check")
	}
}

func TestNewIssuerRejectsUnknownKinds(t *testing.T) {
	if _, err := newIssuer("Whatever"); err == nil {
		t.Fatal("newIssuer accepted an unknown kind")
	} else if !kmp.IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true", err)
	}
}

func TestSetConditionReportsChanges(t *testing.T) {
	var status api.IssuerStatus
	if changed := setCondition(&status, 1, api.IssuerConditionReady, metav1.ConditionTrue, api.IssuerReasonChecked, "ok"); !changed {
		t.Error("adding a condition reported no change")
	}
	if changed := setCondition(&status, 1, api.IssuerConditionReady, metav1.ConditionTrue, api.IssuerReasonChecked, "ok"); changed {
		t.Error("re-setting an identical condition reported a change")
	}

	first := status.Conditions[0].LastTransitionTime
	if changed := setCondition(&status, 1, api.IssuerConditionReady, metav1.ConditionFalse, api.IssuerReasonFailed, "broken"); !changed {
		t.Error("flipping a condition reported no change")
	}
	if status.Conditions[0].LastTransitionTime == first && !first.IsZero() {
		t.Error("the transition time was not refreshed when the status flipped")
	}
	if len(status.Conditions) != 1 {
		t.Errorf("conditions = %d, want the Ready condition to be updated in place", len(status.Conditions))
	}
}

func TestHealthCheckInterval(t *testing.T) {
	spec := &api.IssuerSpec{}
	if got := healthCheckInterval(spec, 0); got != defaultHealthCheckInterval {
		t.Errorf("healthCheckInterval = %s, want %s", got, defaultHealthCheckInterval)
	}
	if got := healthCheckInterval(spec, time.Minute); got != time.Minute {
		t.Errorf("healthCheckInterval = %s, want the controller default of 1m", got)
	}
	spec.HealthCheckInterval = &metav1.Duration{Duration: 2 * time.Minute}
	if got := healthCheckInterval(spec, time.Minute); got != 2*time.Minute {
		t.Errorf("healthCheckInterval = %s, want the issuer setting of 2m", got)
	}
}

// readyConditionMessage returns the message of the Ready condition.
func readyConditionMessage(status *api.IssuerStatus) string {
	for _, condition := range status.Conditions {
		if condition.Type == api.IssuerConditionReady {
			return condition.Message
		}
	}
	return ""
}
