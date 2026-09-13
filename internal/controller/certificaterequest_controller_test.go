package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
)

const testRequestName = "app-certificate"

// certificateRequestOption customises the request under test.
type certificateRequestOption func(*cmapi.CertificateRequest)

func withKind(kind string) certificateRequestOption {
	return func(cr *cmapi.CertificateRequest) { cr.Spec.IssuerRef.Kind = kind }
}

func withGroup(group string) certificateRequestOption {
	return func(cr *cmapi.CertificateRequest) { cr.Spec.IssuerRef.Group = group }
}

func approved() certificateRequestOption {
	return func(cr *cmapi.CertificateRequest) {
		setCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "approved")
	}
}

func denied() certificateRequestOption {
	return func(cr *cmapi.CertificateRequest) {
		setCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "denied")
	}
}

func createdAt(t time.Time) certificateRequestOption {
	return func(cr *cmapi.CertificateRequest) { cr.CreationTimestamp = metav1.NewTime(t) }
}

func newCertificateRequest(opts ...certificateRequestOption) *cmapi.CertificateRequest {
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              testRequestName,
			Namespace:         testNamespace,
			CreationTimestamp: metav1.Now(),
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: []byte("-----BEGIN CERTIFICATE REQUEST-----\nplaceholder\n-----END CERTIFICATE REQUEST-----\n"),
			IssuerRef: cmmeta.ObjectReference{
				Name:  testIssuerName,
				Kind:  KMPIssuerKind,
				Group: api.GroupVersion.Group,
			},
		},
	}
	for _, opt := range opts {
		opt(cr)
	}
	return cr
}

// reconcileRequest runs one reconcile against the given objects.
func reconcileRequest(t *testing.T, r *CertificateRequestReconciler, c client.Client) (ctrl.Result, error) {
	t.Helper()
	r.Client = c
	if r.Recorder == nil {
		r.Recorder = record.NewFakeRecorder(16)
	}
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testRequestName},
	})
}

func getRequest(t *testing.T, c client.Client) *cmapi.CertificateRequest {
	t.Helper()
	var cr cmapi.CertificateRequest
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testRequestName}, &cr); err != nil {
		t.Fatalf("getting the certificate request: %v", err)
	}
	return &cr
}

func TestCertificateRequestIgnoresOtherIssuers(t *testing.T) {
	tests := []struct {
		name string
		opts []certificateRequestOption
	}{
		{name: "another API group", opts: []certificateRequestOption{withGroup("awspca.cert-manager.io"), approved()}},
		{name: "another kind in this group", opts: []certificateRequestOption{withKind("SomeOtherIssuer"), approved()}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer := &fakeSigner{}
			c := newFakeClient(t, newCertificateRequest(tc.opts...), newTestIssuer(true), newTestSecret())
			r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

			if _, err := reconcileRequest(t, r, c); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if signer.signs != 0 {
				t.Errorf("the request was signed %d times, want 0", signer.signs)
			}
			if got := getRequest(t, c); len(got.Status.Conditions) > 1 {
				t.Errorf("conditions were changed on a request this issuer does not own: %v", got.Status.Conditions)
			}
		})
	}
}

func TestCertificateRequestWaitsForApproval(t *testing.T) {
	signer := &fakeSigner{}
	c := newFakeClient(t, newCertificateRequest(), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if signer.signs != 0 {
		t.Errorf("an unapproved request was signed %d times, want 0", signer.signs)
	}
	if reason := certificateRequestReadyReason(getRequest(t, c)); reason != cmapi.CertificateRequestReasonPending {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonPending)
	}
}

func TestCertificateRequestSignsWithoutApprovalWhenDisabled(t *testing.T) {
	signer := &fakeSigner{bundle: &kmp.Bundle{Certificate: []byte("cert"), CA: []byte("ca")}}
	c := newFakeClient(t, newCertificateRequest(), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: false}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if signer.signs != 1 {
		t.Fatalf("the request was signed %d times, want 1", signer.signs)
	}
}

func TestCertificateRequestFailsWhenDenied(t *testing.T) {
	signer := &fakeSigner{}
	c := newFakeClient(t, newCertificateRequest(denied()), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := getRequest(t, c)
	if reason := certificateRequestReadyReason(got); reason != cmapi.CertificateRequestReasonDenied {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonDenied)
	}
	if got.Status.FailureTime == nil {
		t.Error("failureTime was not set on a denied request")
	}
	if signer.signs != 0 {
		t.Errorf("a denied request was signed %d times, want 0", signer.signs)
	}
}

func TestCertificateRequestWaitsForTheIssuer(t *testing.T) {
	signer := &fakeSigner{}
	c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(false), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	result, err := reconcileRequest(t, r, c)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("the request was not requeued while the issuer is not ready")
	}
	if signer.signs != 0 {
		t.Errorf("the request was signed %d times while the issuer was not ready, want 0", signer.signs)
	}
	if reason := certificateRequestReadyReason(getRequest(t, c)); reason != cmapi.CertificateRequestReasonPending {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonPending)
	}
}

func TestCertificateRequestIssues(t *testing.T) {
	bundle := &kmp.Bundle{Certificate: []byte("-----BEGIN CERTIFICATE-----\nleaf\n"), CA: []byte("-----BEGIN CERTIFICATE-----\nroot\n")}
	signer := &fakeSigner{bundle: bundle}
	recorder := record.NewFakeRecorder(16)
	c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true, Recorder: recorder}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := getRequest(t, c)
	if string(got.Status.Certificate) != string(bundle.Certificate) {
		t.Errorf("status.certificate = %q, want the signed certificate", got.Status.Certificate)
	}
	if string(got.Status.CA) != string(bundle.CA) {
		t.Errorf("status.ca = %q, want the root certificate", got.Status.CA)
	}
	if reason := certificateRequestReadyReason(got); reason != cmapi.CertificateRequestReasonIssued {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonIssued)
	}
	if !certificateRequestHasCondition(got, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue) {
		t.Error("the Ready condition is not true after issuance")
	}
}

func TestCertificateRequestIsNotSignedTwice(t *testing.T) {
	signer := &fakeSigner{bundle: &kmp.Bundle{Certificate: []byte("cert")}}
	c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	for i := 0; i < 2; i++ {
		if _, err := reconcileRequest(t, r, c); err != nil {
			t.Fatalf("Reconcile %d: %v", i, err)
		}
	}
	if signer.signs != 1 {
		t.Errorf("the request was signed %d times, want 1", signer.signs)
	}
}

func TestCertificateRequestFailsOnPermanentErrors(t *testing.T) {
	tests := []struct {
		name    string
		build   func() *CertificateRequestReconciler
		wantMsg string
	}{
		{
			name: "signing configuration is rejected",
			build: func() *CertificateRequestReconciler {
				return &CertificateRequestReconciler{
					SignerBuilder:          failingBuilder(fmt.Errorf("%w: signType MSCA requires signing.templateName", kmp.ErrInvalidConfig)),
					CheckApprovedCondition: true,
				}
			},
			wantMsg: "signing.templateName",
		},
		{
			name: "key manager plus rejects the request",
			build: func() *CertificateRequestReconciler {
				return &CertificateRequestReconciler{
					SignerBuilder:          builderFor(&fakeSigner{signErr: &kmp.Error{Op: "signCSR", Message: "Template not found", Permanent: true}}),
					CheckApprovedCondition: true,
				}
			},
			wantMsg: "Template not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(true), newTestSecret())
			r := tc.build()

			if _, err := reconcileRequest(t, r, c); err != nil {
				t.Fatalf("Reconcile returned an error for a permanent failure, want the request to be failed instead: %v", err)
			}
			got := getRequest(t, c)
			if reason := certificateRequestReadyReason(got); reason != cmapi.CertificateRequestReasonFailed {
				t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonFailed)
			}
			if got.Status.FailureTime == nil {
				t.Error("failureTime was not set on a failed request")
			}
			if message := readyMessage(got); !strings.Contains(message, tc.wantMsg) {
				t.Errorf("ready message = %q, want it to mention %q", message, tc.wantMsg)
			}
		})
	}
}

func TestCertificateRequestRetriesTransientErrors(t *testing.T) {
	signer := &fakeSigner{signErr: &kmp.Error{Op: "signCSR", StatusCode: 503}}
	c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	_, err := reconcileRequest(t, r, c)
	if err == nil {
		t.Fatal("Reconcile succeeded on a transient error, want the error to be returned so the controller retries")
	}
	got := getRequest(t, c)
	if reason := certificateRequestReadyReason(got); reason != cmapi.CertificateRequestReasonPending {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonPending)
	}
	if got.Status.FailureTime != nil {
		t.Error("failureTime was set on a retryable failure")
	}
}

func TestCertificateRequestGivesUpAfterMaxRetryDuration(t *testing.T) {
	now := time.Now()
	signer := &fakeSigner{signErr: &kmp.Error{Op: "signCSR", StatusCode: 503}}
	c := newFakeClient(t, newCertificateRequest(approved(), createdAt(now.Add(-time.Hour))), newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{
		SignerBuilder:          builderFor(signer),
		CheckApprovedCondition: true,
		MaxRetryDuration:       10 * time.Minute,
		Clock:                  func() time.Time { return now },
	}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if reason := certificateRequestReadyReason(getRequest(t, c)); reason != cmapi.CertificateRequestReasonFailed {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonFailed)
	}
}

func TestCertificateRequestRetriesAMissingSecret(t *testing.T) {
	signer := &fakeSigner{bundle: &kmp.Bundle{Certificate: []byte("cert")}}
	c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(true)) // no Secret
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	if _, err := reconcileRequest(t, r, c); err == nil {
		t.Fatal("Reconcile succeeded without the credentials Secret, want a retryable error")
	}
	if reason := certificateRequestReadyReason(getRequest(t, c)); reason != cmapi.CertificateRequestReasonPending {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonPending)
	}
}

func TestCertificateRequestFailsOnAMisconfiguredSecret(t *testing.T) {
	secret := newTestSecret()
	secret.Data = map[string][]byte{"wrong-key": []byte("token")}
	signer := &fakeSigner{}
	c := newFakeClient(t, newCertificateRequest(approved()), newTestIssuer(true), secret)
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile returned an error for a misconfigured Secret, want the request to be failed instead: %v", err)
	}
	if reason := certificateRequestReadyReason(getRequest(t, c)); reason != cmapi.CertificateRequestReasonFailed {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonFailed)
	}
}

func TestCertificateRequestDoesNotRetryAFailedRequest(t *testing.T) {
	cr := newCertificateRequest(approved())
	setCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonFailed, "gave up earlier")
	signer := &fakeSigner{bundle: &kmp.Bundle{Certificate: []byte("cert")}}
	c := newFakeClient(t, cr, newTestIssuer(true), newTestSecret())
	r := &CertificateRequestReconciler{SignerBuilder: builderFor(signer), CheckApprovedCondition: true}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if signer.signs != 0 {
		t.Errorf("a failed request was signed %d times, want 0", signer.signs)
	}
}

func TestCertificateRequestUsesTheClusterIssuer(t *testing.T) {
	clusterIssuer := &api.KMPClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName},
		Spec:       newTestIssuerSpec(),
	}
	setCondition(&clusterIssuer.Status, 0, api.IssuerConditionReady, metav1.ConditionTrue, api.IssuerReasonChecked, "ready")

	// The credentials of a cluster scoped issuer live in the controller's
	// namespace, not in the namespace of the request.
	secret := newTestSecret()
	secret.Namespace = "cert-manager"

	signer := &fakeSigner{bundle: &kmp.Bundle{Certificate: []byte("cert")}}
	c := newFakeClient(t, newCertificateRequest(approved(), withKind(KMPClusterIssuerKind)), clusterIssuer, secret)
	r := &CertificateRequestReconciler{
		SignerBuilder:            builderFor(signer),
		CheckApprovedCondition:   true,
		ClusterResourceNamespace: "cert-manager",
	}

	if _, err := reconcileRequest(t, r, c); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if signer.signs != 1 {
		t.Errorf("the request was signed %d times, want 1", signer.signs)
	}
}

func TestRequestedDuration(t *testing.T) {
	cr := newCertificateRequest()
	if got := requestedDuration(cr); got != 0 {
		t.Errorf("requestedDuration of a request without a duration = %s, want 0", got)
	}
	cr.Spec.Duration = &metav1.Duration{Duration: 48 * time.Hour}
	if got := requestedDuration(cr); got != 48*time.Hour {
		t.Errorf("requestedDuration = %s, want 48h", got)
	}
}

func TestRetryOrFailClassifiesErrors(t *testing.T) {
	r := &CertificateRequestReconciler{Recorder: record.NewFakeRecorder(4)}
	cr := newCertificateRequest()

	if _, err := r.retryOrFail(cr, errors.New("connection refused")); err == nil {
		t.Error("a transient error was swallowed, want it returned for a retry")
	}
	if _, err := r.retryOrFail(cr, fmt.Errorf("%w: bad template", kmp.ErrInvalidConfig)); err != nil {
		t.Errorf("a permanent error was returned for a retry: %v", err)
	}
	if reason := certificateRequestReadyReason(cr); reason != cmapi.CertificateRequestReasonFailed {
		t.Errorf("ready reason = %q, want %q", reason, cmapi.CertificateRequestReasonFailed)
	}
}

// readyMessage returns the message of the Ready condition.
func readyMessage(cr *cmapi.CertificateRequest) string {
	for _, condition := range cr.Status.Conditions {
		if condition.Type == cmapi.CertificateRequestConditionReady {
			return condition.Message
		}
	}
	return ""
}
