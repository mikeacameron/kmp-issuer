package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
	"github.com/mikeacameron/kmp-issuer/internal/signer"
)

// issuerNotReadyRequeue is how long to wait before looking at a request whose
// issuer is not ready yet. Issuer changes also re-enqueue the request, so this
// is only a safety net.
const issuerNotReadyRequeue = 30 * time.Second

// CertificateRequestReconciler signs approved CertificateRequests that name a
// KMPIssuer or KMPClusterIssuer.
type CertificateRequestReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// ClusterResourceNamespace is where Secrets of cluster scoped issuers live.
	ClusterResourceNamespace string

	// SignerBuilder constructs the Key Manager Plus signer for an issuer.
	SignerBuilder signer.Builder

	// CheckApprovedCondition makes the controller wait for cert-manager's
	// approval before signing. It should only be turned off on clusters where
	// the approval feature is disabled.
	CheckApprovedCondition bool

	// MaxRetryDuration bounds how long a request may keep failing with retryable
	// errors before it is marked failed. Zero disables the bound.
	MaxRetryDuration time.Duration

	// Clock is swapped out in tests.
	Clock func() time.Time
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=signers,verbs=sign,resourceNames=kmpissuers.kmp.cert-manager.io/*;kmpclusterissuers.kmp.cert-manager.io/*

// Reconcile signs one CertificateRequest.
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Ignore requests for other issuer implementations.
	issuerRef := certificateRequest.Spec.IssuerRef
	if issuerRef.Group != api.GroupVersion.Group {
		return ctrl.Result{}, nil
	}
	switch issuerRef.Kind {
	case KMPIssuerKind, KMPClusterIssuerKind:
	default:
		return ctrl.Result{}, nil
	}

	// Nothing to do once the certificate has been issued, and a failed request
	// is replaced by cert-manager rather than retried here.
	if len(certificateRequest.Status.Certificate) > 0 || isFailed(&certificateRequest) {
		return ctrl.Result{}, nil
	}

	before := certificateRequest.DeepCopy()
	defer func() {
		if equality.Semantic.DeepEqual(before.Status, certificateRequest.Status) {
			return
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = errors.Join(err, fmt.Errorf("updating the status of certificate request %s: %w", req.NamespacedName, updateErr))
			result = ctrl.Result{}
		}
	}()

	if isDenied(&certificateRequest) {
		r.fail(&certificateRequest, cmapi.CertificateRequestReasonDenied, "The request was denied by an approval controller")
		return ctrl.Result{}, nil
	}

	if r.CheckApprovedCondition && !isApproved(&certificateRequest) {
		log.V(1).Info("waiting for the request to be approved")
		r.pending(&certificateRequest, "Waiting for the request to be approved")
		return ctrl.Result{}, nil
	}

	issuer, err := r.resolveIssuer(ctx, &certificateRequest)
	if err != nil {
		return r.retryOrFail(&certificateRequest, fmt.Errorf("resolving the issuer: %w", err))
	}

	if !isReady(issuer.GetStatus()) {
		message := fmt.Sprintf("%s %s is not ready", issuerRef.Kind, issuerRef.Name)
		log.V(1).Info(message)
		r.pending(&certificateRequest, message)
		return ctrl.Result{RequeueAfter: issuerNotReadyRequeue}, nil
	}

	creds, err := readCredentials(ctx, r.Client, issuer.GetSpec(), secretNamespace(issuer, r.ClusterResourceNamespace))
	if err != nil {
		return r.retryOrFail(&certificateRequest, fmt.Errorf("reading the issuer credentials: %w", err))
	}

	kmpSigner, err := r.SignerBuilder(issuer.GetSpec(), creds)
	if err != nil {
		return r.retryOrFail(&certificateRequest, fmt.Errorf("configuring the key manager plus client: %w", err))
	}

	bundle, err := kmpSigner.Sign(ctx, kmp.Request{
		CSRPEM:   certificateRequest.Spec.Request,
		Duration: requestedDuration(&certificateRequest),
		IsCA:     certificateRequest.Spec.IsCA,
	})
	if err != nil {
		return r.retryOrFail(&certificateRequest, fmt.Errorf("signing the request with key manager plus: %w", err))
	}

	certificateRequest.Status.Certificate = bundle.Certificate
	certificateRequest.Status.CA = bundle.CA
	setCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonIssued, "Signed by Key Manager Plus")
	r.Recorder.Event(&certificateRequest, corev1.EventTypeNormal, cmapi.CertificateRequestReasonIssued, "Signed by Key Manager Plus")
	log.Info("issued the certificate", "issuer", issuerRef.Name, "kind", issuerRef.Kind)

	return ctrl.Result{}, nil
}

// resolveIssuer loads the issuer a request names. Namespaced issuers are read
// from the namespace of the request.
func (r *CertificateRequestReconciler) resolveIssuer(ctx context.Context, cr *cmapi.CertificateRequest) (api.Issuer, error) {
	issuer, err := newIssuer(cr.Spec.IssuerRef.Kind)
	if err != nil {
		return nil, err
	}
	name := types.NamespacedName{Name: cr.Spec.IssuerRef.Name}
	if cr.Spec.IssuerRef.Kind == KMPIssuerKind {
		name.Namespace = cr.Namespace
	}
	if err := r.Get(ctx, name, issuer); err != nil {
		return nil, fmt.Errorf("getting %s %s: %w", cr.Spec.IssuerRef.Kind, name, err)
	}
	return issuer, nil
}

// retryOrFail records a failure. Configuration errors and rejections by Key
// Manager Plus fail the request outright, because retrying the same request
// cannot succeed; everything else keeps the request pending and is retried with
// backoff until MaxRetryDuration expires.
func (r *CertificateRequestReconciler) retryOrFail(cr *cmapi.CertificateRequest, err error) (ctrl.Result, error) {
	if kmp.IsPermanent(err) {
		r.fail(cr, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}
	if r.MaxRetryDuration > 0 && r.now().Sub(cr.CreationTimestamp.Time) > r.MaxRetryDuration {
		r.fail(cr, cmapi.CertificateRequestReasonFailed,
			fmt.Sprintf("Giving up after %s: %s", r.MaxRetryDuration, err))
		return ctrl.Result{}, nil
	}
	r.pending(cr, err.Error())
	return ctrl.Result{}, err
}

// fail marks a request as permanently failed.
func (r *CertificateRequestReconciler) fail(cr *cmapi.CertificateRequest, reason, message string) {
	if cr.Status.FailureTime == nil {
		now := metav1.Now()
		cr.Status.FailureTime = &now
	}
	setCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, reason, message)
	r.Recorder.Event(cr, corev1.EventTypeWarning, reason, message)
}

// pending records that the request is not signed yet.
func (r *CertificateRequestReconciler) pending(cr *cmapi.CertificateRequest, message string) {
	setCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending, message)
}

func (r *CertificateRequestReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// requestedDuration returns the certificate lifetime cert-manager asked for, if
// any.
func requestedDuration(cr *cmapi.CertificateRequest) time.Duration {
	if cr.Spec.Duration == nil {
		return 0
	}
	return cr.Spec.Duration.Duration
}

// SetupWithManager registers the reconciler and makes issuer changes re-enqueue
// the requests that wait for them.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.SignerBuilder == nil {
		r.SignerBuilder = signer.NewKMPSigner
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Named("certificaterequest").
		Watches(&api.KMPIssuer{}, handler.EnqueueRequestsFromMapFunc(r.requestsForIssuer(KMPIssuerKind))).
		Watches(&api.KMPClusterIssuer{}, handler.EnqueueRequestsFromMapFunc(r.requestsForIssuer(KMPClusterIssuerKind))).
		Complete(r)
}

// requestsForIssuer maps an issuer to the unsigned requests that name it.
func (r *CertificateRequestReconciler) requestsForIssuer(kind string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		log := ctrl.LoggerFrom(ctx)

		var list cmapi.CertificateRequestList
		var opts []client.ListOption
		if kind == KMPIssuerKind {
			opts = append(opts, client.InNamespace(obj.GetNamespace()))
		}
		if err := r.List(ctx, &list, opts...); err != nil {
			log.Error(err, "listing certificate requests for an issuer change", "kind", kind, "issuer", obj.GetName())
			return nil
		}

		var requests []reconcile.Request
		for i := range list.Items {
			cr := &list.Items[i]
			ref := cr.Spec.IssuerRef
			if ref.Group != api.GroupVersion.Group || ref.Kind != kind || ref.Name != obj.GetName() {
				continue
			}
			if len(cr.Status.Certificate) > 0 || isFailed(cr) {
				continue
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name},
			})
		}
		return requests
	}
}
