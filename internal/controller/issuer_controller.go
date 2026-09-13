package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
	"github.com/mikeacameron/kmp-issuer/internal/signer"
)

// IssuerReconciler keeps the Ready condition of one issuer kind up to date by
// checking that Key Manager Plus is reachable with the configured credentials.
type IssuerReconciler struct {
	client.Client

	// Kind is either KMPIssuer or KMPClusterIssuer.
	Kind string

	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// ClusterResourceNamespace is where Secrets of cluster scoped issuers live.
	ClusterResourceNamespace string

	// SignerBuilder constructs the Key Manager Plus client to check with.
	SignerBuilder signer.Builder

	// HealthCheckInterval is the default re-check interval for issuers that do
	// not set one.
	HealthCheckInterval time.Duration
}

// +kubebuilder:rbac:groups=kmp.cert-manager.io,resources=kmpissuers;kmpclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=kmp.cert-manager.io,resources=kmpissuers/status;kmpclusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile checks one issuer and records the result in its Ready condition.
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := newIssuer(r.Kind)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if issuer.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	status := issuer.GetStatus()
	before := status.DeepCopy()
	interval := healthCheckInterval(issuer.GetSpec(), r.HealthCheckInterval)

	checkErr := r.check(ctx, issuer)
	switch {
	case checkErr == nil:
		setCondition(status, issuer.GetGeneration(), api.IssuerConditionReady, metav1.ConditionTrue,
			api.IssuerReasonChecked, "Key Manager Plus is reachable and the credentials were accepted")
	default:
		setCondition(status, issuer.GetGeneration(), api.IssuerConditionReady, metav1.ConditionFalse,
			api.IssuerReasonFailed, checkErr.Error())
	}

	if !equality.Semantic.DeepEqual(before, status) {
		if err := r.Status().Update(ctx, issuer); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating the status of %s %s: %w", r.Kind, req.NamespacedName, err)
		}
		if checkErr != nil {
			r.Recorder.Event(issuer, corev1.EventTypeWarning, api.IssuerReasonFailed, checkErr.Error())
		} else {
			r.Recorder.Event(issuer, corev1.EventTypeNormal, api.IssuerReasonChecked, "Key Manager Plus is reachable")
		}
	}

	if checkErr != nil {
		log.Error(checkErr, "the issuer is not usable", "kind", r.Kind)
		if kmp.IsPermanent(checkErr) {
			// The spec has to change before this can succeed, and a spec change
			// triggers a new reconcile.
			return ctrl.Result{}, nil
		}
		// Let the controller back off and try again.
		return ctrl.Result{}, checkErr
	}

	return ctrl.Result{RequeueAfter: interval}, nil
}

// check builds a signer from the issuer's configuration and asks Key Manager
// Plus whether it is reachable.
func (r *IssuerReconciler) check(ctx context.Context, issuer api.Issuer) error {
	spec := issuer.GetSpec()

	creds, err := readCredentials(ctx, r.Client, spec, secretNamespace(issuer, r.ClusterResourceNamespace))
	if err != nil {
		return err
	}
	kmpSigner, err := r.SignerBuilder(spec, creds)
	if err != nil {
		return err
	}
	if err := kmpSigner.Check(ctx); err != nil {
		return fmt.Errorf("checking the key manager plus API: %w", err)
	}
	return nil
}

// SetupWithManager registers the reconciler for its issuer kind.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuer, err := newIssuer(r.Kind)
	if err != nil {
		return err
	}
	if r.SignerBuilder == nil {
		r.SignerBuilder = signer.NewKMPSigner
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(issuer).
		Named(r.Kind).
		Complete(r)
}
