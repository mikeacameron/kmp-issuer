// Command manager runs the cert-manager external issuer for ManageEngine Key
// Manager Plus.
package main

import (
	"flag"
	"os"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(api.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr              string
		probeAddr                string
		enableLeaderElection     bool
		clusterResourceNamespace string
		disableApprovedCheck     bool
		healthCheckInterval      time.Duration
		maxRetryDuration         time.Duration
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the metric endpoint binds to. Set to 0 to disable metrics.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election, so that only one manager is active at a time.")
	flag.StringVar(&clusterResourceNamespace, "cluster-resource-namespace", defaultClusterResourceNamespace(),
		"The namespace Secrets referenced by a KMPClusterIssuer are read from.")
	flag.BoolVar(&disableApprovedCheck, "disable-approved-check", false,
		"Sign CertificateRequests that carry no Approved condition. Only for clusters where cert-manager's approval is disabled.")
	flag.DurationVar(&healthCheckInterval, "health-check-interval", 5*time.Minute,
		"How often to re-check the Key Manager Plus connectivity of issuers that do not set spec.healthCheckInterval.")
	flag.DurationVar(&maxRetryDuration, "max-retry-duration", 10*time.Minute,
		"How long to keep retrying a CertificateRequest that fails with retryable errors before marking it failed. Set to 0 to retry indefinitely.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "kmp-issuer.kmp.cert-manager.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start the manager")
		os.Exit(1)
	}

	for _, kind := range []string{controller.KMPIssuerKind, controller.KMPClusterIssuerKind} {
		issuerReconciler := &controller.IssuerReconciler{
			Client:                   mgr.GetClient(),
			Kind:                     kind,
			Scheme:                   mgr.GetScheme(),
			Recorder:                 mgr.GetEventRecorderFor("kmp-issuer"),
			ClusterResourceNamespace: clusterResourceNamespace,
			HealthCheckInterval:      healthCheckInterval,
		}
		if err := issuerReconciler.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to set up the issuer controller", "kind", kind)
			os.Exit(1)
		}
	}

	certificateRequestReconciler := &controller.CertificateRequestReconciler{
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		Recorder:                 mgr.GetEventRecorderFor("kmp-issuer"),
		ClusterResourceNamespace: clusterResourceNamespace,
		CheckApprovedCondition:   !disableApprovedCheck,
		MaxRetryDuration:         maxRetryDuration,
	}
	if err := certificateRequestReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up the certificate request controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up the health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up the readiness check")
		os.Exit(1)
	}

	setupLog.Info("starting the manager", "clusterResourceNamespace", clusterResourceNamespace)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "the manager exited with an error")
		os.Exit(1)
	}
}

// defaultClusterResourceNamespace prefers the namespace the controller runs in,
// which the deployment exposes as POD_NAMESPACE.
func defaultClusterResourceNamespace() string {
	if namespace := os.Getenv("POD_NAMESPACE"); namespace != "" {
		return namespace
	}
	return "cert-manager"
}
