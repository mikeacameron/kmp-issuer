package controller

import (
	"context"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/mikeacameron/kmp-issuer/api/v1alpha1"
	"github.com/mikeacameron/kmp-issuer/internal/kmp"
	"github.com/mikeacameron/kmp-issuer/internal/signer"
)

// testScheme knows the types the controllers work with.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme,
		cmapi.AddToScheme,
		api.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("building the test scheme: %v", err)
		}
	}
	return scheme
}

func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objects...).
		WithStatusSubresource(&cmapi.CertificateRequest{}, &api.KMPIssuer{}, &api.KMPClusterIssuer{}).
		Build()
}

// fakeSigner stands in for the Key Manager Plus client.
type fakeSigner struct {
	bundle   *kmp.Bundle
	signErr  error
	checkErr error
	signs    int
}

func (f *fakeSigner) Sign(_ context.Context, _ kmp.Request) (*kmp.Bundle, error) {
	f.signs++
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.bundle, nil
}

func (f *fakeSigner) Check(_ context.Context) error { return f.checkErr }

// builderFor returns a signer.Builder that always yields the given signer.
func builderFor(s *fakeSigner) signer.Builder {
	return func(_ *api.IssuerSpec, _ signer.Credentials) (signer.Signer, error) {
		return s, nil
	}
}

// failingBuilder returns a signer.Builder that always fails to configure.
func failingBuilder(err error) signer.Builder {
	return func(_ *api.IssuerSpec, _ signer.Credentials) (signer.Signer, error) {
		return nil, err
	}
}

const (
	testNamespace  = "app"
	testIssuerName = "kmp"
	testSecretName = "kmp-credentials"
)

func newTestSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
		Data:       map[string][]byte{defaultAuthTokenKey: []byte("A3164150-4C15-4AA4-918E-F258F38149F8")},
	}
}

func newTestIssuerSpec() api.IssuerSpec {
	return api.IssuerSpec{
		URL:                "https://kmp.example.com:6565",
		AuthTokenSecretRef: api.SecretKeySelector{Name: testSecretName},
		Signing: api.SigningSpec{
			SignType:     api.SignTypeMSCA,
			ServerName:   "ca1",
			CAName:       "ca1-ca",
			TemplateName: "WebServer",
		},
	}
}

// newTestIssuer returns a namespaced issuer, ready when ready is true.
func newTestIssuer(ready bool) *api.KMPIssuer {
	issuer := &api.KMPIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testNamespace},
		Spec:       newTestIssuerSpec(),
	}
	if ready {
		setCondition(&issuer.Status, issuer.Generation, api.IssuerConditionReady, metav1.ConditionTrue,
			api.IssuerReasonChecked, "ready")
	}
	return issuer
}
