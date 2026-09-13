package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Issuer is implemented by both KMPIssuer and KMPClusterIssuer so that the
// controllers can handle the namespaced and the cluster scoped kind with one
// code path. It is structurally compatible with controller-runtime's
// client.Object.
//
// +kubebuilder:object:generate=false
type Issuer interface {
	metav1.Object
	runtime.Object

	// GetSpec returns the issuer configuration.
	GetSpec() *IssuerSpec
	// GetStatus returns the mutable issuer status.
	GetStatus() *IssuerStatus
}

var (
	_ Issuer = &KMPIssuer{}
	_ Issuer = &KMPClusterIssuer{}
)

// GetSpec returns the issuer configuration.
func (i *KMPIssuer) GetSpec() *IssuerSpec { return &i.Spec }

// GetStatus returns the mutable issuer status.
func (i *KMPIssuer) GetStatus() *IssuerStatus { return &i.Status }

// GetSpec returns the issuer configuration.
func (i *KMPClusterIssuer) GetSpec() *IssuerSpec { return &i.Spec }

// GetStatus returns the mutable issuer status.
func (i *KMPClusterIssuer) GetStatus() *IssuerStatus { return &i.Status }
