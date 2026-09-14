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

package v1alpha1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// AuthSecretTokenKey is the key of the Secret referenced by
	// spec.authSecretName that holds the Key Manager Plus AUTHTOKEN. The token
	// is generated per Key Manager Plus user under "Personalize -> API".
	AuthSecretTokenKey = "authtoken"

	// AuthSecretCABundleKey is the optional key of the same Secret holding a
	// PEM encoded bundle of CA certificates used to verify the TLS certificate
	// the Key Manager Plus server presents. When absent, the system trust store
	// of the controller is used.
	AuthSecretCABundleKey = "ca.crt"
)

// SignType selects how Key Manager Plus signs a certificate signing request.
// The values mirror the "signType" field of the Key Manager Plus signCSR API.
type SignType string

const (
	// SignTypeMSCA signs the CSR with a Microsoft Certificate Authority that
	// Key Manager Plus talks to directly. This is the Key Manager Plus default.
	SignTypeMSCA SignType = "MSCA"

	// SignTypeMSCAUsingAgent signs the CSR with a Microsoft Certificate
	// Authority reached through a Key Manager Plus agent. Requires Key Manager
	// Plus build 7030 or later.
	SignTypeMSCAUsingAgent SignType = "MSCAusingAgent"

	// SignTypeWithRoot signs the CSR with a root certificate held in the Key
	// Manager Plus certificate store.
	SignTypeWithRoot SignType = "signWithRoot"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type="string",JSONPath=".spec.url"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="string",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// KMPIssuer is the Schema for the kmpissuers API.
type KMPIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec            `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus `json:"status,omitempty"`
}

// IssuerSpec defines the desired state of KMPIssuer
type IssuerSpec struct {
	// URL is the base URL of the ManageEngine Key Manager Plus server,
	// including the scheme and the port its web interface listens on, for
	// example: "https://kmp.example.com:6565". The REST API path
	// ("/api/pki/restapi/...") is appended by the controller.
	//
	// +kubebuilder:validation:Pattern=`^https?://`
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`

	// A reference to a Secret in the same namespace as the referent. If the
	// referent is a KMPClusterIssuer, the reference instead refers to the resource
	// with the given name in the configured 'cluster resource namespace', which
	// is set as a flag on the controller component (and defaults to the
	// namespace that the controller runs in).
	//
	// The Secret must hold the Key Manager Plus AUTHTOKEN under the "authtoken"
	// key. It may also hold a PEM encoded CA bundle under "ca.crt", used to
	// verify the TLS certificate of the Key Manager Plus server.
	//
	// +kubebuilder:validation:MinLength=1
	AuthSecretName string `json:"authSecretName"`

	// Signing configures how Key Manager Plus should sign submitted requests.
	//
	// +optional
	Signing SigningSpec `json:"signing,omitempty"`

	// InsecureSkipTLSVerify disables verification of the Key Manager Plus
	// server certificate. It exists for evaluation against a Key Manager Plus
	// instance that still serves its default self-signed certificate and must
	// not be used in production; supply a CA bundle in the auth Secret instead.
	//
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// RequestTimeout bounds a single HTTP call to Key Manager Plus.
	// Defaults to 30s.
	//
	// +optional
	RequestTimeout *metav1.Duration `json:"requestTimeout,omitempty"`
}

// SigningSpec describes the signing back end Key Manager Plus should use.
// Which fields apply depends on signType.
type SigningSpec struct {
	// SignType selects the Key Manager Plus signing back end. Defaults to MSCA,
	// which is also the Key Manager Plus API default.
	//
	// +kubebuilder:validation:Enum=MSCA;MSCAusingAgent;signWithRoot
	// +kubebuilder:default=MSCA
	// +optional
	SignType SignType `json:"signType,omitempty"`

	// ServerName is the host name of the Microsoft CA server as registered in
	// Key Manager Plus. Required for the MSCA and MSCAusingAgent sign types.
	//
	// +optional
	ServerName string `json:"serverName,omitempty"`

	// CAName is the name of the certificate authority on the Microsoft CA
	// server. Required for the MSCA and MSCAusingAgent sign types.
	//
	// +optional
	CAName string `json:"caName,omitempty"`

	// TemplateName is the Microsoft CA certificate template to issue from, for
	// example "WebServer". Required for the MSCA and MSCAusingAgent sign types.
	//
	// +optional
	TemplateName string `json:"templateName,omitempty"`

	// AgentName is the name of the Key Manager Plus agent that reaches the
	// Microsoft CA. Required for the MSCAusingAgent sign type.
	//
	// +optional
	AgentName string `json:"agentName,omitempty"`

	// AgentResponseTimeoutSeconds is how long Key Manager Plus waits for the
	// agent to answer, in seconds. Only used with the MSCAusingAgent sign type.
	//
	// +kubebuilder:validation:Minimum=1
	// +optional
	AgentResponseTimeoutSeconds *int32 `json:"agentResponseTimeoutSeconds,omitempty"`

	// RootCertificateCommonName is the common name of the root certificate in
	// the Key Manager Plus store used to sign. Required for the signWithRoot
	// sign type.
	//
	// +optional
	RootCertificateCommonName string `json:"rootCertificateCommonName,omitempty"`

	// RootCertificateSerialNumber is the serial number of the root certificate
	// used to sign. Set it when several stored root certificates share a common
	// name. Only used with the signWithRoot sign type.
	//
	// +optional
	RootCertificateSerialNumber string `json:"rootCertificateSerialNumber,omitempty"`

	// ValidityDays is the requested lifetime of the issued certificate, in
	// days. Only used with the signWithRoot sign type; Microsoft CA templates
	// carry their own validity. When unset, the duration of the request is
	// used.
	//
	// +kubebuilder:validation:Minimum=1
	// +optional
	ValidityDays *int32 `json:"validityDays,omitempty"`

	// IsIntermediate marks the issued certificate as an intermediate CA
	// certificate. Only used with the signWithRoot sign type. When unset, the
	// isCA field of the request decides.
	//
	// +optional
	IsIntermediate *bool `json:"isIntermediate,omitempty"`

	// Email is recorded by Key Manager Plus against the imported CSR and is
	// used for its expiry notifications.
	//
	// +optional
	Email string `json:"email,omitempty"`

	// CSRLookupOperation names the Key Manager Plus REST operation that lists
	// stored certificate signing requests, for example "getCSRs".
	//
	// signCSR identifies the request to sign by its Key Manager Plus CSR_ID.
	// The documented importCSR response reports only whether the import
	// succeeded, so on such builds the id has to be looked up by common name
	// after importing, and this field names the operation to look it up with.
	// Leave it empty on builds whose importCSR response already carries the id;
	// issuance then reports what the response contained if the id is missing.
	//
	// +optional
	CSRLookupOperation string `json:"csrLookupOperation,omitempty"`
}

func (vi *KMPIssuer) GetConditions() []metav1.Condition {
	return vi.Status.Conditions
}

// GetIssuerTypeIdentifier returns a string that uniquely identifies the
// issuer type. This should be a constant across all instances of this
// issuer type. This string is used as a prefix when determining the
// issuer type for a Kubernetes CertificateSigningRequest resource based
// on the issuerName field. The value should be formatted as follows:
// "<issuer resource (plural)>.<issuer group>". For example, the value
// "simpleclusterissuers.issuer.cert-manager.io" will match all CSRs
// with an issuerName set to eg. "simpleclusterissuers.issuer.cert-manager.io/issuer1".
func (vi *KMPIssuer) GetIssuerTypeIdentifier() string {
	return "kmpissuers.kmp.cert-manager.io"
}

// issuer-lib requires that we implement the Issuer interface
// so that it can interact with our Issuer resource.
var _ v1alpha1.Issuer = &KMPIssuer{}

// +kubebuilder:object:root=true

// KMPIssuerList contains a list of KMPIssuer.
type KMPIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMPIssuer `json:"items"`
}
