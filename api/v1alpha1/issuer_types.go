package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SignType selects how Key Manager Plus signs a certificate signing request.
//
// The values mirror the "signType" field of the Key Manager Plus signCSR API.
type SignType string

const (
	// SignTypeMSCA signs the CSR with a Microsoft Certificate Authority that
	// Key Manager Plus talks to directly. This is the Key Manager Plus default.
	SignTypeMSCA SignType = "MSCA"

	// SignTypeMSCAUsingAgent signs the CSR with a Microsoft Certificate
	// Authority reached through a Key Manager Plus agent. Requires KMP build
	// 7030 or later.
	SignTypeMSCAUsingAgent SignType = "MSCAusingAgent"

	// SignTypeWithRoot signs the CSR with a root certificate held in the Key
	// Manager Plus certificate store.
	SignTypeWithRoot SignType = "signWithRoot"
)

// IssuerSpec is the shared spec of KMPIssuer and KMPClusterIssuer.
type IssuerSpec struct {
	// URL is the base URL of the Key Manager Plus server, including the scheme
	// and the port the web interface listens on, for example
	// "https://kmp.example.com:6565". The REST API path
	// ("/api/pki/restapi/...") is appended by the controller.
	//
	// +kubebuilder:validation:Pattern=`^https?://`
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`

	// AuthTokenSecretRef references the Secret holding the Key Manager Plus
	// AUTHTOKEN used to authenticate REST API calls. The token is generated per
	// KMP user under "Personalize -> API".
	//
	// For a KMPIssuer the Secret is read from the issuer's own namespace. For a
	// KMPClusterIssuer it is read from the namespace given by the controller's
	// --cluster-resource-namespace flag.
	AuthTokenSecretRef SecretKeySelector `json:"authTokenSecretRef"`

	// Signing configures how Key Manager Plus should sign submitted requests.
	// +optional
	Signing SigningSpec `json:"signing,omitempty"`

	// CABundle is a PEM encoded bundle of CA certificates used to verify the
	// TLS certificate presented by the Key Manager Plus server. When empty, the
	// system trust store of the controller is used.
	//
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	// CABundleSecretRef references a Secret key holding a PEM encoded CA bundle
	// used to verify the Key Manager Plus server certificate. It is an
	// alternative to inlining the bundle in caBundle; if both are set the
	// contents are concatenated.
	//
	// +optional
	CABundleSecretRef *SecretKeySelector `json:"caBundleSecretRef,omitempty"`

	// InsecureSkipTLSVerify disables verification of the Key Manager Plus
	// server certificate. It exists for evaluation against a KMP instance that
	// still serves its default self-signed certificate and must not be used in
	// production; prefer caBundle.
	//
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// RequestTimeout bounds a single HTTP call to Key Manager Plus.
	// Defaults to 30s.
	//
	// +optional
	RequestTimeout *metav1.Duration `json:"requestTimeout,omitempty"`

	// HealthCheckInterval is how often the issuer's connectivity to Key Manager
	// Plus is re-checked. Defaults to 5m.
	//
	// +optional
	HealthCheckInterval *metav1.Duration `json:"healthCheckInterval,omitempty"`
}

// SigningSpec describes the signing back end used for the CSRs submitted by
// this issuer. Which fields apply depends on signType.
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
	// carry their own validity. When unset, the request's own duration is used
	// if cert-manager supplied one, otherwise Key Manager Plus decides.
	//
	// +kubebuilder:validation:Minimum=1
	// +optional
	ValidityDays *int32 `json:"validityDays,omitempty"`

	// IsIntermediate marks the issued certificate as an intermediate CA
	// certificate. Only used with the signWithRoot sign type. When unset, the
	// isCA field of the CertificateRequest decides.
	//
	// +optional
	IsIntermediate *bool `json:"isIntermediate,omitempty"`

	// Email is recorded by Key Manager Plus against the imported CSR and is
	// used for its expiry notifications.
	//
	// +optional
	Email string `json:"email,omitempty"`
}

// SecretKeySelector references one key of one Secret.
type SecretKeySelector struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key within the Secret. Defaults to "authtoken" for auth token references
	// and to "ca.crt" for CA bundle references.
	// +optional
	Key string `json:"key,omitempty"`
}

// IssuerStatus is the shared status of KMPIssuer and KMPClusterIssuer.
type IssuerStatus struct {
	// Conditions holds the observed state of the issuer. The "Ready" condition
	// reports whether the controller can reach Key Manager Plus with the
	// configured credentials.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// IssuerConditionReady indicates that an issuer is configured correctly and
	// its Key Manager Plus back end is reachable.
	IssuerConditionReady string = "Ready"

	// IssuerReasonChecked is set when the connectivity check succeeded.
	IssuerReasonChecked string = "Checked"

	// IssuerReasonFailed is set when the issuer is misconfigured or Key Manager
	// Plus could not be reached.
	IssuerReasonFailed string = "Failed"

	// IssuerReasonPending is set while the issuer is being checked for the
	// first time.
	IssuerReasonPending string = "Pending"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=cert-manager;cert-manager-kmp,shortName=kmpissuer
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// KMPIssuer issues certificates from a ManageEngine Key Manager Plus server for
// CertificateRequests in its own namespace.
type KMPIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KMPIssuerList contains a list of KMPIssuer.
type KMPIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMPIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=cert-manager;cert-manager-kmp,shortName=kmpclusterissuer
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// KMPClusterIssuer issues certificates from a ManageEngine Key Manager Plus
// server for CertificateRequests in any namespace.
type KMPClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KMPClusterIssuerList contains a list of KMPClusterIssuer.
type KMPClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMPClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KMPIssuer{}, &KMPIssuerList{}, &KMPClusterIssuer{}, &KMPClusterIssuerList{})
}
