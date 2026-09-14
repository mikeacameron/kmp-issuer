/*
Copyright 2026 The kmp-issuer Authors.

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

package kmp

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// verifyRequestedNames reports the identities that were asked for in the
// request but are missing from the issued certificate.
//
// A certificate authority may add names, and Key Manager Plus passes the
// request to a Microsoft CA whose template decides what the subject and the
// subject alternative names end up being: a template that builds the subject
// from Active Directory silently drops what the request asked for. Publishing
// such a certificate would leave cert-manager re-issuing forever, because the
// result never matches the Certificate, so it is refused here with an
// explanation instead.
func verifyRequestedNames(csr *x509.CertificateRequest, leaf *x509.Certificate) error {
	var missing []string

	if requested := csr.Subject.CommonName; requested != "" && !strings.EqualFold(requested, leaf.Subject.CommonName) {
		missing = append(missing, fmt.Sprintf("common name %q (the certificate has %q)", requested, leaf.Subject.CommonName))
	}

	for _, name := range csr.DNSNames {
		if !containsFold(leaf.DNSNames, name) {
			missing = append(missing, fmt.Sprintf("DNS name %q", name))
		}
	}

	for _, ip := range csr.IPAddresses {
		found := false
		for _, issued := range leaf.IPAddresses {
			if issued.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, fmt.Sprintf("IP address %q", ip))
		}
	}

	for _, email := range csr.EmailAddresses {
		if !containsFold(leaf.EmailAddresses, email) {
			missing = append(missing, fmt.Sprintf("email address %q", email))
		}
	}

	for _, uri := range csr.URIs {
		found := false
		for _, issued := range leaf.URIs {
			if issued.String() == uri.String() {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, fmt.Sprintf("URI %q", uri))
		}
	}

	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: key manager plus returned a certificate that is missing %s. "+
		"A Microsoft CA template only keeps the subject and the subject alternative names of a request "+
		"when it is configured to supply them from the request",
		ErrInvalidConfig, strings.Join(missing, ", "))
}

// containsFold reports whether values holds want, ignoring case, as host names
// and mail addresses are compared case-insensitively.
func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
