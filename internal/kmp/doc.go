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

// Package kmp is a client for the ManageEngine Key Manager Plus (KMP) PKI REST
// API, plus the signing workflow that a cert-manager issuer needs on top of it.
//
// # API surface
//
// All calls go to
//
//	<base-url>/api/pki/restapi/<operation>
//
// and authenticate with the AUTHTOKEN header, which carries the API token of a
// Key Manager Plus user. Operation parameters are passed as an INPUT_DATA
// parameter holding a JSON document of the form
//
//	{"operation":{"Details":{ ... }}}
//
// Signing a CSR is three calls:
//
//	importCSR      uploads the PEM encoded CSR and returns its CSR id
//	signCSR        signs the stored CSR with a Microsoft CA (directly or through
//	               a KMP agent) or with a root certificate held by KMP, and
//	               returns the common name and serial number of the new
//	               certificate
//	getCertificate fetches the issued certificate by common name and serial
//	               number
//
// # Response handling
//
// Key Manager Plus response envelopes differ between operations and between
// product builds: the status may be reported as "Status" or "status", the
// payload may sit at the top level, under "Details", or under
// "operation.result". Rather than pinning one shape, responses are decoded into
// a generic document and queried with a case-insensitive deep search for the
// fields this package needs (see response.go). Certificates are located by
// scanning the whole response for PEM blocks or base64 encoded DER, so an extra
// wrapper field does not break issuance.
package kmp
