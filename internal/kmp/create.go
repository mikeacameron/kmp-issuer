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
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Operations that let Key Manager Plus hold the private key.
const (
	opCreateCSR = "createCSR"
	opExportCSR = "exportCSR"
)

// File types the exportCSR operation can return.
const (
	FileTypeCSR        = "CSR"
	FileTypePrivateKey = "PrivateKey"
	FileTypeKeyStore   = "KeyStore"
)

// CreateCSRRequest asks Key Manager Plus to generate a key pair and a matching
// certificate signing request, and to keep both in its store.
//
// This is the escrowed-key flow: unlike ImportCSR, the private key is generated
// by Key Manager Plus rather than by the caller, and is retrieved afterwards
// with ExportPrivateKey.
type CreateCSRRequest struct {
	// CommonName is the subject common name, sent as CNAME.
	CommonName string

	// AltNames are the subject alternative names, sent as the comma separated
	// ALT_NAMES parameter. Both host names and IP addresses go here.
	AltNames []string

	// Organization, OrganizationalUnit, Location, State and Country make up the
	// rest of the subject, sent as ORG, ORGUNIT, LOCATION, STATE and COUNTRY.
	Organization       string
	OrganizationalUnit string
	Location           string
	State              string
	Country            string

	// Password protects the key store Key Manager Plus creates, and is needed
	// again to export the private key.
	Password string

	// KeyAlgorithm and KeyLength select the key to generate, sent as ALG and
	// LEN, for example "RSA" and 2048.
	KeyAlgorithm string
	KeyLength    int32

	// SignatureAlgorithm is sent as SIGALG, for example "SHA256".
	SignatureAlgorithm string

	// StoreType is the key store format Key Manager Plus keeps the key in, sent
	// as StoreType, for example "PKCS12".
	StoreType string

	// ValidityType and ValidityDays are sent as VALIDITY_TYPE and VALIDITY.
	ValidityType string
	ValidityDays *int32
}

// details renders the request as the Details object of INPUT_DATA. Only the
// fields that were set are sent, so that Key Manager Plus applies its own
// defaults to the rest.
func (r CreateCSRRequest) details() map[string]any {
	details := map[string]any{"CNAME": r.CommonName}

	optional := map[string]string{
		"ALT_NAMES": strings.Join(r.AltNames, ","),
		"ORG":       r.Organization,
		"ORGUNIT":   r.OrganizationalUnit,
		"LOCATION":  r.Location,
		"STATE":     r.State,
		"COUNTRY":   r.Country,
		"PASSWORD":  r.Password,
		"ALG":       r.KeyAlgorithm,
		"SIGALG":    r.SignatureAlgorithm,
		"StoreType": r.StoreType,
	}
	for key, value := range optional {
		if value != "" {
			details[key] = value
		}
	}

	if r.KeyLength > 0 {
		details["LEN"] = strconv.Itoa(int(r.KeyLength))
	}
	if r.ValidityType != "" {
		details["VALIDITY_TYPE"] = r.ValidityType
	}
	if r.ValidityDays != nil {
		details["VALIDITY"] = strconv.Itoa(int(*r.ValidityDays))
	}
	return details
}

// CreateCSR has Key Manager Plus generate a key pair and a certificate signing
// request for it. The returned CSR carries the id when the response reports
// one; otherwise it is looked up with FindCSRID, as after an import.
func (c *Client) CreateCSR(ctx context.Context, req CreateCSRRequest) (*CSR, error) {
	if strings.TrimSpace(req.CommonName) == "" {
		return nil, &Error{Op: opCreateCSR, Permanent: true, Err: errors.New("the request has no common name")}
	}

	encodedInput, err := inputData(req.details())
	if err != nil {
		return nil, &Error{Op: opCreateCSR, Permanent: true, Err: err}
	}

	query := url.Values{inputDataParam: []string{encodedInput}}
	parsed, err := c.call(ctx, http.MethodPost, opCreateCSR, query, nil, "")
	if err != nil {
		return nil, err
	}

	id, _ := parsed.findString(csrIDKeys...)
	commonName, _ := parsed.findString(commonNameKeys...)
	if commonName == "" {
		commonName = req.CommonName
	}
	return &CSR{ID: id, CommonName: commonName, Response: parsed.truncatedBody()}, nil
}

// ExportCSR downloads one of the files Key Manager Plus keeps for a stored CSR:
// the request itself, its private key, or the key store holding both.
//
// The response is returned as it arrived. Key Manager Plus may answer with the
// file directly or wrap its content in a JSON envelope, so the caller decodes
// it rather than this method guessing.
func (c *Client) ExportCSR(ctx context.Context, csrID, fileType string) ([]byte, error) {
	if csrID == "" {
		return nil, &Error{Op: opExportCSR, Permanent: true, Err: errors.New("no CSR id to export")}
	}
	if fileType == "" {
		fileType = FileTypePrivateKey
	}

	encodedInput, err := inputData(map[string]any{
		"CSR_ID":   csrID,
		"fileType": fileType,
	})
	if err != nil {
		return nil, &Error{Op: opExportCSR, Permanent: true, Err: err}
	}

	query := url.Values{inputDataParam: []string{encodedInput}}
	return c.callRaw(ctx, http.MethodGet, opExportCSR, query)
}
