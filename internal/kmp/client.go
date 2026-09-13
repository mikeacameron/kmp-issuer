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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	// apiBasePath is the path prefix of the Key Manager Plus PKI REST API.
	apiBasePath = "/api/pki/restapi"

	// authTokenHeader carries the Key Manager Plus API token.
	authTokenHeader = "AUTHTOKEN"

	// inputDataParam is the parameter Key Manager Plus reads operation
	// arguments from.
	inputDataParam = "INPUT_DATA"

	// defaultTimeout bounds a single API call.
	defaultTimeout = 30 * time.Second

	// maxResponseBytes bounds how much of a response body is read. Certificate
	// payloads are small; anything larger indicates the request did not reach
	// the API (a login page, for example).
	maxResponseBytes = 8 << 20
)

// Operation names of the Key Manager Plus PKI REST API used by this package.
const (
	opImportCSR      = "importCSR"
	opSignCSR        = "signCSR"
	opGetCertificate = "getCertificate"
)

// Config configures a Client.
type Config struct {
	// BaseURL is the root URL of the Key Manager Plus server, for example
	// "https://kmp.example.com:6565".
	BaseURL string

	// AuthToken is the Key Manager Plus AUTHTOKEN of the API user.
	AuthToken string

	// CABundle is an optional PEM bundle used to verify the server
	// certificate. When empty the system roots are used.
	CABundle []byte

	// InsecureSkipTLSVerify disables server certificate verification.
	InsecureSkipTLSVerify bool

	// Timeout bounds a single API call. Defaults to 30s.
	Timeout time.Duration

	// UserAgent is sent with every request.
	UserAgent string

	// Transport overrides the HTTP transport. Used by tests.
	Transport http.RoundTripper
}

// Client talks to the Key Manager Plus PKI REST API.
type Client struct {
	baseURL    *url.URL
	authToken  string
	httpClient *http.Client
	userAgent  string
}

// NewClient validates cfg and returns a client for the Key Manager Plus API.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("key manager plus URL is empty")
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil {
		return nil, fmt.Errorf("parsing key manager plus URL: %w", err)
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("key manager plus URL %q must use http or https", cfg.BaseURL)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("key manager plus URL %q has no host", cfg.BaseURL)
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return nil, errors.New("key manager plus auth token is empty")
	}

	transport := cfg.Transport
	if transport == nil {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipTLSVerify, //nolint:gosec // opt-in, documented as unsafe
		}
		if len(cfg.CABundle) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CABundle) {
				return nil, errors.New("no certificates found in the configured CA bundle")
			}
			tlsConfig.RootCAs = pool
		}
		httpTransport := http.DefaultTransport.(*http.Transport).Clone()
		httpTransport.TLSClientConfig = tlsConfig
		transport = httpTransport
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &Client{
		baseURL:    parsed,
		authToken:  strings.TrimSpace(cfg.AuthToken),
		httpClient: &http.Client{Transport: transport, Timeout: timeout},
		userAgent:  cfg.UserAgent,
	}, nil
}

// endpoint builds the URL of an API operation.
func (c *Client) endpoint(op string) *url.URL {
	u := *c.baseURL
	u.Path = path.Join(u.Path, apiBasePath, op)
	u.RawQuery = ""
	return &u
}

// details wraps operation arguments in the envelope Key Manager Plus expects.
func inputData(details map[string]any) (string, error) {
	payload := map[string]any{
		"operation": map[string]any{
			"Details": details,
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encoding INPUT_DATA: %w", err)
	}
	return string(encoded), nil
}

// call performs an API request and decodes the response envelope. A non-2xx
// status, an undecodable body or a response reporting failure all yield an
// *Error.
func (c *Client) call(ctx context.Context, method, op string, query url.Values, body io.Reader, contentType string) (*response, error) {
	endpoint := c.endpoint(op)
	if len(query) > 0 {
		endpoint.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, &Error{Op: op, Permanent: true, Err: fmt.Errorf("building request: %w", err)}
	}
	req.Header.Set(authTokenHeader, c.authToken)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transport failures are transient: the server may be restarting or the
		// network briefly unavailable.
		return nil, &Error{Op: op, Err: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &Error{Op: op, StatusCode: resp.StatusCode, Err: fmt.Errorf("reading response: %w", err)}
	}

	parsed, parseErr := parseResponse(raw)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &Error{
			Op:         op,
			StatusCode: resp.StatusCode,
			Body:       truncate(string(raw), maxRecordedBody),
			Permanent:  permanentStatus(resp.StatusCode),
		}
		if parseErr == nil {
			apiErr.APIStatus = parsed.status()
			apiErr.Message = parsed.message()
		}
		return nil, apiErr
	}
	if parseErr != nil {
		return nil, &Error{
			Op:         op,
			StatusCode: resp.StatusCode,
			Body:       truncate(string(raw), maxRecordedBody),
			Permanent:  true,
			Err:        parseErr,
		}
	}
	if !parsed.succeeded() {
		return nil, &Error{
			Op:         op,
			StatusCode: resp.StatusCode,
			APIStatus:  parsed.status(),
			Message:    parsed.message(),
			Body:       parsed.truncatedBody(),
			Permanent:  true,
		}
	}
	return parsed, nil
}

// CSR is a certificate signing request stored in Key Manager Plus.
type CSR struct {
	// ID is the Key Manager Plus identifier of the stored CSR, passed to
	// signCSR as CSR_ID.
	ID string
	// CommonName is the subject common name Key Manager Plus recorded.
	CommonName string
}

// csrIDKeys are the field names Key Manager Plus builds use for the identifier
// of a stored CSR.
var csrIDKeys = []string{"CSR_ID", "csrId", "csrID", "csrid", "certificateRequestId", "id"}

var commonNameKeys = []string{"commonName", "common_name", "CNAME", "cn", "subjectCommonName"}

var serialNumberKeys = []string{"serialNumber", "serial_number", "serialNo", "serial"}

var certificateIDKeys = []string{"Certificate_ID", "certificateId", "certificateID", "certId"}

// ImportCSR uploads a PEM encoded CSR to Key Manager Plus and returns the
// stored request, whose ID is the handle used for signing.
//
// email, when set, is recorded against the request and used by Key Manager Plus
// for expiry notifications.
func (c *Client) ImportCSR(ctx context.Context, csrPEM []byte, email string) (*CSR, error) {
	if len(csrPEM) == 0 {
		return nil, &Error{Op: opImportCSR, Permanent: true, Err: errors.New("CSR is empty")}
	}

	details := map[string]any{}
	if email != "" {
		details["Email"] = email
	}
	encodedInput, err := inputData(details)
	if err != nil {
		return nil, &Error{Op: opImportCSR, Permanent: true, Err: err}
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	filePart, err := writer.CreateFormFile("CSR", "request.csr")
	if err != nil {
		return nil, &Error{Op: opImportCSR, Permanent: true, Err: fmt.Errorf("building multipart body: %w", err)}
	}
	if _, err := filePart.Write(csrPEM); err != nil {
		return nil, &Error{Op: opImportCSR, Permanent: true, Err: fmt.Errorf("writing CSR part: %w", err)}
	}
	if err := writer.WriteField(inputDataParam, encodedInput); err != nil {
		return nil, &Error{Op: opImportCSR, Permanent: true, Err: fmt.Errorf("writing INPUT_DATA part: %w", err)}
	}
	if err := writer.Close(); err != nil {
		return nil, &Error{Op: opImportCSR, Permanent: true, Err: fmt.Errorf("closing multipart body: %w", err)}
	}

	parsed, err := c.call(ctx, http.MethodPost, opImportCSR, nil, &body, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	id, ok := parsed.findString(csrIDKeys...)
	if !ok {
		return nil, &Error{
			Op:        opImportCSR,
			Permanent: true,
			Body:      parsed.truncatedBody(),
			Message:   parsed.message(),
			Err:       errors.New("the response carries no CSR id, so the request cannot be signed"),
		}
	}
	commonName, _ := parsed.findString(commonNameKeys...)
	return &CSR{ID: id, CommonName: commonName}, nil
}

// SignRequest describes one call to the signCSR operation.
type SignRequest struct {
	// CSRID identifies the CSR previously stored with ImportCSR.
	CSRID string

	// SignType selects the signing back end: "MSCA", "MSCAusingAgent" or
	// "signWithRoot". Empty means the Key Manager Plus default, MSCA.
	SignType string

	// ServerName, CAName and TemplateName address a Microsoft CA and are used
	// by the MSCA and MSCAusingAgent sign types.
	ServerName   string
	CAName       string
	TemplateName string

	// AgentName and AgentResponseTimeoutSeconds are used by the MSCAusingAgent
	// sign type.
	AgentName                   string
	AgentResponseTimeoutSeconds *int32

	// RootCertificateCommonName, RootCertificateSerialNumber, ValidityDays and
	// IsIntermediate are used by the signWithRoot sign type.
	RootCertificateCommonName   string
	RootCertificateSerialNumber string
	ValidityDays                *int32
	IsIntermediate              *bool
}

// SignResult identifies the certificate produced by signCSR.
type SignResult struct {
	CertificateID string
	CommonName    string
	SerialNumber  string
}

// details renders the request as the Details object of INPUT_DATA, including
// only the fields that apply to its sign type.
func (r SignRequest) details() map[string]any {
	details := map[string]any{"CSR_ID": r.CSRID}
	signType := r.SignType
	if signType == "" {
		signType = "MSCA"
	}
	details["signType"] = signType

	switch signType {
	case "signWithRoot":
		details["rootCertificateCommonName"] = r.RootCertificateCommonName
		if r.RootCertificateSerialNumber != "" {
			details["rootCertificateSerialNumber"] = r.RootCertificateSerialNumber
		}
		if r.ValidityDays != nil {
			details["Validity"] = strconv.Itoa(int(*r.ValidityDays))
		}
		if r.IsIntermediate != nil {
			details["isIntermediate"] = *r.IsIntermediate
		}
	case "MSCAusingAgent":
		details["serverName"] = r.ServerName
		details["caName"] = r.CAName
		details["templateName"] = r.TemplateName
		details["agentName"] = r.AgentName
		if r.AgentResponseTimeoutSeconds != nil {
			details["agentResponseTimeout"] = *r.AgentResponseTimeoutSeconds
		}
	default: // MSCA
		details["serverName"] = r.ServerName
		details["caName"] = r.CAName
		details["templateName"] = r.TemplateName
	}
	return details
}

// SignCSR signs a stored CSR and returns the identity of the issued
// certificate.
func (c *Client) SignCSR(ctx context.Context, req SignRequest) (*SignResult, error) {
	if req.CSRID == "" {
		return nil, &Error{Op: opSignCSR, Permanent: true, Err: errors.New("CSR id is empty")}
	}
	encodedInput, err := inputData(req.details())
	if err != nil {
		return nil, &Error{Op: opSignCSR, Permanent: true, Err: err}
	}

	query := url.Values{inputDataParam: []string{encodedInput}}
	parsed, err := c.call(ctx, http.MethodPost, opSignCSR, query, nil, "")
	if err != nil {
		return nil, err
	}

	result := &SignResult{}
	result.CertificateID, _ = parsed.findString(certificateIDKeys...)
	result.CommonName, _ = parsed.findString(commonNameKeys...)
	result.SerialNumber, _ = parsed.findString(serialNumberKeys...)
	if result.CommonName == "" && result.SerialNumber == "" && result.CertificateID == "" {
		return nil, &Error{
			Op:        opSignCSR,
			Permanent: true,
			Message:   parsed.message(),
			Body:      parsed.truncatedBody(),
			Err:       errors.New("the response identifies no signed certificate"),
		}
	}
	return result, nil
}

// GetCertificate fetches an issued certificate by common name and, when known,
// serial number. Every certificate found in the response is returned, so a
// response that also carries the issuing chain yields it too.
func (c *Client) GetCertificate(ctx context.Context, commonName, serialNumber string) ([]*x509.Certificate, error) {
	if commonName == "" && serialNumber == "" {
		return nil, &Error{Op: opGetCertificate, Permanent: true, Err: errors.New("neither common name nor serial number is known")}
	}

	details := map[string]any{}
	if commonName != "" {
		details["common_name"] = commonName
	}
	if serialNumber != "" {
		details["serial_number"] = serialNumber
	}
	encodedInput, err := inputData(details)
	if err != nil {
		return nil, &Error{Op: opGetCertificate, Permanent: true, Err: err}
	}

	query := url.Values{inputDataParam: []string{encodedInput}}
	parsed, err := c.call(ctx, http.MethodGet, opGetCertificate, query, nil, "")
	if err != nil {
		return nil, err
	}

	certs, err := certificatesFromStrings(parsed.collectStrings())
	if err != nil {
		return nil, &Error{Op: opGetCertificate, Permanent: true, Body: parsed.truncatedBody(), Err: err}
	}
	if len(certs) == 0 {
		return nil, &Error{
			Op:        opGetCertificate,
			Permanent: false, // Key Manager Plus may not have published it yet.
			Message:   parsed.message(),
			Body:      parsed.truncatedBody(),
			Err:       errors.New("the response carries no certificate"),
		}
	}
	return certs, nil
}

// Ping verifies that the Key Manager Plus API is reachable and that the
// configured auth token is accepted. A lookup for a certificate that does not
// exist is enough: it exercises authentication without changing any state, and
// an empty result still proves the token was accepted.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.GetCertificate(ctx, "kmp-issuer-connectivity-probe.invalid", "")
	if err == nil {
		return nil
	}
	if IsAuthFailure(err) {
		return err
	}
	var kmpErr *Error
	if errors.As(err, &kmpErr) {
		// "No certificate found" and friends mean the API answered us, which is
		// all the probe is after. A transport failure or an unparseable body
		// carries an underlying error and is a genuine problem.
		if kmpErr.StatusCode >= 200 && kmpErr.StatusCode <= 299 && kmpErr.Err != nil && kmpErr.Op == opGetCertificate {
			if strings.Contains(kmpErr.Err.Error(), "no certificate") {
				return nil
			}
		}
		if kmpErr.StatusCode >= 200 && kmpErr.StatusCode <= 299 && kmpErr.APIStatus != "" {
			// The API rejected the lookup rather than failing to serve it.
			return nil
		}
	}
	return err
}
