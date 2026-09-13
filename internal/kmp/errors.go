package kmp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Error describes a failed Key Manager Plus API call.
type Error struct {
	// Op is the REST operation that failed, for example "signCSR".
	Op string
	// StatusCode is the HTTP status code, or 0 if the call never completed.
	StatusCode int
	// APIStatus is the "Status" field of the response body, if any.
	APIStatus string
	// Message is the human readable reason, taken from the response body when
	// Key Manager Plus supplied one.
	Message string
	// Body is a truncated copy of the response body, kept for diagnostics when
	// the response did not follow the documented shape.
	Body string
	// Permanent reports whether retrying the identical call is pointless.
	Permanent bool
	// Err is the underlying transport or decoding error, if any.
	Err error
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "key manager plus: %s", e.Op)
	if e.StatusCode != 0 {
		fmt.Fprintf(&b, ": http %d", e.StatusCode)
	}
	if e.APIStatus != "" {
		fmt.Fprintf(&b, ": status %q", e.APIStatus)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	if e.Message == "" && e.Err == nil && e.Body != "" {
		fmt.Fprintf(&b, ": %s", e.Body)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// IsPermanent reports whether err is a failure that will not be resolved by
// retrying the same request, such as a rejected auth token or an unknown
// certificate template. Callers use it to decide between failing a
// CertificateRequest and retrying it later.
func IsPermanent(err error) bool {
	if errors.Is(err, ErrInvalidConfig) {
		return true
	}
	var kmpErr *Error
	if errors.As(err, &kmpErr) {
		return kmpErr.Permanent
	}
	return false
}

// permanentStatus reports whether an HTTP status code means the request itself
// was rejected rather than the server being briefly unable to serve it.
func permanentStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return code >= 400 && code < 500
}

// authFailureHints are substrings Key Manager Plus uses when it rejects the
// AUTHTOKEN. They are matched case-insensitively.
var authFailureHints = []string{
	"authtoken",
	"auth token",
	"authentication failed",
	"invalid token",
	"unauthorized",
	"not authorized",
	"invalid user",
}

// IsAuthFailure reports whether err looks like a rejected or missing AUTHTOKEN.
func IsAuthFailure(err error) bool {
	var kmpErr *Error
	if !errors.As(err, &kmpErr) {
		return false
	}
	if kmpErr.StatusCode == http.StatusUnauthorized || kmpErr.StatusCode == http.StatusForbidden {
		return true
	}
	haystack := strings.ToLower(kmpErr.Message + " " + kmpErr.Body)
	for _, hint := range authFailureHints {
		if strings.Contains(haystack, hint) {
			return true
		}
	}
	return false
}
