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
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// response is a decoded Key Manager Plus response body. Key Manager Plus wraps
// payloads differently per operation and per build, so the body is kept as a
// generic document and queried by field name rather than unmarshalled into a
// fixed struct.
type response struct {
	doc  any
	body []byte
}

// maxRecordedBody bounds how much of a response body is copied into errors.
const maxRecordedBody = 2048

func parseResponse(body []byte) (*response, error) {
	r := &response{body: body}
	if err := json.Unmarshal(body, &r.doc); err != nil {
		return nil, fmt.Errorf("decoding response body as JSON: %w", err)
	}
	return r, nil
}

// truncatedBody returns the response body, shortened for use in error messages.
func (r *response) truncatedBody() string {
	if r == nil {
		return ""
	}
	return truncate(string(r.body), maxRecordedBody)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "... (truncated)"
}

// statusKeys and messageKeys are the field names Key Manager Plus uses for the
// outcome of an operation.
var (
	statusKeys  = []string{"status", "Status", "STATUS", "result"}
	messageKeys = []string{"message", "Message", "MESSAGE", "reason", "error", "errormessage", "error_message"}
)

// status returns the reported operation status, for example "Success".
func (r *response) status() string {
	v, _ := r.findString(statusKeys...)
	return v
}

// message returns the human readable message of the response, if any.
func (r *response) message() string {
	v, _ := r.findString(messageKeys...)
	return v
}

// succeeded reports whether the response describes a successful operation. A
// response that carries no status field at all is treated as successful,
// because some operations answer with the payload alone.
func (r *response) succeeded() bool {
	status := strings.TrimSpace(strings.ToLower(r.status()))
	switch status {
	case "":
		return !r.hasFailureMessage()
	case "success", "successful", "ok", "true", "200":
		return true
	default:
		return false
	}
}

// failureHints are words Key Manager Plus uses in messages of failed operations
// that report no status field.
var failureHints = []string{"failed", "failure", "error", "invalid", "not found", "denied", "unable to"}

func (r *response) hasFailureMessage() bool {
	msg := strings.ToLower(r.message())
	if msg == "" {
		return false
	}
	for _, hint := range failureHints {
		if strings.Contains(msg, hint) {
			return true
		}
	}
	return false
}

// findString returns the first string value stored under any of the given keys,
// searching the whole document depth-first. Key comparison ignores case,
// underscores and spaces, so "CSR_ID", "csrId" and "csr id" all match a request
// for "csrid".
func (r *response) findString(keys ...string) (string, bool) {
	if r == nil {
		return "", false
	}
	wanted := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		wanted[normalizeKey(k)] = struct{}{}
	}
	return findScalar(r.doc, wanted)
}

func findScalar(node any, wanted map[string]struct{}) (string, bool) {
	switch typed := node.(type) {
	case map[string]any:
		// Prefer a match at this level over one nested deeper, so that a
		// top-level "status" wins over a "status" inside a detail record.
		for key, value := range typed {
			if _, ok := wanted[normalizeKey(key)]; !ok {
				continue
			}
			if s, ok := scalarString(value); ok {
				return s, true
			}
		}
		for _, key := range sortedKeys(typed) {
			if s, ok := findScalar(typed[key], wanted); ok {
				return s, true
			}
		}
	case []any:
		for _, item := range typed {
			if s, ok := findScalar(item, wanted); ok {
				return s, true
			}
		}
	}
	return "", false
}

// collectStrings returns every string value in the document, depth-first, so
// that certificates can be located wherever the response happens to carry them.
func (r *response) collectStrings() []string {
	if r == nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(node any) {
		switch typed := node.(type) {
		case string:
			out = append(out, typed)
		case map[string]any:
			for _, key := range sortedKeys(typed) {
				walk(typed[key])
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(r.doc)
	return out
}

// scalarString renders JSON scalars as strings. Key Manager Plus returns
// numeric identifiers sometimes quoted and sometimes bare.
func scalarString(v any) (string, bool) {
	switch typed := v.(type) {
	case string:
		s := strings.TrimSpace(typed)
		if s == "" {
			return "", false
		}
		return s, true
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10), true
		}
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(typed), true
	case json.Number:
		return typed.String(), true
	}
	return "", false
}

func normalizeKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range strings.ToLower(k) {
		switch r {
		case '_', '-', ' ', '.':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sortedKeys keeps traversal order deterministic so that repeated calls against
// the same response return the same value.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
