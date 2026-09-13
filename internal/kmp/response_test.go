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

import "testing"

func TestResponseFindString(t *testing.T) {
	tests := []struct {
		name string
		body string
		keys []string
		want string
	}{
		{
			name: "top level field",
			body: `{"Status":"Success","Message":"CSR saved successfully","CSR_ID":"42"}`,
			keys: csrIDKeys,
			want: "42",
		},
		{
			name: "nested under details",
			body: `{"Status":"Success","Details":{"csrId":17}}`,
			keys: csrIDKeys,
			want: "17",
		},
		{
			name: "nested under an operation result envelope",
			body: `{"operation":{"result":{"status":"Success"},"Details":[{"commonName":"app.example.com"}]}}`,
			keys: commonNameKeys,
			want: "app.example.com",
		},
		{
			name: "key spelling differences are ignored",
			body: `{"details":{"serial number":"0A0B"}}`,
			keys: serialNumberKeys,
			want: "0A0B",
		},
		{
			name: "numeric identifiers are rendered as strings",
			body: `{"Certificate_ID":1024}`,
			keys: certificateIDKeys,
			want: "1024",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseResponse([]byte(tc.body))
			if err != nil {
				t.Fatalf("parseResponse: %v", err)
			}
			got, ok := parsed.findString(tc.keys...)
			if !ok {
				t.Fatalf("findString(%v) found nothing in %s", tc.keys, tc.body)
			}
			if got != tc.want {
				t.Errorf("findString(%v) = %q, want %q", tc.keys, got, tc.want)
			}
		})
	}
}

func TestResponseFindStringMissing(t *testing.T) {
	parsed, err := parseResponse([]byte(`{"Status":"Success","Message":"CSR saved successfully"}`))
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if got, ok := parsed.findString(csrIDKeys...); ok {
		t.Errorf("findString found %q, want no result", got)
	}
}

func TestResponseSucceeded(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "success", body: `{"Status":"Success"}`, want: true},
		{name: "lowercase status key", body: `{"status":"success"}`, want: true},
		{name: "failure", body: `{"Status":"Failed","Message":"Invalid template"}`, want: false},
		{name: "payload without a status", body: `{"Details":{"certificate":"---"}}`, want: true},
		{name: "message reporting a failure without a status", body: `{"Message":"Invalid AUTHTOKEN"}`, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseResponse([]byte(tc.body))
			if err != nil {
				t.Fatalf("parseResponse: %v", err)
			}
			if got := parsed.succeeded(); got != tc.want {
				t.Errorf("succeeded() = %v, want %v for %s", got, tc.want, tc.body)
			}
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	for _, key := range []string{"CSR_ID", "csrId", "csr id", "csr.id", "csr-id"} {
		if got := normalizeKey(key); got != "csrid" {
			t.Errorf("normalizeKey(%q) = %q, want %q", key, got, "csrid")
		}
	}
}
