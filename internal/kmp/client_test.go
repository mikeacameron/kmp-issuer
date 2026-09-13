package kmp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "A3164150-4C15-4AA4-918E-F258F38149F8"

// recordedRequest is one call the fake Key Manager Plus server received.
type recordedRequest struct {
	Method    string
	Path      string
	AuthToken string
	InputData map[string]any
	CSR       string
}

// fakeKMP is a stand-in for the Key Manager Plus PKI REST API.
type fakeKMP struct {
	t        *testing.T
	server   *httptest.Server
	requests []recordedRequest

	// handlers maps an operation name to its response. A handler may write any
	// status code it likes.
	handlers map[string]http.HandlerFunc
}

func newFakeKMP(t *testing.T) *fakeKMP {
	t.Helper()
	fake := &fakeKMP{t: t, handlers: map[string]http.HandlerFunc{}}
	mux := http.NewServeMux()
	mux.HandleFunc(apiBasePath+"/", func(w http.ResponseWriter, r *http.Request) {
		op := strings.TrimPrefix(r.URL.Path, apiBasePath+"/")
		fake.record(r, op)
		handler, ok := fake.handlers[op]
		if !ok {
			http.Error(w, fmt.Sprintf(`{"Status":"Failed","Message":"unexpected operation %s"}`, op), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	})
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeKMP) record(r *http.Request, op string) {
	f.t.Helper()
	rec := recordedRequest{Method: r.Method, Path: op, AuthToken: r.Header.Get(authTokenHeader)}

	raw := r.URL.Query().Get(inputDataParam)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			f.t.Fatalf("parsing multipart body of %s: %v", op, err)
		}
		if raw == "" {
			raw = r.FormValue(inputDataParam)
		}
		if file, _, err := r.FormFile("CSR"); err == nil {
			defer file.Close()
			content, err := io.ReadAll(file)
			if err != nil {
				f.t.Fatalf("reading the CSR part of %s: %v", op, err)
			}
			rec.CSR = string(content)
		}
	}
	if raw != "" {
		var envelope struct {
			Operation struct {
				Details map[string]any `json:"Details"`
			} `json:"operation"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			f.t.Fatalf("decoding INPUT_DATA of %s: %v", op, err)
		}
		rec.InputData = envelope.Operation.Details
	}
	f.requests = append(f.requests, rec)
}

func (f *fakeKMP) on(op string, handler http.HandlerFunc) {
	f.handlers[op] = handler
}

// respond registers a handler answering with a fixed body.
func (f *fakeKMP) respond(op, body string) {
	f.on(op, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
}

func (f *fakeKMP) requestFor(op string) *recordedRequest {
	f.t.Helper()
	for i := range f.requests {
		if f.requests[i].Path == op {
			return &f.requests[i]
		}
	}
	f.t.Fatalf("no %s request was made; got %v", op, f.requests)
	return nil
}

func (f *fakeKMP) client(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient(Config{BaseURL: f.server.URL, AuthToken: testToken, UserAgent: "kmp-issuer/test"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestNewClientValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "empty URL", cfg: Config{AuthToken: testToken}},
		{name: "empty token", cfg: Config{BaseURL: "https://kmp.example.com:6565"}},
		{name: "unsupported scheme", cfg: Config{BaseURL: "ftp://kmp.example.com", AuthToken: testToken}},
		{name: "no host", cfg: Config{BaseURL: "https://", AuthToken: testToken}},
		{name: "unusable CA bundle", cfg: Config{BaseURL: "https://kmp.example.com:6565", AuthToken: testToken, CABundle: []byte("not a certificate")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(tc.cfg); err == nil {
				t.Fatalf("NewClient(%+v) succeeded, want an error", tc.cfg)
			}
		})
	}
}

func TestClientEndpoint(t *testing.T) {
	client, err := NewClient(Config{BaseURL: "https://kmp.example.com:6565/", AuthToken: testToken})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	want := "https://kmp.example.com:6565/api/pki/restapi/signCSR"
	if got := client.endpoint(opSignCSR).String(); got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

func TestImportCSR(t *testing.T) {
	fake := newFakeKMP(t)
	fake.respond(opImportCSR, `{"Status":"Success","Message":"CSR saved successfully","CSR_ID":"7","commonName":"app.example.com"}`)

	csrPEM, _ := newTestCSR(t, "app.example.com")
	stored, err := fake.client(t).ImportCSR(context.Background(), csrPEM, "pki@example.com")
	if err != nil {
		t.Fatalf("ImportCSR: %v", err)
	}
	if stored.ID != "7" {
		t.Errorf("CSR id = %q, want %q", stored.ID, "7")
	}
	if stored.CommonName != "app.example.com" {
		t.Errorf("common name = %q, want %q", stored.CommonName, "app.example.com")
	}

	req := fake.requestFor(opImportCSR)
	if req.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.Method)
	}
	if req.AuthToken != testToken {
		t.Errorf("AUTHTOKEN header = %q, want %q", req.AuthToken, testToken)
	}
	if req.CSR != string(csrPEM) {
		t.Errorf("uploaded CSR = %q, want the request PEM", req.CSR)
	}
	if got := req.InputData["Email"]; got != "pki@example.com" {
		t.Errorf("Email = %v, want pki@example.com", got)
	}
}

func TestImportCSRWithoutIdentifier(t *testing.T) {
	fake := newFakeKMP(t)
	fake.respond(opImportCSR, `{"Status":"Success","Message":"CSR saved successfully"}`)

	csrPEM, _ := newTestCSR(t, "app.example.com")
	_, err := fake.client(t).ImportCSR(context.Background(), csrPEM, "")
	if err == nil {
		t.Fatal("ImportCSR succeeded, want an error about the missing CSR id")
	}
	if !IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true", err)
	}
}

func TestSignCSRDetailsPerSignType(t *testing.T) {
	agentTimeout := int32(90)
	validity := int32(365)
	isIntermediate := true

	tests := []struct {
		name string
		req  SignRequest
		want map[string]any
	}{
		{
			name: "microsoft CA",
			req: SignRequest{
				CSRID: "1", SignType: SignTypeMSCA,
				ServerName: "kmp-w12r2-1", CAName: "kmp-w12r2-1-ca", TemplateName: "WebServer",
			},
			want: map[string]any{
				"CSR_ID": "1", "signType": "MSCA",
				"serverName": "kmp-w12r2-1", "caName": "kmp-w12r2-1-ca", "templateName": "WebServer",
			},
		},
		{
			name: "microsoft CA through an agent",
			req: SignRequest{
				CSRID: "2", SignType: SignTypeMSCAUsingAgent,
				ServerName: "test-w16-1", CAName: "test-W16-1-CA", TemplateName: "WebServer",
				AgentName: "test-w16-1", AgentResponseTimeoutSeconds: &agentTimeout,
			},
			want: map[string]any{
				"CSR_ID": "2", "signType": "MSCAusingAgent",
				"serverName": "test-w16-1", "caName": "test-W16-1-CA", "templateName": "WebServer",
				"agentName": "test-w16-1", "agentResponseTimeout": float64(90),
			},
		},
		{
			name: "root certificate held by key manager plus",
			req: SignRequest{
				CSRID: "3", SignType: SignTypeWithRoot,
				RootCertificateCommonName: "example-root", RootCertificateSerialNumber: "0A0B",
				ValidityDays: &validity, IsIntermediate: &isIntermediate,
			},
			want: map[string]any{
				"CSR_ID": "3", "signType": "signWithRoot",
				"rootCertificateCommonName": "example-root", "rootCertificateSerialNumber": "0A0B",
				"Validity": "365", "isIntermediate": true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKMP(t)
			fake.respond(opSignCSR, `{"Status":"Success","commonName":"app.example.com","Certificate_ID":"11","serialNumber":"5B"}`)

			result, err := fake.client(t).SignCSR(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("SignCSR: %v", err)
			}
			if result.SerialNumber != "5B" || result.CommonName != "app.example.com" || result.CertificateID != "11" {
				t.Errorf("result = %+v, want the identifiers from the response", result)
			}

			got := fake.requestFor(opSignCSR).InputData
			if len(got) != len(tc.want) {
				t.Errorf("INPUT_DATA Details = %v, want exactly %v", got, tc.want)
			}
			for key, want := range tc.want {
				if got[key] != want {
					t.Errorf("INPUT_DATA Details[%q] = %#v, want %#v", key, got[key], want)
				}
			}
		})
	}
}

func TestSignCSRWithoutIdentifiers(t *testing.T) {
	fake := newFakeKMP(t)
	fake.respond(opSignCSR, `{"Status":"Success","Message":"done"}`)

	_, err := fake.client(t).SignCSR(context.Background(), SignRequest{CSRID: "1", SignType: SignTypeMSCA})
	if err == nil {
		t.Fatal("SignCSR succeeded, want an error about the unidentified certificate")
	}
	if !IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = false, want true", err)
	}
}

func TestGetCertificate(t *testing.T) {
	pki := newTestPKI(t)
	csrPEM, csr := newTestCSR(t, "app.example.com")
	leaf := pki.issue(t, csr, 500)

	t.Run("PEM chain in a nested field", func(t *testing.T) {
		fake := newFakeKMP(t)
		body, err := json.Marshal(map[string]any{
			"Status": "Success",
			"Details": map[string]any{
				"certificate": pemString(leaf, pki.interCert),
				"rootCert":    pemString(pki.rootCert),
			},
		})
		if err != nil {
			t.Fatalf("building the response: %v", err)
		}
		fake.respond(opGetCertificate, string(body))

		certs, err := fake.client(t).GetCertificate(context.Background(), "app.example.com", "5B")
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if len(certs) != 3 {
			t.Fatalf("got %d certificates, want 3", len(certs))
		}

		req := fake.requestFor(opGetCertificate)
		if req.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", req.Method)
		}
		if req.InputData["common_name"] != "app.example.com" || req.InputData["serial_number"] != "5B" {
			t.Errorf("INPUT_DATA Details = %v, want the common name and serial number", req.InputData)
		}
	})

	t.Run("bare base64 DER", func(t *testing.T) {
		fake := newFakeKMP(t)
		encoded := base64.StdEncoding.EncodeToString(leaf.Raw)
		fake.respond(opGetCertificate, fmt.Sprintf(`{"Status":"Success","certificateContent":%q}`, encoded))

		certs, err := fake.client(t).GetCertificate(context.Background(), "app.example.com", "")
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if len(certs) != 1 || !certs[0].Equal(leaf) {
			t.Fatalf("got %d certificates, want the issued leaf", len(certs))
		}
	})

	t.Run("no certificate in the response", func(t *testing.T) {
		fake := newFakeKMP(t)
		fake.respond(opGetCertificate, `{"Status":"Success","Details":[]}`)

		_, err := fake.client(t).GetCertificate(context.Background(), "app.example.com", "")
		if err == nil {
			t.Fatal("GetCertificate succeeded, want an error")
		}
		if IsPermanent(err) {
			t.Errorf("IsPermanent(%v) = true, want false so the controller retries", err)
		}
	})

	_ = csrPEM
}

func TestCallErrorClassification(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		wantPermanent bool
		wantAuth      bool
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"Status":"Failed","Message":"Invalid AUTHTOKEN"}`, wantPermanent: true, wantAuth: true},
		{name: "bad request", status: http.StatusBadRequest, body: `{"Status":"Failed","Message":"Template not found"}`, wantPermanent: true},
		{name: "server error", status: http.StatusInternalServerError, body: `{"Status":"Failed"}`},
		{name: "too many requests", status: http.StatusTooManyRequests, body: `{"Status":"Failed"}`},
		{name: "api level failure", status: http.StatusOK, body: `{"Status":"Failed","Message":"CA server is not configured"}`, wantPermanent: true},
		{name: "html error page", status: http.StatusOK, body: `<html>login</html>`, wantPermanent: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKMP(t)
			fake.on(opSignCSR, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})

			_, err := fake.client(t).SignCSR(context.Background(), SignRequest{CSRID: "1", SignType: SignTypeMSCA})
			if err == nil {
				t.Fatal("SignCSR succeeded, want an error")
			}
			if got := IsPermanent(err); got != tc.wantPermanent {
				t.Errorf("IsPermanent(%v) = %v, want %v", err, got, tc.wantPermanent)
			}
			if got := IsAuthFailure(err); got != tc.wantAuth {
				t.Errorf("IsAuthFailure(%v) = %v, want %v", err, got, tc.wantAuth)
			}
			if !strings.Contains(err.Error(), opSignCSR) {
				t.Errorf("error %q does not name the failing operation", err)
			}
		})
	}
}

func TestErrorDoesNotLeakTheToken(t *testing.T) {
	fake := newFakeKMP(t)
	fake.on(opSignCSR, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"Status":"Failed","Message":"Template not found"}`)
	})

	_, err := fake.client(t).SignCSR(context.Background(), SignRequest{CSRID: "1", SignType: SignTypeMSCA})
	if err == nil {
		t.Fatal("SignCSR succeeded, want an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error %q contains the auth token", err)
	}
}

func TestPing(t *testing.T) {
	t.Run("api answers", func(t *testing.T) {
		fake := newFakeKMP(t)
		fake.respond(opGetCertificate, `{"Status":"Failed","Message":"No certificate found for the given common name"}`)

		if err := fake.client(t).Ping(context.Background()); err != nil {
			t.Errorf("Ping: %v", err)
		}
	})

	t.Run("token rejected", func(t *testing.T) {
		fake := newFakeKMP(t)
		fake.on(opGetCertificate, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"Status":"Failed","Message":"Invalid AUTHTOKEN"}`)
		})

		err := fake.client(t).Ping(context.Background())
		if err == nil {
			t.Fatal("Ping succeeded, want an authentication error")
		}
		if !IsAuthFailure(err) {
			t.Errorf("IsAuthFailure(%v) = false, want true", err)
		}
	})

	t.Run("server unreachable", func(t *testing.T) {
		client, err := NewClient(Config{BaseURL: "http://127.0.0.1:1", AuthToken: testToken})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := client.Ping(context.Background()); err == nil {
			t.Fatal("Ping succeeded against a closed port, want an error")
		}
	})
}
