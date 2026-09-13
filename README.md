# kmp-issuer

A [cert-manager](https://cert-manager.io) external issuer for **ManageEngine Key
Manager Plus**. It turns `CertificateRequest` resources into certificates signed
through the Key Manager Plus PKI REST API, so Kubernetes workloads can get
certificates from the same Microsoft CA or internal root that the rest of the
estate uses.

```
Certificate ──► CertificateRequest ──► kmp-issuer ──► Key Manager Plus ──► Microsoft CA
                                                                       └─► KMP root certificate
```

## How it works

Each `CertificateRequest` that names a `KMPIssuer` or `KMPClusterIssuer` is
fulfilled with three calls against `<spec.url>/api/pki/restapi`, authenticated
with the `AUTHTOKEN` header:

| Step | Operation | What it does |
| --- | --- | --- |
| 1 | `importCSR` | Uploads the PEM encoded CSR from `spec.request` and returns its CSR id |
| 2 | `signCSR` | Signs the stored CSR with the configured back end and returns the common name and serial number of the new certificate |
| 3 | `getCertificate` | Fetches the issued certificate by common name and serial number |

The controller then checks that the returned leaf carries the public key of the
CSR, orders the chain above it, and writes the leaf plus intermediates to
`status.certificate` and the root to `status.ca`. Certificates in the response
that are not part of that chain are discarded.

## Install

Requires cert-manager v1.13 or later.

```sh
# Custom resource definitions
kubectl apply -f config/crd/bases

# Controller, RBAC and the cert-manager approver binding
make deploy IMG=ghcr.io/mikeacameron/kmp-issuer:latest
```

`config/rbac/cert_manager_approver.yaml` grants cert-manager's built-in approver
the `approve` permission on this issuer's signers. Without it every request
stays unapproved and is never signed. It is bound to the `cert-manager`
ServiceAccount in the `cert-manager` namespace; adjust it if cert-manager runs
elsewhere.

## Configure an issuer

The API token comes from Key Manager Plus under **Personalize → API**. Store it
in a Secret:

```sh
kubectl -n app create secret generic kmp-credentials --from-literal=authtoken=<token>
```

For a `KMPIssuer` the Secret is read from the issuer's own namespace. For a
`KMPClusterIssuer` it is read from the controller's namespace
(`--cluster-resource-namespace`, `kmp-issuer-system` by default).

```yaml
apiVersion: kmp.cert-manager.io/v1alpha1
kind: KMPIssuer
metadata:
  name: kmp
  namespace: app
spec:
  url: https://kmp.example.com:6565
  authTokenSecretRef:
    name: kmp-credentials
    key: authtoken            # optional, defaults to "authtoken"
  signing:
    signType: MSCA
    serverName: ca1.corp.example.com
    caName: corp-issuing-ca
    templateName: WebServer
```

Then reference it from a `Certificate`:

```yaml
  issuerRef:
    name: kmp
    kind: KMPIssuer
    group: kmp.cert-manager.io
```

More examples, including agent based signing and signing with a root
certificate held by Key Manager Plus, are in [`config/samples`](config/samples).

### Spec reference

| Field | Description |
| --- | --- |
| `url` | Base URL of the Key Manager Plus server, including the port, for example `https://kmp.example.com:6565` |
| `authTokenSecretRef` | Secret holding the `AUTHTOKEN`. Key defaults to `authtoken` |
| `caBundle` | PEM bundle verifying the Key Manager Plus server certificate |
| `caBundleSecretRef` | The same bundle taken from a Secret key, `ca.crt` by default |
| `insecureSkipTLSVerify` | Disables server certificate verification. Evaluation only |
| `requestTimeout` | Timeout of a single API call. Defaults to `30s` |
| `healthCheckInterval` | How often the issuer's connectivity is re-checked. Defaults to `5m` |
| `signing.signType` | `MSCA`, `MSCAusingAgent` or `signWithRoot`. Defaults to `MSCA` |
| `signing.serverName` `signing.caName` `signing.templateName` | The Microsoft CA server, CA and certificate template. Required for `MSCA` and `MSCAusingAgent` |
| `signing.agentName` `signing.agentResponseTimeoutSeconds` | The Key Manager Plus agent to reach the CA through, and how long to wait for it. `MSCAusingAgent` only, which needs KMP build 7030 or later |
| `signing.rootCertificateCommonName` `signing.rootCertificateSerialNumber` | The stored root certificate to sign with. `signWithRoot` only |
| `signing.validityDays` `signing.isIntermediate` | Lifetime of the issued certificate and whether it is a CA certificate. `signWithRoot` only |
| `signing.email` | Recorded against the imported CSR for Key Manager Plus expiry notifications |

With `signWithRoot`, a `Certificate` that sets `spec.duration` or `spec.isCA`
supplies `validityDays` and `isIntermediate` when the issuer does not pin them.
Microsoft CA templates carry their own lifetime, so both fields are ignored for
the two MSCA sign types.

### Controller flags

| Flag | Default | Description |
| --- | --- | --- |
| `--cluster-resource-namespace` | `$POD_NAMESPACE`, else `cert-manager` | Namespace holding Secrets of cluster scoped issuers |
| `--disable-approved-check` | `false` | Sign requests that carry no `Approved` condition |
| `--health-check-interval` | `5m` | Default issuer re-check interval |
| `--max-retry-duration` | `10m` | How long a request may keep failing with retryable errors before it is marked failed. `0` retries indefinitely |
| `--leader-elect` | `false` | Run a single active manager |
| `--metrics-bind-address` | `:8080` | Metrics endpoint |
| `--health-probe-bind-address` | `:8081` | `/healthz` and `/readyz` |

## Behaviour

* **Approval.** Requests are only signed once cert-manager marks them
  `Approved`, and a `Denied` request is failed immediately.
* **Issuer readiness.** Each issuer is checked against Key Manager Plus and
  carries a `Ready` condition; requests wait for a ready issuer and are
  re-queued as soon as one becomes ready.
* **Retries.** Rejections by Key Manager Plus and configuration mistakes (an
  unknown template, a missing Secret key, a rejected token) fail the request,
  since retrying the same call cannot succeed. Timeouts, `5xx` responses and a
  missing Secret are retried with backoff until `--max-retry-duration`.
* **Chain safety.** A certificate whose public key does not match the CSR is
  rejected rather than published.

```sh
kubectl get kmpissuers -A
kubectl describe certificaterequest app-tls-1
```

## Development

Dependencies are resolved from the module proxy rather than vendored, so start
with:

```sh
make tidy     # writes go.sum
make test     # gofmt, go vet and the unit tests
make build
```

The Key Manager Plus client in [`internal/kmp`](internal/kmp) depends only on
the standard library and is covered by tests that run against an in-process fake
of the REST API, so the request shapes and the chain handling can be exercised
without a Key Manager Plus server.

After changing the API types, regenerate the generated code and manifests:

```sh
make generate manifests
```

## Compatibility note

The API mapping follows ManageEngine's published REST API documentation for Key
Manager Plus: the `/api/pki/restapi` base path, the `AUTHTOKEN` header, the
`INPUT_DATA={"operation":{"Details":{...}}}` envelope, and the `importCSR`,
`signCSR` and `getCertificate` operations with the parameters listed above.

Key Manager Plus response envelopes differ between operations and between
builds, so responses are not decoded into a fixed shape: the client searches the
whole response for the fields it needs, matching field names case-insensitively
and ignoring separators (`CSR_ID`, `csrId` and `csr id` are all accepted), and
locates certificates by scanning for PEM blocks or base64 encoded DER. If a
build answers with a shape this misses, the error names the operation and
includes the response body, and the field lists in
[`internal/kmp/client.go`](internal/kmp/client.go) (`csrIDKeys`,
`commonNameKeys`, `serialNumberKeys`, `certificateIDKeys`) are the single place
to extend.

## License

No license has been chosen for this repository yet.
