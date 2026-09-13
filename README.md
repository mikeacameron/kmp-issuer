# kmp-issuer

A [cert-manager](https://cert-manager.io) external issuer for **ManageEngine Key
Manager Plus**. It signs cert-manager `CertificateRequest` resources, and
Kubernetes `CertificateSigningRequest` resources, through the Key Manager Plus
PKI REST API, so Kubernetes workloads get certificates from the same Microsoft
CA or internal root as the rest of the estate.

```
Certificate ─► CertificateRequest ─┐
                                   ├─► kmp-issuer ─► Key Manager Plus ─┬─► Microsoft CA
CertificateSigningRequest ─────────┘                                   └─► KMP root certificate
```

The project is built on [cert-manager/sample-external-issuer][sample], the
official external issuer template, and keeps its layout: the API types under
`api/v1alpha1`, the [issuer-lib][issuer-lib] `CombinedController` wiring in
`internal/controllers/signer.go`, the signing back end in `internal/signer`, and
the kubebuilder `config/` kustomize tree, `Makefile` and `test/e2e` scaffolding.
Key Manager Plus replaces the template's local example CA.

[sample]: https://github.com/cert-manager/sample-external-issuer
[issuer-lib]: https://github.com/cert-manager/issuer-lib

## How it works

Fulfilling one request takes three calls against
`<spec.url>/api/pki/restapi`, authenticated with the `AUTHTOKEN` header:

| Step | Operation | What it does |
| --- | --- | --- |
| 1 | `importCSR` | Uploads the PEM encoded CSR and returns its CSR id |
| 2 | `signCSR` | Signs the stored CSR with the configured back end and returns the common name and serial number of the new certificate |
| 3 | `getCertificate` | Fetches the issued certificate by common name and serial number |

Key Manager Plus is a remote CA, so the X.509 CSR is passed through as
issuer-lib supplies it rather than being rebuilt into a certificate template.
The client then checks that the returned leaf carries the public key of the CSR,
orders the chain above it and discards any unrelated certificates, and hands the
result to `pki.ParseSingleCertificateChainPEM`, which splits it into the
certificate chain and the CA that cert-manager stores.

## Install

Requires cert-manager. `config/rbac` includes the ClusterRole and binding that
let cert-manager's built-in approver approve requests for these signers; without
them every request stays unapproved and is never signed.

```sh
make install                                      # CRDs
make deploy IMG=ghcr.io/mikeacameron/kmp-issuer:latest
```

## Creating KMPIssuer and KMPClusterIssuer resources

The API token comes from Key Manager Plus under **Personalize → API**. Put it in
a Secret under the `authtoken` key, optionally alongside the CA bundle that
verifies the Key Manager Plus server certificate under `ca.crt`:

```sh
kubectl -n app create secret generic kmp-credentials \
  --from-literal=authtoken=<token> \
  --from-file=ca.crt=/path/to/kmp-ca.pem
```

```yaml
apiVersion: kmp.cert-manager.io/v1alpha1
kind: KMPIssuer
metadata:
  name: kmp
  namespace: app
spec:
  url: https://kmp.example.com:6565
  authSecretName: kmp-credentials
  signing:
    signType: MSCA
    serverName: ca1.corp.example.com
    caName: corp-issuing-ca
    templateName: WebServer
```

```yaml
  issuerRef:
    name: kmp
    kind: KMPIssuer
    group: kmp.cert-manager.io
```

A `KMPIssuer` reads its Secret from its own namespace; a `KMPClusterIssuer`
reads it from the namespace given by `--cluster-resource-namespace`, which
defaults to the namespace the controller runs in. Full examples for all three
sign types are in [`config/samples`](config/samples).

### Spec reference

| Field | Description |
| --- | --- |
| `url` | Base URL of the Key Manager Plus server, including the port, for example `https://kmp.example.com:6565` |
| `authSecretName` | Secret holding the `AUTHTOKEN` under `authtoken`, and optionally a CA bundle under `ca.crt` |
| `insecureSkipTLSVerify` | Disables server certificate verification. Evaluation only |
| `requestTimeout` | Timeout of a single API call. Defaults to `30s` |
| `signing.signType` | `MSCA`, `MSCAusingAgent` or `signWithRoot`. Defaults to `MSCA` |
| `signing.serverName` `signing.caName` `signing.templateName` | The Microsoft CA server, CA and certificate template. Required for `MSCA` and `MSCAusingAgent` |
| `signing.agentName` `signing.agentResponseTimeoutSeconds` | The Key Manager Plus agent to reach the CA through, and how long to wait for it. `MSCAusingAgent` only, which needs KMP build 7030 or later |
| `signing.rootCertificateCommonName` `signing.rootCertificateSerialNumber` | The stored root certificate to sign with. `signWithRoot` only |
| `signing.validityDays` `signing.isIntermediate` | Lifetime of the issued certificate and whether it is a CA certificate. `signWithRoot` only |
| `signing.email` | Recorded against the imported CSR for Key Manager Plus expiry notifications |

With `signWithRoot`, a request that carries a duration or asks for a CA
certificate supplies `validityDays` and `isIntermediate` when the issuer does
not pin them. Microsoft CA templates carry their own lifetime, so both fields
are ignored for the two MSCA sign types.

### Issuer health checks

Each issuer is checked before any request is signed: the controller reads the
Secret, builds a client and asks Key Manager Plus for a certificate that does
not exist, which exercises the endpoint and the token without changing
anything. The result is reported in the `Ready` condition.

```console
$ kubectl get kmpissuers -A
NAMESPACE   NAME   URL                             READY   REASON    MESSAGE
app         kmp    https://kmp.example.com:6565    True    Checked   Success
```

A rejection or a misconfiguration — an unknown template, a rejected token, a
missing key in the Secret — is reported as a permanent error, so issuer-lib
stops retrying until the issuer or the Secret changes. Timeouts, connection
failures and `5xx` responses are retried until `MaxRetryDuration`.

## Development

```sh
make test          # generate, fmt, vet, envtest and the unit tests
make lint          # golangci-lint
make build
make test-e2e      # against a Kind cluster
```

The Key Manager Plus client in [`internal/kmp`](internal/kmp) depends only on
the standard library and is covered by tests that run against an in-process fake
of the REST API, so the request shapes, the error classification and the chain
handling are exercised without a Key Manager Plus server.

The end-to-end suite deploys the controller and checks the metrics endpoint on
any cluster. Its issuance spec needs a real server and is skipped unless one is
configured:

```sh
KMP_URL=https://kmp.example.com:6565 KMP_AUTHTOKEN=<token> \
KMP_SERVER_NAME=ca1.corp.example.com KMP_CA_NAME=corp-issuing-ca \
KMP_TEMPLATE_NAME=WebServer make test-e2e
```

## Compatibility note

The API mapping follows ManageEngine's published REST API documentation for Key
Manager Plus: the `/api/pki/restapi` base path, the `AUTHTOKEN` header, the
`INPUT_DATA={"operation":{"Details":{...}}}` envelope, and the `importCSR`,
`signCSR` and `getCertificate` operations with the parameters listed above.

Response envelopes differ between operations and between product builds, so
responses are not decoded into a fixed shape: the client searches the whole
response for the fields it needs, matching field names case-insensitively and
ignoring separators (`CSR_ID`, `csrId` and `csr id` all match), and locates
certificates by scanning for PEM blocks or base64 encoded DER. If a build
answers with a shape this misses, the error names the operation and includes the
response body, and the field lists in
[`internal/kmp/client.go`](internal/kmp/client.go) (`csrIDKeys`,
`commonNameKeys`, `serialNumberKeys`, `certificateIDKeys`) are the single place
to extend.

## Security considerations

The controller reads Secrets in every namespace, and any user who can create a
`KMPIssuer` can point it at a Secret in its namespace. Restrict who may create
issuers, and prefer a `KMPClusterIssuer` whose credentials live in the
controller's own namespace.

`insecureSkipTLSVerify` turns off verification of the Key Manager Plus server
certificate and exposes the API token to anyone who can intercept the
connection. Supply `ca.crt` in the auth Secret instead.

## License

Apache License 2.0, see [LICENSE](LICENSE). The scaffolding is derived from
[cert-manager/sample-external-issuer][sample], which is Apache 2.0 licensed;
files taken from it keep their original copyright notice.
