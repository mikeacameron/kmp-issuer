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

It offers two ways to get a certificate, differing in who holds the private key:

| | Who generates the key | What you create | When to use it |
| --- | --- | --- | --- |
| **Issuer** | cert-manager, in the cluster | a cert-manager `Certificate` naming a `KMPIssuer` | The key never leaves the cluster. Prefer this. |
| **Escrow** | Key Manager Plus | a `KMPCertificate` | Key Manager Plus is the key custodian and has to be able to recover the key. |

The project is built on [cert-manager/sample-external-issuer][sample], the
official external issuer template, and keeps its layout: the API types under
`api/v1alpha1`, the [issuer-lib][issuer-lib] `CombinedController` wiring in
`internal/controllers/signer.go`, the signing back end in `internal/signer`, and
the kubebuilder `config/` kustomize tree, `Makefile` and `test/e2e` scaffolding.
Key Manager Plus replaces the template's local example CA.

[sample]: https://github.com/cert-manager/sample-external-issuer
[issuer-lib]: https://github.com/cert-manager/issuer-lib

## How it works

Every call goes to `<spec.url>/api/pki/restapi/<operation>` and authenticates
with the `AUTHTOKEN` header. Fulfilling one request takes three of them, plus an
optional lookup:

**1. Upload the CSR** — `POST /api/pki/restapi/importCSR`, multipart, with the
PEM encoded CSR from the request as the `CSR` part:

```http
POST /api/pki/restapi/importCSR
AUTHTOKEN: <token>
Content-Type: multipart/form-data

CSR=@request.csr
INPUT_DATA={"operation":{"Details":{"Email":"pki@example.com"}}}
```

**2. Sign it** — `POST /api/pki/restapi/signCSR`, with the parameters of the
configured sign type:

```jsonc
// signType MSCA
{"operation":{"Details":{"signType":"MSCA","CSR_ID":"301",
  "serverName":"ca1.corp.example.com","caName":"corp-issuing-ca","templateName":"WebServer"}}}

// signType MSCAusingAgent
{"operation":{"Details":{"signType":"MSCAusingAgent","CSR_ID":"301",
  "serverName":"ca1.corp.example.com","caName":"corp-issuing-ca","templateName":"WebServer",
  "agentName":"kmp-agent-1","agentResponseTimeout":90}}}

// signType signWithRoot
{"operation":{"Details":{"signType":"signWithRoot","CSR_ID":"301",
  "rootCertificateCommonName":"Example Internal Root CA","Validity":"365","isIntermediate":false}}}
```

The response reports `commonName`, `Certificate_ID` and `serialNumber`.

**3. Fetch the certificate** — `GET /api/pki/restapi/getCertificate` with the
identity from step 2:

```jsonc
{"operation":{"Details":{"common_name":"app.corp.example.com","serial_number":"4242"}}}
```

**Between 1 and 2, when needed: resolve the `CSR_ID`** — `signCSR` addresses the
request by id, which the documented `importCSR` response does not return. See
[Resolving the CSR id](#resolving-the-csr-id).

### Why not createCertificate or createCSR

Key Manager Plus can mint a certificate in one call with `createCertificate`,
which is tempting because it would also avoid the CSR id lookup below. It is not
usable from an issuer, and neither is `createCSR`. Both take the subject as
parameters — `CNAME`, `ALT_NAMES`, `ORGUNIT`, `ORG`, `LOCATION`, `STATE`,
`COUNTRY`, `VALIDITY`, and crucially `ALG`, `LEN`, `PASSWORD` and `StoreType` —
and no CSR: Key Manager Plus generates the key pair itself and hands back a
password protected PKCS#12 or JKS store.

cert-manager has already generated a private key in the cluster and stored it in
the Secret; it asks the issuer to certify *that* public key. A certificate for a
key generated inside Key Manager Plus does not match it and is useless — this
issuer rejects such a certificate rather than publishing it. Making those
operations work would mean exporting the private key out of Key Manager Plus and
into the Secret, which gives up the guarantee that the key never leaves the
cluster, and which the issuer interface has no room for in any case: it returns
a certificate chain and nothing else. The subject would also have to be squeezed
into flat string parameters, losing what the CSR expresses exactly, such as IP
address SANs distinct from DNS SANs.

So the CSR based path is the one an external issuer has to use, and the CSR id
is resolved as described below. `createCertificate` remains the right call for
automation outside Kubernetes, where Key Manager Plus owning the key is fine.

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

### Container image

CI builds the image for `linux/amd64` and `linux/arm64` and pushes it to the
GitHub container registry, `ghcr.io/mikeacameron/kmp-issuer`:

| Tag | Published from |
| --- | --- |
| `latest` | every push to `main` |
| `main` | the same build, tagged by branch |
| `sha-<commit>` | every build, for pinning a deployment to a commit |
| `1.2.3`, `1.2` | a `v1.2.3` tag |

Pull requests build the image but do not push it, so a change that breaks the
Dockerfile fails before it merges. The binary is stamped with the tag it was
built from, which the manager logs at startup and serves as `version`.

A package published from a private repository is private, and the cluster needs
an image pull secret for it. Make the package public under the repository's
Packages settings if the cluster should pull it anonymously.

## Requesting a certificate

Everything the certificate must carry is declared on the `Certificate`.
cert-manager generates the private key in the cluster, builds a CSR from these
fields, and this issuer hands that CSR to Key Manager Plus unchanged, so the
subject and the SANs are what Key Manager Plus signs:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-tls
  namespace: app
spec:
  secretName: app-tls
  commonName: app.corp.example.com
  subject:
    organizations: ["Example Company Inc"]
    organizationalUnits: ["Platform Engineering"]
    localities: ["Ottawa"]
    provinces: ["Ontario"]
    countries: ["CA"]
  dnsNames:
  - app.corp.example.com
  - app.internal
  ipAddresses:
  - 10.0.2.24
  usages: ["server auth", "digital signature", "key encipherment"]
  issuerRef:
    name: kmp
    kind: KMPIssuer
    group: kmp.cert-manager.io
```

| Certificate field | X.509 field in the CSR | Key Manager Plus |
| --- | --- | --- |
| `commonName` | Subject CN | The domain name of the request, and the name it is fetched back by |
| `subject.organizations` | Subject O | Signed as supplied |
| `subject.organizationalUnits` | Subject OU | Signed as supplied |
| `subject.localities` `subject.provinces` `subject.countries` | Subject L, ST, C | Signed as supplied |
| `dnsNames` | subjectAltName dNSName | Signed as supplied |
| `ipAddresses` | subjectAltName iPAddress | Signed as supplied |
| `uris` `emailAddresses` | subjectAltName URI, rfc822Name | Signed as supplied |
| `duration` | — | `Validity` on `signCSR`, for the `signWithRoot` sign type only |
| `isCA` | basicConstraints | `isIntermediate` on `signCSR`, for the `signWithRoot` sign type only |

There is no way to pass subject fields to Key Manager Plus outside the CSR: its
`signCSR` operation selects the CA, the template or the root certificate, and
nothing about the subject. Two consequences are worth knowing before rollout:

* **Microsoft CA templates decide whether the subject survives.** A template
  configured to build the subject from Active Directory will replace what the
  CSR asked for. For the fields above to appear in the issued certificate, the
  template must be set to supply the subject in the request.
* **Key usages come from the template too**, for the MSCA sign types. Keep the
  `usages` on the Certificate consistent with the template, or cert-manager will
  keep re-issuing because the returned certificate does not match the request.

### Subject alternative names

SANs need no issuer configuration. They are declared on the Certificate, and
cert-manager puts them in the CSR that this issuer hands to Key Manager Plus:

| Certificate field | SAN type |
| --- | --- |
| `dnsNames` | dNSName |
| `ipAddresses` | iPAddress |
| `uris` | uniformResourceIdentifier |
| `emailAddresses` | rfc822Name |
| `otherNames` | otherName, with cert-manager's `OtherNames` feature gate enabled |

Two things catch people out:

* **`commonName` is not a SAN.** Clients have ignored the common name for years,
  so the host name has to appear in `dnsNames` as well, even when it is already
  the common name. The example above does that.
* **`ALT_NAMES` is not involved.** That parameter belongs to `createCSR` and
  `createCertificate`, which this issuer does not use. With `importCSR` the SANs
  travel inside the CSR, so there is nothing to map and nothing to configure.

Whether they survive is up to the CA. A Microsoft CA template that builds the
subject from Active Directory issues a certificate for a name of its own
choosing and drops the requested SANs; the template has to be configured to
supply the subject from the request instead.

Rather than publish a certificate that does not carry what was asked for — which
leaves cert-manager re-issuing in a loop, since the result never matches the
Certificate — this issuer refuses it and says what is missing:

```
Key Manager Plus returned a certificate that is missing DNS name
"app.internal", IP address "10.0.2.24". A Microsoft CA template only keeps the
subject and the subject alternative names of a request when it is configured to
supply them from the request
```

Names the CA adds of its own are accepted, and host names are compared without
regard to case. To see what was actually issued:

```sh
kubectl get secret app-tls -o jsonpath='{.data.tls\.crt}' | base64 -d |
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
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
| `signing.csrLookupOperation` | The operation that lists stored CSRs, used to resolve the `CSR_ID` after import. See below |

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

### Resolving the CSR id

`signCSR` identifies the request to sign by the `CSR_ID` Key Manager Plus
assigned it, but the documented `importCSR` response reports only the outcome:

```json
{"result": {"message": "CSR demo.test.com imported successfully.", "status": "Success"}, "name": "importCSR"}
```

The issuer uses the id when a build does report one, and otherwise looks it up
by common name through the operation named in `signing.csrLookupOperation`. To
find out which applies to your Key Manager Plus, import a CSR and look at what
comes back:

```sh
curl -sk -X POST -H "AUTHTOKEN: $TOKEN"   "https://kmp.example.com:6565/api/pki/restapi/importCSR"   -F 'CSR=@/tmp/test.csr'   -F 'INPUT_DATA={"operation":{"Details":{}}}'
```

If the response carries an id, no further configuration is needed: field names
are matched case-insensitively and ignoring separators, so `CSR_ID`, `csrId` and
`csrid` are all recognised. If it does not, set `signing.csrLookupOperation` to
the operation your build uses to list CSRs; the issuer queries it with the
common name and takes the id of the matching record, preferring the newest when
several match. A response that names only other CSRs is refused rather than
guessed at, so a request is never signed against someone else's CSR. Until one
of the two works, issuance fails with the import response quoted in the
CertificateRequest, which is the fastest way to see what your build returned.

## Key Manager Plus owned keys: KMPCertificate

A cert-manager issuer can only certify a key that cert-manager generated: the
issuer interface returns a certificate chain and has nowhere to put a private
key. When Key Manager Plus should own the key instead — so that it can be
recovered from the vault later — use a `KMPCertificate`, which this controller
reconciles itself:

```yaml
apiVersion: kmp.cert-manager.io/v1alpha1
kind: KMPCertificate
metadata:
  name: app
  namespace: app
spec:
  secretName: app-tls
  issuerRef:
    name: kmp            # the KMPIssuer supplying the endpoint, credentials and CA
    kind: KMPIssuer
  commonName: app.corp.example.com
  dnsNames: ["app.corp.example.com", "app.internal"]
  ipAddresses: ["10.0.2.24"]
  subject:
    organization: Example Company Inc
    organizationalUnit: Platform Engineering
    locality: Ottawa
    province: Ontario
    country: CA
  privateKey:
    algorithm: RSA
    size: 2048
    signatureAlgorithm: SHA256
    storeType: PKCS12
  validityDays: 365
  renewBefore: 720h
```

Each field maps to a `createCSR` parameter — `commonName` to `CNAME`,
`dnsNames` and `ipAddresses` to the comma separated `ALT_NAMES`,
`subject.organization` to `ORG`, `subject.organizationalUnit` to `ORGUNIT`,
`subject.locality` to `LOCATION`, `subject.province` to `STATE`,
`subject.country` to `COUNTRY`, and the `privateKey` fields to `ALG`, `LEN`,
`SIGALG` and `StoreType`.

Issuance is four calls:

| Step | Operation | What it does |
| --- | --- | --- |
| 1 | `createCSR` | Key Manager Plus generates the key pair and a request for it |
| 2 | `signCSR` | Signs it with the CA configured on the issuer |
| 3 | `getCertificate` | Fetches the issued certificate |
| 4 | `exportCSR` | Retrieves the private key, as `fileType=PrivateKey` |

The result is written to a `kubernetes.io/tls` Secret owned by the
`KMPCertificate`, holding `tls.crt` (leaf and intermediates), `tls.key` and
`ca.crt`. A replacement is requested once the certificate reaches
`renewBefore` of its expiry, defaulting to the last third of its lifetime, and
whenever the Secret stops matching the spec.

Before anything is published, the certificate and the exported key are checked
against each other, and the certificate is checked for the names that were
asked for, so a mismatched pair or a subject rewritten by a Microsoft CA
template fails loudly rather than landing in a Secret.

### What escrow costs you

* **The private key travels over the Key Manager Plus API** and is written to a
  Secret. That is the point of escrow, but it is a real difference from the
  issuer flow, where the key is generated in the cluster and never leaves it.
* **Exports must be PEM.** This controller does not carry a PKCS#12 or JKS
  library, so an export that returns a key store fails with a message saying to
  ask for the `PrivateKey` file type. Encrypted PEM is decrypted with the key
  store password; PKCS#8 encryption is not supported.
* **The key store password matters.** `spec.keyStorePasswordSecretRef` supplies
  one; without it a password is generated for each issuance and recorded in the
  target Secret under `keystore-password`, since the key could not be recovered
  from Key Manager Plus without it.

## Compatibility note

The API mapping follows ManageEngine's published REST API documentation for Key
Manager Plus: the `/api/pki/restapi` base path, the `AUTHTOKEN` header, the
`INPUT_DATA={"operation":{"Details":{...}}}` envelope, and the `importCSR`,
`signCSR` and `getCertificate` operations with the parameters listed above.

The `importCSR` response above is quoted from ManageEngine's documentation.
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
