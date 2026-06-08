# Using DPoP

Create OAuth 2.0 DPoP (Demonstrating Proof of Possession) proofs on the client side,
per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

## Overview

DPoP binds an access token to a key pair held by the client. On every request to a
protected resource (or to the token endpoint), the client sends a short-lived **proof
JWT** in the `DPoP` header, signed by its private key, that ties the request to that
key. A stolen access token is then useless without the matching private key.

A DPoP proof is a JWS whose protected header carries `typ: dpop+jwt` and the client's
**public key embedded as `jwk`**, with a payload of ``DPoPClaims``:

| Claim | Meaning |
|-------|---------|
| `jti` | Unique identifier (replay protection) |
| `htm` | HTTP method of the request |
| `htu` | HTTP target URI (query and fragment removed) |
| `iat` | Creation time |
| `ath` | `base64url(SHA-256(access_token))` — present when calling a resource server |
| `nonce` | Server-provided nonce, when challenged |

This guide covers the **client** side — creating and attaching proofs. For verifying
proofs on a resource server, see <doc:9-VaporIntegration> and
<doc:10-HummingbirdIntegration>.

DPoP support lives behind the `HTTP` package trait for the networking request types:

```swift
.package(url: "https://github.com/amosavian/JWSETKit", from: "2.0.0", traits: ["HTTP"])
```

## The client key

DPoP requires a long-lived asymmetric key pair owned by the client. Use any
``JSONWebSigningKey`` — typically an EC key:

```swift
import Crypto
import JWSETKit

// Generate once and persist securely (e.g. Keychain / Secure Enclave).
let clientKey = P256.Signing.PrivateKey()
```

The same key should be reused across requests for the lifetime of the bound access
token: the access token's `cnf.jkt` is the SHA-256 thumbprint of this key's public half,
so changing keys invalidates the binding.

## Creating a proof

Mint a proof directly with ``DPoPProof/init(method:url:accessToken:nonce:algorithm:issuedAt:jwtId:using:)``:

```swift
import JWSETKit

let proof = try DPoPProof(
    method: "POST",
    url: URL(string: "https://server.example.com/token")!,
    using: clientKey
)
let header = try String(proof) // value for the `DPoP` http header
```

- `htm`/`htu` come from `method`/`url`; the URI's query and fragment are removed
  automatically (RFC 9449 §4.3).
- `jti` defaults to a fresh random value; `iat` defaults to now.
- `algorithm` is inferred from the key when omitted.

### Binding to an access token (`ath`)

When calling a **protected resource**, the proof must include `ath` — the hash of the
access token being presented. Pass the token and it is hashed for you (a leading
`"Bearer "`/`"DPoP "` scheme is ignored):

```swift
let proof = try DPoPProof(
    method: "GET",
    url: URL(string: "https://api.example.com/me")!,
    accessToken: accessToken,
    using: clientKey
)
```

## Attaching a proof to a request

JWSETKit attaches the proof and switches the access token to the `DPoP` authentication
scheme (`Authorization: DPoP <token>`, RFC 9449 §7.1) in one call. The access token is
read from the request's existing `Authorization` header, so set it first.

### Foundation `URLRequest`

```swift
import Foundation
import JWSETKit

var request = URLRequest(url: URL(string: "https://api.example.com/me")!)
request.httpMethod = "GET"
request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

try request.setDPoPProof(using: clientKey)
// Authorization: DPoP <token>
// DPoP: <proof>

let (data, _) = try await URLSession.shared.data(for: request)
```

### AsyncHTTPClient `HTTPClientRequest`

```swift
import AsyncHTTPClient
import JWSETKit

var request = HTTPClientRequest(url: "https://api.example.com/me")
request.method = .GET
request.headers.add(name: "authorization", value: "Bearer \(accessToken)")

try request.setDPoPProof(using: clientKey)

let response = try await HTTPClient.shared.execute(request, timeout: .seconds(30))
```

### swift-http-types `HTTPRequest`

```swift
import HTTPTypes
import JWSETKit

var request = HTTPRequest(method: .get, url: URL(string: "https://api.example.com/me")!)
request.headerFields[.authorization] = "Bearer \(accessToken)"

try request.setDPoPProof(using: clientKey)
```

You can also work at the header level directly — `HTTPFields.setDPoPProof(method:url:using:)`
and the NIO `HTTPHeaders` equivalent — when you hold headers rather than a request value.

## Token-endpoint vs. resource requests

- **Token endpoint** (requesting/refreshing an access token): send a proof **without**
  `ath` — there is no access token yet. Just `setDPoPProof` on a request that has no
  `Authorization` header.
- **Protected resource**: the request carries the access token, so `setDPoPProof`
  includes `ath` and rewrites the scheme to `DPoP` automatically.

## The `DPoP-Nonce` challenge

A server may require a server-chosen nonce. It responds `401` with a
`DPoP-Nonce: <value>` header (and `WWW-Authenticate: DPoP error="use_dpop_nonce"`). Read
that header and retry with the nonce included:

```swift
var request = URLRequest(url: resourceURL)
request.httpMethod = "GET"
request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
try request.setDPoPProof(using: clientKey)

var (data, response) = try await URLSession.shared.data(for: request)

if let http = response as? HTTPURLResponse,
   http.statusCode == 401,
   let nonce = http.value(forHTTPHeaderField: "DPoP-Nonce") {
    // Mint a fresh proof carrying the nonce and retry.
    try request.setDPoPProof(nonce: nonce, using: clientKey)
    (data, response) = try await URLSession.shared.data(for: request)
}
```

Each retry mints a new proof (fresh `jti`/`iat`), so the same request value can be
re-stamped safely.

## Notes

- Mint a **fresh proof per request** — `jti` and `iat` must be unique/current so the
  server's replay and freshness checks pass.
- The proof is signed by the **client** key and self-describes its public key in the
  header; the resource server confirms it matches the access token's `cnf.jkt`.

## See Also

- <doc:9-VaporIntegration>
- <doc:10-HummingbirdIntegration>
- ``DPoPProof``
- ``DPoPClaims``
- ``JSONWebToken``