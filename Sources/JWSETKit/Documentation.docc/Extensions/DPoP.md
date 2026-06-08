# ``JWSETKit/DPoPProof``

A signed proof that demonstrates possession of a private key when making an HTTP
request, per OAuth 2.0 Demonstrating Proof of Possession
([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)).

## Overview

DPoP hardens bearer tokens against theft. A normal `Bearer` access token can be replayed
by anyone who obtains it; a DPoP-bound token can only be used by the client that holds a
specific private key. On each request, the client sends a fresh, short-lived **proof**
JWT — a `DPoPProof` — alongside the access token. The proof is signed by the client's
private key and describes the request it accompanies, so the server can confirm the
caller actually controls the key the token was issued to.

A `DPoPProof` is a ``JSONWebSignature`` whose protected header declares
`typ: dpop+jwt` and embeds the client's **public key** in the `jwk` parameter, with a
``DPoPClaims`` payload:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
.
{
  "jti": "e1j3V_bKic8-LAEB",
  "htm": "GET",
  "htu": "https://api.example.com/me",
  "iat": 1749200000,
  "ath": "fUHyO2r2Z3Dz_3-h..."
}
```

| Claim | Accessor | Meaning |
| --- | --- | --- |
| `jti` | ``DPoPRegisteredParameters/jwtId`` / ``DPoPRegisteredParameters/jwtUUID`` | Unique proof identifier; lets the server detect replay. |
| `htm` | ``DPoPRegisteredParameters/httpMethod`` | HTTP method the proof is bound to. |
| `htu` | ``DPoPRegisteredParameters/httpURL`` | Target URI, with query and fragment removed. |
| `iat` | ``DPoPRegisteredParameters/issuedAt`` | Creation time; the server enforces freshness. |
| `ath` | ``DPoPRegisteredParameters/accessTokenHash`` | `SHA-256` of the access token; present on resource requests. |
| `nonce` | ``DPoPRegisteredParameters/nonce`` | Server-supplied nonce, when challenged. |

> For an end-to-end client walkthrough — generating a key, attaching proofs to
> requests, and handling nonces — see <doc:11-DPoP>.

## Creating a proof

Mint a proof with the request's method and target URI. The signing key's public half is
embedded automatically, `jti` and `iat` are generated, and the signature algorithm is
inferred from the key:

```swift
import JWSETKit
import Crypto

let clientKey = P256.Signing.PrivateKey()

let proof = try DPoPProof(
    method: "POST",
    url: URL(string: "https://server.example.com/token")!,
    using: clientKey
)
let headerValue = try String(proof) // send as the `DPoP` http header
```

The `htu` is normalized as it is stored: the query and fragment are stripped, so a proof
created for `…/me?page=2#x` is bound to `…/me` (RFC 9449 §4.3).

### Binding to an access token

When the proof accompanies an access token (a request to a protected resource), include
the token so its hash is recorded in `ath`. A leading `"Bearer "`/`"DPoP "` scheme is
ignored:

```swift
let proof = try DPoPProof(
    method: "GET",
    url: URL(string: "https://api.example.com/me")!,
    accessToken: accessToken,
    using: clientKey
)
```

### Server-supplied nonce

If a server requires a nonce (responding `401` with a `DPoP-Nonce` header), include it
when minting the retry proof:

```swift
let proof = try DPoPProof(
    method: "GET",
    url: resourceURL,
    accessToken: accessToken,
    nonce: serverNonce,
    using: clientKey
)
```

## Attaching to a request

Rather than building the header by hand, JWSETKit can mint and attach a proof to a
request in one step, reading the access token from the request's existing
`Authorization` header and rewriting its scheme from `Bearer` to `DPoP`
(RFC 9449 §7.1). This is available on `URLRequest`, AsyncHTTPClient's
`HTTPClientRequest`, swift-http-types' `HTTPRequest`, and the header collections
`HTTPHeaders` / `HTTPFields` (all behind the `HTTP` package trait):

```swift
var request = URLRequest(url: URL(string: "https://api.example.com/me")!)
request.httpMethod = "GET"
request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

try request.setDPoPProof(using: clientKey)
// Authorization: DPoP <token>
// DPoP: <proof>
```

See <doc:11-DPoP> for every transport and the full nonce-retry loop.

## Verifying a proof

On a resource server, verifying a DPoP-bound request takes **two** independent checks,
both required by RFC 9449 §4.3:

1. ``verify(method:url:accessToken:nonce:currentDate:)`` validates the proof itself —
   the `typ: dpop+jwt` header, an embedded asymmetric `jwk`, the signature against that
   embedded key, the `htm`/`htu` match (with `htu` normalization), that `iat` is not in
   the future, and — when an access token is supplied — that `ath` matches it.

2. ``verifyBinding(accessToken:)`` confirms the access token is bound to *this* proof's
   key, by comparing the token's `cnf.jkt` confirmation (RFC 7800) to the SHA-256 JWK
   thumbprint of the proof's embedded public key.

```swift
// `proof` parsed from the request's `DPoP` header;
// `accessToken` is the JWSETKit `JSONWebToken` from `Authorization`.
try proof.verify(method: "GET", url: requestURL, accessToken: rawAccessTokenString)
try proof.verifyBinding(accessToken: accessToken)
```

Why both: `ath` proves the proof was made *for this token value*, defeating replay of a
proof across requests; `cnf.jkt` proves the token may *only* be used with this key,
defeating use of a stolen token with an attacker's own key. Neither check subsumes the
other.

The framework integrations expose these as a single `verifyDPoPProof(…)` on the request
or header types — see <doc:9-VaporIntegration> and <doc:10-HummingbirdIntegration>.

## Security Considerations

### Algorithm requirements

Verification **rejects** the `none` algorithm and any symmetric (MAC) algorithm: a DPoP
proof must be signed with an asymmetric key whose public half is embedded in the header.

### Freshness and replay

``verify(method:url:accessToken:nonce:currentDate:)`` rejects future-dated proofs
(`iat > currentDate`) but does **not** enforce a maximum age or track `jti`. JWSETKit is
stateless by design; a resource server must additionally:

- enforce its own acceptable-age window by reading ``DPoPRegisteredParameters/issuedAt``, and
- reject reused ``DPoPRegisteredParameters/jwtId`` values within that window using its own
  store (for example Redis), to prevent proof replay.

### URI matching

`htu` is compared after normalization — scheme and host are lowercased and the query and
fragment are removed — so proofs bind to an origin and path, not to incidental query
parameters.

## Topics

### Creating a Proof

- ``init(method:url:accessToken:nonce:algorithm:issuedAt:jwtId:using:)``

### Verifying a Proof

- ``verify(method:url:accessToken:nonce:currentDate:)``
- ``verifyBinding(accessToken:)``

### Claims

- ``DPoPClaims``
- ``DPoPRegisteredParameters``
