# Using JWSETKit with Hummingbird

Authenticate requests, verify provider tokens, issue JWTs, and use DPoP in a
[Hummingbird](https://hummingbird.codes) application.

## Overview

Hummingbird is built on [swift-http-types](https://github.com/apple/swift-http-types):
`request.headers` is an `HTTPFields` value and `request.head` is an `HTTPRequest`.
JWSETKit ships extensions on both, so you can verify and read tokens directly — and,
because `HTTPRequest` carries the `:scheme`/`:authority` pseudo-headers, JWSETKit can
reconstruct the absolute request URI needed for DPoP without extra configuration.

Enable the `HTTP` package trait to get the swift-http-types helpers and JWKS fetching:

```swift
.package(url: "https://github.com/amosavian/JWSETKit", from: "2.0.0", traits: ["HTTP"])
```

## Verifying incoming tokens

Verify the `Authorization: Bearer` token straight from `request.headers`:

```swift
import Hummingbird
import JWSETKit

let router = Router()
router.get("me") { request, context -> String in
    // Throws if the token is missing, malformed, expired, or the audience mismatches.
    try request.headers.verifyAuthorizationToken(using: keys, for: "my-api")

    let token = request.headers.authorizationToken!
    return "Hello, \(token.subject ?? "anonymous")"
}
```

`verifyAuthorizationToken` accepts a ``JSONWebKeySet``, a single validating key, or any
sequence of keys, plus an optional `audience`.

### Authentication middleware

[hummingbird-auth](https://github.com/hummingbird-project/hummingbird-auth) provides
`AuthenticatorMiddleware`, which authenticates a request and stores the resulting
identity in an `AuthRequestContext`. Implement `authenticate(request:context:)` using
JWSETKit to verify the token and build your identity — mirroring the structure of the
official [`auth-jwt` example](https://github.com/hummingbird-project/hummingbird-examples/tree/main/auth-jwt):

```swift
import Hummingbird
import HummingbirdAuth
import JWSETKit

struct User: Authenticatable {
    let id: String
    let name: String?
}

struct JWTAuthenticator: AuthenticatorMiddleware {
    typealias Context = BasicAuthRequestContext<User>
    let keys: JSONWebKeySet
    let audience: String

    func authenticate(request: Request, context: Context) async throws -> User? {
        guard let token = request.headers.authorizationToken else {
            return nil
        }
        // Verify signature, exp/nbf, and audience.
        try token.verify(using: keys, for: audience)
        return User(id: token.subject ?? "", name: token.name)
    }
}
```

Use the `BasicAuthRequestContext` (or your own `AuthRequestContext`), add the
middleware, and read the identity in handlers via `context.requireIdentity()`:

```swift
let router = Router(context: BasicAuthRequestContext<User>.self)
router.add(middleware: JWTAuthenticator(keys: keys, audience: "my-api"))
router.get("profile") { request, context -> String in
    let user = try context.requireIdentity() // throws 401 if not authenticated
    return "Subject: \(user.id)"
}
```

> An authenticator returning `nil` leaves `context.identity` unset; `requireIdentity()`
> then throws `401 Unauthorized`. To reject unauthenticated requests up front (rather
> than per-route), add `IsAuthenticatedMiddleware` after the authenticator.

## Verifying provider tokens with JWKS

Fetch a provider's JSON Web Key Set and verify against it:

```swift
// Sign in with Apple
let appleKeys = try await JSONWebKeySet(provider: .apple)
try request.headers.verifyAuthorizationToken(using: appleKeys, for: "your.bundle.id")

// Google / Firebase / Microsoft
let googleKeys = try await JSONWebKeySet(provider: .google)
let firebaseKeys = try await JSONWebKeySet(provider: .firebase)
let microsoftKeys = try await JSONWebKeySet(provider: .microsoft)

// Any OpenID Connect issuer (discovers `jwks_uri` from `.well-known/openid-configuration`)
let provider = try await JSONWebKeySetProvider.openID(URL(string: "https://issuer.example.com")!)
let keys = try await JSONWebKeySet(provider: provider)
```

> Caching: JWSETKit does not cache JWKS responses. Fetch once at startup (or on a
> schedule) and hold the ``JSONWebKeySet`` in your application services, refreshing it
> when a key rotates.

## Issuing tokens

Sign a JWT and return it to the client:

```swift
import Hummingbird
import JWSETKit

struct Credentials: Decodable { let username: String; let password: String }

router.post("login") { request, context -> [String: String] in
    let credentials = try await request.decode(as: Credentials.self, context: context)
    let userID = try await authenticate(credentials)

    let claims = try JSONWebTokenClaims {
        $0.issuer = "https://my-api.example.com"
        $0.subject = userID
        $0.audience = ["my-api"]
        $0.issuedAt = .init()
        $0.expiry = .init(timeIntervalSinceNow: 3600)
        $0.jwtUUID = .init()
    }

    let jwt = try JSONWebToken(payload: claims, using: signingKey)
    return ["token": try String(jwt)]
}
```

## DPoP (RFC 9449)

### Resource server: verifying a DPoP proof

Hummingbird's `request.head` is an `HTTPRequest` carrying the scheme and authority, so
JWSETKit reconstructs the absolute `htu` for you — call `verifyDPoPProof` directly on
the request:

```swift
import Hummingbird
import HummingbirdAuth
import JWSETKit

struct DPoPAuthenticator: AuthenticatorMiddleware {
    typealias Context = BasicAuthRequestContext<User>
    let keys: JSONWebKeySet
    let audience: String

    func authenticate(request: Request, context: Context) async throws -> User? {
        guard let token = request.headers.authorizationToken,
              let proof = request.headers.dpopProof
        else {
            return nil
        }
        // 1. Verify the access token signature/claims.
        try token.verify(using: keys, for: audience)
        // 2. Verify the DPoP proof against this request. htm/htu/iat are reconstructed
        //    from request.head, and the ath binding is checked against the access token
        //    in the Authorization header.
        try request.head.verifyDPoPProof()
        // 3. Confirm the token is bound to the proof's key (cnf.jkt).
        try proof.verifyBinding(accessToken: token)

        return User(id: token.subject ?? "", name: token.name)
    }
}
```

> Replay protection: JWSETKit's `verify` does not track `jti`. Read `proof.jwtId`
> (or `proof.jwtUUID`) and reject reused identifiers within your `iat` acceptance
> window using your own store.

### Client: sending a DPoP-bound request

Sending DPoP-bound requests (minting a proof on an outgoing `HTTPRequest`) is not
specific to Hummingbird. See <doc:11-DPoP> for the full client flow — minting proofs,
binding the access token (`ath`), and handling the `DPoP-Nonce` challenge.

## See Also

- <doc:5-SecurityGuidelines>
- <doc:9-VaporIntegration>
- <doc:11-DPoP>
- ``JSONWebToken``
- ``JSONWebKeySet``
- ``DPoPProof``