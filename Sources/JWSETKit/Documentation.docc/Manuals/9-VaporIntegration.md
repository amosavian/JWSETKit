# Using JWSETKit with Vapor

Authenticate requests, verify provider tokens, issue JWTs, use DPoP, and migrate from
vapor/jwt in a [Vapor](https://vapor.codes) application.

## Overview

Vapor's `Request` exposes its headers as NIOHTTP1 `HTTPHeaders`. JWSETKit ships
`HTTPHeaders` extensions, so you can verify and read tokens directly from
`request.headers` without any wrapper types. Beyond plain JWT, JWSETKit also offers JWE
encryption, SD-JWT selective disclosure, multiple signatures, HPKE, and DPoP.

Enable the `HTTP` package trait to get the networking helpers (JWKS fetching, DPoP on
`HTTPClientRequest`):

```swift
.package(url: "https://github.com/amosavian/JWSETKit", from: "2.0.0", traits: ["HTTP"])
```

## Verifying incoming tokens

Verify the `Authorization: Bearer` token straight from the request headers:

```swift
import Vapor
import JWSETKit

func routes(_ app: Application) throws {
    app.get("me") { req async throws -> String in
        // Throws if the token is missing, malformed, expired, or the audience mismatches.
        try req.headers.verifyAuthorizationToken(using: keys, for: "my-api")

        let token = req.headers.authorizationToken!
        return "Hello, \(token.subject ?? "anonymous")"
    }
}
```

`verifyAuthorizationToken` accepts a ``JSONWebKeySet``, a single validating key, or any
sequence of keys, and an optional `audience`. Read any claim from the verified token via
dynamic member lookup, e.g. `token.subject`, `token.issuer`, `token.expiry`, or your own
custom claims.

### Authentication middleware

Encapsulate verification in an `AsyncMiddleware` so every protected route is guarded:

```swift
import Vapor
import JWSETKit

struct JWTAuthMiddleware: AsyncMiddleware {
    let keys: JSONWebKeySet
    let audience: String

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        do {
            try request.headers.verifyAuthorizationToken(using: keys, for: audience)
        } catch {
            throw Abort(.unauthorized, reason: "Invalid or missing token")
        }
        return try await next.respond(to: request)
    }
}

// In configure.swift
let protected = app.grouped(JWTAuthMiddleware(keys: keys, audience: "my-api"))
protected.get("profile") { req async throws -> String in
    let token = req.headers.authorizationToken!
    return "Subject: \(token.subject ?? "")"
}
```

You can also conform to Vapor's `AsyncBearerAuthenticator` and log in your own user type:

```swift
struct JWTAuthenticator: AsyncBearerAuthenticator {
    let keys: JSONWebKeySet

    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        try request.headers.verifyAuthorizationToken(using: keys)
        let jwt = request.headers.authorizationToken!
        // request.auth.login(User(from: jwt.payload))
    }
}
```

## Verifying provider tokens with JWKS

Fetch a provider's JSON Web Key Set and verify tokens against it. JWSETKit includes
endpoints for the major identity platforms:

```swift
// Sign in with Apple
let appleKeys = try await JSONWebKeySet(provider: .apple)
try req.headers.verifyAuthorizationToken(using: appleKeys, for: "your.bundle.id")

// Google / Firebase / Microsoft
let googleKeys = try await JSONWebKeySet(provider: .google)
let firebaseKeys = try await JSONWebKeySet(provider: .firebase)
let microsoftKeys = try await JSONWebKeySet(provider: .microsoft)

// Any OpenID Connect issuer (discovers `jwks_uri` from `.well-known/openid-configuration`)
let provider = try await JSONWebKeySetProvider.openID(URL(string: "https://issuer.example.com")!)
let keys = try await JSONWebKeySet(provider: provider)

// Or a JWKS URL directly
let custom = try await JSONWebKeySet(url: URL(string: "https://example.com/.well-known/jwks.json")!)
```

### Caching JWKS

JWSETKit does not cache JWKS responses itself. In Vapor, use the built-in
`EndpointCache`, which honors HTTP cache headers and refreshes on key rotation:

```swift
import Vapor
import JWSETKit

let appleKeysCache = EndpointCache<JSONWebKeySet>(uri: "https://appleid.apple.com/auth/keys")

func protected(req: Request) async throws -> Response {
    let keys = try await appleKeysCache.get(on: req).get()
    try req.headers.verifyAuthorizationToken(using: keys, for: "com.myapp")
    // ...
}
```

### Provider token claims

JWSETKit includes OIDC standard claims via
``JSONWebTokenClaimsPublicOIDCStandardParameters``, so common fields are available
without defining a token type:

```swift
let jwt = try JSONWebToken(from: tokenString)
try jwt.verify(using: appleKeys, for: "com.myapp")

let email = jwt.payload.email
let isVerified = jwt.payload.isEmailVerified
let givenName = jwt.payload.givenName
let familyName = jwt.payload.familyName
```

For non-standard, provider-specific claims (e.g. Apple's `is_private_email`), add an
extension — see <doc:7-Extending-Container>.

## Issuing tokens

Sign a JWT and return it to the client:

```swift
import Vapor
import JWSETKit

app.post("login") { req async throws -> [String: String] in
    let credentials = try req.content.decode(Credentials.self)
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

You can also set the token on a response or another request via
`headers.authorizationToken = jwt`.

## DPoP (RFC 9449)

### Resource server: verifying a DPoP proof

A resource server verifies both the proof (`DPoP` header) and that the access token is
bound to the proof's key (`cnf.jkt`). Because Vapor's incoming `request.url` is a path
only, supply the absolute request URI you serve on:

```swift
import Vapor
import JWSETKit

struct DPoPAuthMiddleware: AsyncMiddleware {
    let keys: JSONWebKeySet
    let baseURL: URL // e.g. https://api.example.com

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let token = request.headers.authorizationToken,
              let proof = request.headers.dpopProof
        else {
            throw Abort(.unauthorized)
        }
        let url = URL(string: request.url.path, relativeTo: baseURL)!

        do {
            // 1. Verify the access token signature/claims.
            try request.headers.verifyAuthorizationToken(using: keys, for: "my-api")
            // 2. Verify the DPoP proof against this request. htm/htu/iat are checked, and
            //    the ath binding is read from the request's Authorization header.
            try request.headers.verifyDPoPProof(method: request.method, url: url)
            // 3. Confirm the token is bound to the proof's key (cnf.jkt).
            try proof.verifyBinding(accessToken: token)
        } catch {
            throw Abort(.unauthorized, reason: "DPoP validation failed")
        }
        return try await next.respond(to: request)
    }
}
```

> Replay protection: JWSETKit's `verify` does not track `jti`. Read `proof.jwtId`
> (or `proof.jwtUUID`) and reject reused identifiers within your `iat` acceptance
> window using your own store (e.g. Redis).

### Client: sending a DPoP-bound request

Sending DPoP-bound requests (e.g. via `req.client` / `HTTPClientRequest`) is not
specific to Vapor. See <doc:11-DPoP> for the full client flow — minting proofs,
binding the access token (`ath`), and handling the `DPoP-Nonce` challenge.

## Migrating from vapor/jwt

Moving an existing Vapor app from vapor/jwt? See <doc:8-MigrationFromVaporJWT> for the
full migration guide — concept mapping, step-by-step migration, algorithm-name
equivalents, and the Vapor-specific features (such as `EndpointCache` JWKS caching and
`AsyncBearerAuthenticator`) and their JWSETKit alternatives.

## See Also

- <doc:5-SecurityGuidelines>
- <doc:7-Extending-Container>
- <doc:8-MigrationFromVaporJWT>
- <doc:11-DPoP>
- ``JSONWebToken``
- ``JSONWebKeySet``
- ``DPoPProof``