# Migrating from vapor/jwt

A guide for migrating from the vapor/jwt library to JWSETKit.

## Overview

This guide helps you migrate from [vapor/jwt](https://github.com/vapor/jwt) to JWSETKit. While both libraries handle JSON Web Tokens, JWSETKit offers additional features like JWE encryption, SD-JWT selective disclosure, multiple signatures, and HPKE support.

## Feature Comparison

| Feature                       | vapor/jwt-kit | JWSETKit |
|-------------------------------|:-------------:|:--------:|
| JWT signing/verification      | ✅ | ✅ |
| JWS (JSON Web Signature)      | ✅ | ✅ |
| JWE (JSON Web Encryption)     | ❌ | ✅ |
| SD-JWT (Selective Disclosure) | ❌ | ✅ |
| Multiple signatures           | ❌ | ✅ |
| ES256K (secp256k1)            | ❌ | ✅ |
| HPKE encryption               | ❌ | ✅ |
| Post-quantum (ML-DSA)         | ✅ | ✅ |
| Apple platforms               | ✅ | ✅ |
| Linux                         | ✅ | ✅ |


| Feature                                   | vapor/jwt | JWSETKit |
|-------------------------------------------|:---------:|:--------:|
| NIOHTTP1 header extensions                | ✅ | ✅ |
| Cloud provider JWKS (Apple, Google, etc.) | ✅ | ✅ |
| JWKS caching with HTTP headers            | ✅ | ❌ |

## Concept Mapping

### Key Types

| vapor/jwt-kit                        | JWSETKit                   | Notes |
|--------------------------------------|----------------------------|-------|
| `JWTKeyCollection`                   | ``JSONWebKeySet``          | Collection of keys |
| `Insecure.RSA.PrivateKey`            | ``JSONWebRSAPrivateKey``   | RSA private key |
| `Insecure.RSA.PublicKey`             | ``JSONWebRSAPublicKey``    | RSA public key |
| `ES*PrivateKey` / `EdDSA.PrivateKey` | ``JSONWebECPrivateKey``    | Private EC/EdDSA keys |
| `ES*PublicKey` / `EdDSA.PublicKey`   | ``JSONWebECPublicKey``     | Public EC/EdDSA keys |
| `MLDSA*PrivateKey`                   | ``JSONWebMLDSAPrivateKey`` | Post-quantum keys |
| `MLDSA*PublicKey`                    | ``JSONWebMLDSAPublicKey``  | Post-quantum keys |

> You can use ``Crypto`` keys directly and you don't need to wrap them. e.g. Use ``P256.Signing.PublicKey``

### Payload Types

Instead of defining new types for each claim, JWSETKit provides storage to make possible
to use native swift types instead of custom types for claims.

| vapor/jwt-kit     | JWSETKit               | Notes                |
|-------------------|------------------------|----------------------|
| `JWTPayload`      | ``JSONWebTokenClaims`` | JWT claims container |
| `ExpirationClaim` | ``Foundation/Date``    | Access via ``JSONWebTokenClaimsRegisteredParameters/expiry`` |
| `IssuedAtClaim`   | ``Foundation/Date``    | Access via ``JSONWebTokenClaimsRegisteredParameters/issuedAt`` |
| `NotBeforeClaim`  | ``Foundation/Date``    | Access via ``JSONWebTokenClaimsRegisteredParameters/notBefore`` |
| `SubjectClaim`    | `String` / `URL`       | Access via ``JSONWebTokenClaimsRegisteredParameters/subject`` |
| `IssuerClaim`     | `String` / `URL`       | Access via ``JSONWebTokenClaimsRegisteredParameters/issuer`` |
| `AudienceClaim`   | `[String]` / `[URL]`   | Access via ``JSONWebTokenClaimsRegisteredParameters/audience`` |
| `IDClaim`         | `String` / `UUID`      | Access via ``JSONWebTokenClaimsRegisteredParameters/jwtId`` |

## Migration Examples

### Creating a JWT

**vapor/jwt (JWTKit):**
```swift
import JWTKit

struct MyPayload: JWTPayload {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var admin: BoolClaim

    func verify(using key: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
    }
}

let keys = JWTKeyCollection()
await keys.add(hmac: "secret", digestAlgorithm: .sha256, kid: "my-key")

let payload = MyPayload(
    sub: "user123",
    exp: .init(value: Date().addingTimeInterval(3600)),
    admin: true
)

let token = try await keys.sign(payload, kid: "my-key")
```

**JWSETKit:**
```swift
import JWSETKit
import Crypto

// Create claims
var claims = try JSONWebTokenClaims {
    $0.subject = "user123"
    $0.expiry = Date().addingTimeInterval(3600)
    $0["admin"] = true  // Custom claims via subscript
}

// Create and sign JWT
let key = SymmetricKey(data: Data("secret".utf8))
var jwt = try JSONWebToken(
    payload: claims, algorithm: .hmacSHA256, using: key
)
let token = jwt.description
```

### Verifying a JWT

**vapor/jwt (JWTKit):**
```swift
let keys = JWTKeyCollection()
await keys.add(hmac: "secret", digestAlgorithm: .sha256)
let payload = try await keys.verify(token, as: MyPayload.self)
```

**JWSETKit:**
```swift
let jwt = try JSONWebToken(from: token)
let key = SymmetricKey(data: Data("secret".utf8))
try jwt.verify(using: key, for: "my-app")  // Verifies signature, exp/nbf, and audience

// Access claims
let subject = jwt.payload.subject
let isAdmin = jwt.payload["admin"] as? Bool
```

### Using RSA Keys

**vapor/jwt-kit:**

```swift
let keys = JWTKeyCollection()
let privateKey = try Insecure.RSA.PrivateKey(pem: privateKeyPEM)
await keys.add(rsa: privateKey, digestAlgorithm: .sha256, kid: "my-key")
```

**JWSETKit:**

```swift
let privateKey = try JSONWebRSAPrivateKey(
    importing: privateKeyDER,
    format: .pkcs8
)
let publicKey = try JSONWebRSAPublicKey(
    importing: publicKeyDER,
    format: .spki
)

// Or load from JWK
let keyFromJWK = try JSONWebRSAPrivateKey(
    importing: jwkData,
    format: .jwk
)

// Create key set
privateKey.keyId = "my-key"
var keySet = JSONWebKeySet(keys: [privateKey])
jwt.updateSignature(using: keySet[keyId: "my-key"]!)
```

### Using EC Keys

**vapor/jwt-kit:**

```swift
let keys = JWTKeyCollection()
let privateKey = try ES256PrivateKey(pem: privateKeyPEM)
await keys.add(ecdsa: privateKey, kid: "my-key")
```

**JWSETKit:**

```swift
let privateKey = try JSONWebECPrivateKey(
    importing: privateKeyDER,
    format: .pkcs8
)

// Sign with ES256
var jwt = try JSONWebToken(
    payload: claims,
    algorithm: .ecdsaSignatureP256SHA256, // This is optional here
    using: privateKey
)
```

### Custom Claims

**vapor/jwt-kit:**

```swift
struct MyPayload: JWTPayload {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var customField: String
    var nested: NestedData

    func verify(using key: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
    }
}
```

**JWSETKit:**

```swift
// Option 1: Use subscript for ad-hoc custom claims
var claims = try JSONWebTokenClaims {
    $0.subject = "user123"
    $0.expiry = Date().addingTimeInterval(3600)
    $0["customField"] = "value"
    $0["nested"] = ["key": "value"]
}

// Option 2: Extend JSONWebTokenClaims properly (recommended for reusable claims)
struct MyCustomClaims: JSONWebContainerParameters {
    var customField: String?
    var nested: [String: String]?

    static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.customField: "customField",
        \.nested: "nested",
    ]
}

extension JSONWebTokenClaims {
    subscript<T>(dynamicMember keyPath: SendableKeyPath<MyCustomClaims, T?>) -> T? {
        get { storage[stringKey(keyPath)] }
        set { storage[stringKey(keyPath)] = newValue }
    }
}

// Usage
var claims = try JSONWebTokenClaims {
    $0.subject = "user123"
    $0.expiry = Date().addingTimeInterval(3600)
    $0.customField = "value"
    $0.nested = ["key": "value"]
}
```

See <doc:7-Extending-Container> for more details on extending JWT claims.

### Loading JWKS from URL

**vapor/jwt-kit:**

```swift
// Fetch JWKS JSON from URL using HTTP client, then add to key collection
let response = try await req.client.get("https://example.com/.well-known/jwks.json")
let jwksJSON = String(buffer: response.body!)
let keys = try await JWTKeyCollection().add(jwksJSON: jwksJSON)
```

**JWSETKit:**

```swift
// Using async/await - fetches and decodes in one step
let keySet = try await JSONWebKeySet(url: URL(string: "https://example.com/.well-known/jwks.json")!)

// Or from data
let keySet = try JSONDecoder().decode(JSONWebKeySet.self, from: jwksData)
```

## Step-by-Step Migration

### 1. Update Package.swift

Remove vapor/jwt and add JWSETKit:

```swift
// Before
.package(url: "https://github.com/vapor/jwt.git", from: "4.0.0"),

// After
.package(url: "https://github.com/amosavian/JWSETKit", from: "1.0.0"),
```

Update target dependencies:

```swift
// Before
.product(name: "JWT", package: "jwt"),

// After
.product(name: "JWSETKit", package: "JWSETKit"),
```

### 2. Replace Imports

```swift
// Before
import JWTKit

// After
import JWSETKit
import Crypto
```

### 3. Update Key Management

Replace `JWTKeyCollection` with individual keys or ``JSONWebKeySet``:

```swift
// Before (JWTKit)
let keys = JWTKeyCollection()
await keys.add(hmac: "secret", digestAlgorithm: .sha256, kid: "default")

// After (JWSETKit)
let key = SymmetricKey(data: Data("secret".utf8))
// Or use JSONWebKeySet for multiple keys
```

### 4. Update Payload Types

Replace `JWTPayload` conforming types with ``JSONWebTokenClaims``:

```swift
// Before
struct MyPayload: JWTPayload { ... }

// After
var claims = try JSONWebTokenClaims { ... }
// Add custom claims via subscript
```

### 5. Update Signing

```swift
// Before (JWTKit)
let token = try await keys.sign(payload, kid: "my-key")

// After (JWSETKit)
var jwt = try JSONWebToken(payload: claims, algorithm: .hmacSHA256, using: key)
let token = jwt.description
```

### 6. Update Verification

```swift
// Before (JWTKit)
let payload = try await keys.verify(token, as: MyPayload.self)

// After (JWSETKit): All-in-one verification
let jwt = try JSONWebToken(from: token)
try jwt.verify(using: key, for: "expected-audience")
```

## New Features in JWSETKit

After migrating, you can take advantage of additional features:

### JWE Encryption

```swift
let jwe = try JSONWebEncryption(
    content: sensitiveData,
    keyEncryptingAlgorithm: .rsaEncryptionOAEP,
    keyEncryptionKey: recipientPublicKey,
    contentEncryptionAlgorithm: .aesEncryptionGCM256
)
let encrypted = jwe.description
```

### SD-JWT Selective Disclosure

```swift
let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .standard,  // Conceals non-standard claims
    using: issuerKey
)
```

### Multiple Signatures

```swift
var jws = try JSONWebSignature(protected: header, payload: claims)
try jws.addSignature(using: key1)
try jws.addSignature(using: key2)
```

## Common Issues

### Algorithm Names

vapor/jwt uses method-based algorithm selection, while JWSETKit uses explicit algorithm identifiers:

| vapor/jwt | JWSETKit | Notes |
|-----------|----------|-------|
| `.hs256()` | `.hmacSHA256` | |
| `.hs384()` | `.hmacSHA384` | |
| `.hs512()` | `.hmacSHA512` | |
| `.rs256()` | `.rsaSignaturePKCS1v15SHA256` | |
| `.rs384()` | `.rsaSignaturePKCS1v15SHA384` | |
| `.rs512()` | `.rsaSignaturePKCS1v15SHA512` | |
| `.ps256()` | `.rsaSignaturePSSSHA256` | |
| `.ps384()` | `.rsaSignaturePSSSHA384` | |
| `.ps512()` | `.rsaSignaturePSSSHA512` | |
| `.es256()` | `.ecdsaSignatureP256SHA256` | |
| N/A        | `.ecdsaSignatureSecp256k1SHA256` | secp256k1 curve |
| `.es384()` | `.ecdsaSignatureP384SHA384` | |
| `.es512()` | `.ecdsaSignatureP521SHA512` | |
| `.eddsa()` | `.eddsaSignature` or `.eddsa25519Signature` | Ed25519 curve |
| `.mldsa65()` | `.mldsa65Signature` | Post-quantum (iOS 26+, macOS 26+) |
| `.mldsa87()` | `.mldsa87Signature` | Post-quantum (iOS 26+, macOS 26+) |

### Verification Methods

In vapor/jwt, verification happens during `verify(_:as:)`. In JWSETKit, you have two options:

**Option 1: All-in-one verification (recommended)**
```swift
try jwt.verify(using: key, for: "expected-audience")
// This verifies: signature, exp/nbf, and audience (if provided)
```

**Option 2: Individual verification methods**
```swift
try jwt.verifySignature(using: key)   // Signature verification
try jwt.verifyDate()                  // exp/nbf verification
try jwt.verifyAudience(includes: "expected-audience")  // Audience verification
// Check issuer manually: jwt.payload.issuer == "expected"
```

## Vapor Integration

JWSETKit provides NIOHTTP1 `HTTPHeaders` extensions that work directly in Vapor applications.

### Migrating from req.jwt to req.headers

**vapor/jwt:**
```swift
let payload = try await req.jwt.verify(as: MyPayload.self)
```

**JWSETKit:**
```swift
// Verify token directly from request headers
try req.headers.verifyAuthorizationToken(using: keySet, for: "expected-audience")

// Access the verified token
let jwt = req.headers.authorizationToken!
let subject = jwt.payload.subject
```

### Predefined Cloud Provider JWKS

Fetch JWKS from major identity providers:

```swift
// Apple Sign-In
let appleKeys = try await JSONWebKeySet(provider: .apple)

// Google Identity
let googleKeys = try await JSONWebKeySet(provider: .google)

// Firebase Auth
let firebaseKeys = try await JSONWebKeySet(provider: .firebase)

// Microsoft/Azure
let microsoftKeys = try await JSONWebKeySet(provider: .microsoft)
```

### Features Not Provided

The following vapor/jwt features are Vapor-specific and not provided by JWSETKit:

#### Application/Request Extensions

| vapor/jwt             | JWSETKit Alternative |
| --------------------- | --- |
| `app.jwt.keys`        | Manage `JSONWebKeySet` in your own storage |
| `req.jwt.verify(as:)` | `req.headers.verifyAuthorizationToken()` |
| `req.jwt.sign(_:)`    | Create JWT and set `req.headers.authorizationToken` |

#### JWTAuthenticator Middleware

vapor/jwt provides `JWTAuthenticator` protocol conforming to Vapor's `AsyncBearerAuthenticator`:

```swift
// vapor/jwt - JWTAuthenticator protocol
public protocol JWTAuthenticator: AsyncBearerAuthenticator {
    associatedtype Payload: JWTPayload
    func authenticate(jwt: Payload, for request: Request) async throws
}

// Usage
struct MyAuthenticator: JWTAuthenticator {
    typealias Payload = MyPayload
    func authenticate(jwt: MyPayload, for request: Request) async throws {
        request.auth.login(jwt)
    }
}
```

JWSETKit alternative - create your own authenticator using `AsyncBearerAuthenticator`:

```swift
// JWSETKit
struct MyAuthenticator: AsyncBearerAuthenticator {
    let keySet: JSONWebKeySet

    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        try request.headers.verifyAuthorizationToken(using: keySet)
        let jwt = request.headers.authorizationToken!
        // Login with your user type based on jwt.payload
    }
}
```

#### JWKS Caching (EndpointCache)

vapor/jwt uses Vapor's `EndpointCache<JWKS>` which automatically caches JWKS responses.
If you're using Vapor with JWSETKit, you can use Vapor's `EndpointCache` directly:

```swift
import Vapor
import JWSETKit

// Create cache for Apple JWKS
let appleKeysCache = EndpointCache<JSONWebKeySet>(uri: "https://appleid.apple.com/auth/keys")

// In a route handler
func protected(req: Request) async throws -> Response {
    let keys = try await appleKeysCache.get(on: req).get()
    try req.headers.verifyAuthorizationToken(using: keys, for: "com.myapp")
    // ...
}
```

#### Cloud Provider Token Claims

vapor/jwt-kit provides specialized token types like `AppleIdentityToken` with pre-defined claims:

```swift
// vapor/jwt-kit AppleIdentityToken structure
struct AppleIdentityToken: JWTPayload {
    let issuer: IssuerClaim           // "https://appleid.apple.com"
    let audience: AudienceClaim       // Your app's client_id
    let subject: SubjectClaim         // Unique user identifier
    let issuedAt: IssuedAtClaim
    let expires: ExpirationClaim
    let nonce: String?
    let email: String?
    let emailVerified: Bool?
    let isPrivateEmail: Bool?
    let realUserStatus: UserDetectionStatus?
}
```

JWSETKit includes OIDC standard claims via ``JSONWebTokenClaimsPublicOIDCStandardParameters``:

```swift
let jwt = try JSONWebToken(from: tokenString)
try jwt.verify(using: appleKeys, for: "com.myapp")

// Standard registered claims
let issuer = jwt.payload.issuer
let subject = jwt.payload.subject

// OIDC standard claims (built-in)
let email = jwt.payload.email
let isVerified = jwt.payload.isEmailVerified
let name = jwt.payload.name
let givenName = jwt.payload.givenName
let familyName = jwt.payload.familyName
let pictureURL = jwt.payload.pictureURL

// Apple-specific claims (define extension for non-standard claims)
struct AppleIdentityTokenParameters: JSONWebContainerParameters {
    var isPrivateEmail: Bool?
    var realUserStatus: Int?

    static let keys: [PartialKeyPath<Self>: String] = [
        \.isPrivateEmail: "is_private_email",
        \.realUserStatus: "real_user_status",
    ]
}

extension JSONWebTokenClaims {
    subscript<T>(dynamicMember keyPath: SendableKeyPath<AppleIdentityTokenParameters, T?>) -> T? {
        get { storage[stringKey(keyPath)] }
        set { storage[stringKey(keyPath)] = newValue }
    }
}

// Usage
let isPrivateEmail = jwt.payload.isPrivateEmail
let realUserStatus = jwt.payload.realUserStatus
```

See <doc:7-Extending-Container> for more details on extending containers.

## Topics

### Key Types
- ``JSONWebRSAPublicKey``
- ``JSONWebRSAPrivateKey``
- ``JSONWebECPublicKey``
- ``JSONWebECPrivateKey``
- ``JSONWebKeySet``

### Token Types
- ``JSONWebToken``
- ``JSONWebSignature``
- ``JSONWebEncryption``

### Claims
- ``JSONWebTokenClaims``
