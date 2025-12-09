# ``JWSETKit/JSONWebSelectiveDisclosureToken``

Create and verify SD-JWT tokens with selective disclosure support per RFC 9901.

## Overview

SD-JWT (Selective Disclosure for JWTs) allows issuers to create tokens where
holders can selectively disclose specific claims to verifiers, enhancing
privacy while maintaining cryptographic verification.

An SD-JWT consists of:
- An **Issuer-signed JWT** containing hashed claims
- **Disclosures** that reveal the actual claim values
- An optional **Key Binding JWT** (KB-JWT) proving holder possession

```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>
```

## Creating an SD-JWT (Issuer)

### Basic Creation

Create an SD-JWT with automatic claim concealment based on a disclosure policy:

```swift
import JWSETKit
import Crypto

// Create claims
let claims = try JSONWebTokenClaims {
    $0.issuer = "https://issuer.example.com"
    $0.subject = "user123"
    $0.issuedAt = Date()
    $0.giveName = "John"
    $0.familyName = "Doe"
    $0.email = "john.doe@example.com"
}

// Create signing key
let issuerKey = P256.Signing.PrivateKey()

// Create SD-JWT - standard claims stay visible, others become disclosable
let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .default,  // Uses standardVisibleClaims
    using: issuerKey
)

// Serialize to compact format
let serialized = try String(sdJWT)
// eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3Mi...~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~...
```

### Custom Disclosure Policy

Specify exactly which claims should be selectively disclosable:

```swift
// Only make email disclosable
let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .disclosable([.init(\.email)]),
    using: issuerKey
)

// Or specify additional visible claims
let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .visible([".init(\.givenName)]),  // given_name stays visible
    using: issuerKey
)
```

### Adding Decoy Digests

Add decoy digests to obscure the number of actual claims:

```swift
var sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .default,
    decoyCount: 5
    using: issuerKey
)
```

### Holder Binding

For tokens requiring proof of possession, add a confirmation key:

```swift
let holderKey = P256.Signing.PrivateKey()

var claims = try JSONWebTokenClaims { ... }
// This methods automatically expose public key.
claims.confirmation = .key(holderKey)

let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .default,
    using: issuerKey
)
```

## Creating a Presentation (Holder)

Select which claims to reveal when presenting to a verifier:

### By Disclosure Selection

```swift
// Parse received SD-JWT
let sdJWT = try JSONWebSelectiveDisclosureToken(from: serializedSDJWT)

// Create presentation with specific disclosures
let presentation = try sdJWT.presenting(
    disclosures: sdJWT.disclosureList.filter {
        $0.key == "given_name" || $0.key == "email"
    }
)
```

### By Path Selection

```swift
// Select claims by JSON Pointer paths
let presentation = try sdJWT.presenting(paths: ["/given_name", "/email"])
```

### With Key Binding

Add a Key Binding JWT to prove holder possession:

```swift
let presentation = try sdJWT.withKeyBinding(
    using: holderKey,
    algorithm: .ecdsaSignatureP256SHA256,
    nonce: "verifier-provided-nonce",
    audience: "https://verifier.example.com"
)
```

## Verification (Verifier)

### Basic Validation

```swift
let sdJWT = try JSONWebSelectiveDisclosureToken(from: presentationString)

// Validate structure (checks for duplicate digests, orphan disclosures)
try sdJWT.validate(requireKeyBinding: false)

// Verify issuer signature
try sdJWT.verifySignature(using: issuerPublicKey)

// Access disclosed payload
let payload = try sdJWT.disclosedPayload
print(payload.givenName) // "John"
```

### With Key Binding Verification

```swift
// Full validation including key binding
try sdJWT.validate()

// Or verify key binding explicitly
try sdJWT.verifyKeyBinding(
    expectedNonce: "verifier-provided-nonce",
    expectedAudience: "https://verifier.example.com"
)
```

### Time-Based Validation

```swift
// Verify expiration and not-before claims
try sdJWT.verifyDate()
```

## Disclosure Policies

``DisclosurePolicy`` defines which claims should be visible vs selectively disclosable.

### Standard Visible Claims

Per RFC 9901 Section 9.7, these claims typically remain visible:
- `iss`, `sub`, `iat`, `exp`, `nbf`, `aud`, `jti`, `cnf`

### SD-JWT VC Claims

Per draft-ietf-oauth-sd-jwt-vc, these MUST NOT be selectively disclosed:
- `vct` (Verifiable Credential Type)
- `vct#integrity` (Type Metadata integrity hash)
- `status` (Credential status)

### Custom Policies

```swift
// All non-standard claims are disclosable
let policy = DisclosurePolicy.default

// Only specified paths are disclosable
let policy = DisclosurePolicy.disclosable(["/email", "/phone"])

// Custom visible claims
let policy = DisclosurePolicy(
    alwaysVisible: .standardVisibleClaims.union(["/given_name"]),
    disclosablePaths: nil
)
```

## Nested Object Disclosures

SD-JWT supports selective disclosure of nested claims:

```swift
var claims = try JSONWebTokenClaims {
    $0.address = .init(
        streetAddress: "123 Main St",
        locality: "Anytown",
        country: "US"
    )
}

// Conceal nested claims
let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .disclosable(["/address/street_address", "/address/locality"]),
    using: issuerKey
)
```

## Array Element Disclosures

Individual array elements can be selectively disclosed:

```swift
var claims = try JSONWebTokenClaims {
    $0.nationalities = ["US", "DE"]
}

// Conceal array elements
let sdJWT = try JSONWebSelectiveDisclosureToken(
    claims: claims,
    policy: .disclosable(["/nationalities/0", "/nationalities/1"]),
    using: issuerKey
)
```

## Security Considerations

### Algorithm Requirements

- The `"none"` algorithm is **rejected** for both SD-JWT and KB-JWT signatures
- Salt values must be at least 128 bits (16 bytes) of cryptographically random data

### Validation Requirements

The ``JSONWebSelectiveDisclosureToken/validate(requireKeyBinding:)`` method checks:
1. **Duplicate digest detection** - Rejects tokens with repeated digests in `_sd` arrays
2. **Orphan disclosure detection** - Rejects presentations with disclosures that have no matching digest
3. **Key binding validation** - Verifies KB-JWT when holder binding is required

### Key Binding Verification

``JSONWebSelectiveDisclosureToken/verifyKeyBinding(expectedNonce:expectedAudience:using:)`` validates:
1. KB-JWT algorithm is not `"none"`
2. KB-JWT header `typ` is `"kb+jwt"`
3. KB-JWT signature using holder's key from `cnf` claim
4. `iat`, `nonce`, `aud` claims match expectations
5. `sd_hash` matches the computed hash over the presentation

## Topics

### Creating SD-JWTs

- ``JSONWebSelectiveDisclosureToken/init(claims:policy:algorithm:hashAlgorithm:using:)``
- ``DisclosurePolicy``

### Presentations

- ``JSONWebSelectiveDisclosureToken/presenting(disclosures:)``
- ``JSONWebSelectiveDisclosureToken/presenting(paths:)``
- ``JSONWebSelectiveDisclosureToken/withKeyBinding(using:algorithm:nonce:audience:)``

### Verification

- ``JSONWebSelectiveDisclosureToken/validate(requireKeyBinding:)``
- ``JSONWebSelectiveDisclosureToken/verifyKeyBinding(expectedNonce:expectedAudience:using:)``
- ``JSONWebSelectiveDisclosureToken/disclosedPayload()``

### Disclosures

- ``JSONWebSelectiveDisclosure``
- ``JSONWebSelectiveDisclosureList``

### Claims

- ``JSONWebTokenSelectiveDisclosureClaimsParameters``
