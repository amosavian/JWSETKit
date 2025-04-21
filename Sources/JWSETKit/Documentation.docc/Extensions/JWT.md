# ``JWSETKit/JSONWebToken``

Usage of JWT, Verifying and make new signatures.  

## Overview

JSON Web Token (JWT) is a compact, URL-safe means of representing
claims to be transferred between two parties.  

The claims in a JWT are encoded as a JSON object that is used as 
the payload of a JSON Web Signature (JWS) structure or as the 
plaintext of a JSON Web Encryption (JWE) structure, enabling the 
claims to be digitally signed or integrity protected with a Message
Authentication Code (MAC) and/or encrypted.

## Initializing And Encoding

To create a JWT instance from `String` or `Data`:

```swift
do {
    let jwt = try JSONWebToken(from: jwtString)
    // Work with the parsed JWT
} catch {
    // Handle parsing errors
    print("Failed to parse JWT: \(error)")
}
```

To assign a JWT to [`URLRequest`](https://developer.apple.com/documentation/foundation/urlrequest)'s
`Authorization` header using ``Foundation/URLRequest/authorizationToken``:

```swift
var request = URLRequest(url: URL(string: "https://www.example.com")!)
request.authorizationToken = jwt
```

To convert a JWT instance back to its string representation:

```swift
do {
    let jwtString = try String(jws: jwt)
    // Use jwtString
} catch {
    print("Failed to serialize JWT: \(error)")
}
```

Or more simply, using the `description` property (which returns an empty string if serialization fails):

```swift
let jwtString = jwt.description
```

## Accessing Claims

Various claims, including registered and claims defined by [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
are predefined for JSON Web Token's payload.

Claim names are more descriptive than keys defined by IANA Registry, 
for example `sub` claim became ``JSONWebTokenClaimsRegisteredParameters/subject``
and `iat` became ``JSONWebTokenClaimsRegisteredParameters/issuedAt``.

For a complete list of predefined claims check ``JSONWebTokenClaimsRegisteredParameters``,
``JSONWebTokenClaimsOAuthParameters``, ``JSONWebTokenClaimsPublicOIDCAuthParameters`` and
``JSONWebTokenClaimsPublicOIDCStandardParameters``.

For `StringORURL` types that are common to be a `URL`, there are two accessors 
for `String` and `URL`, e.g.
```swift
let subjectString = jwt.subject // `sub` claim as String
let subjectURL = jwt.subjectURL // `sub` claim parsed as URL
```

Date types are converted automatically from Unix Epoch to Swift's `Date`.

For types that can be either a string or an array of strings, data type is `[String]`,
```swift
let singleAudience = jwt.audience.first
```

Also ``JSONWebTokenClaimsOAuthParameters/scope`` items are separated by
space according to standard and a list of items can be accessed
using ``JSONWebTokenClaimsOAuthParameters/scopes``. 

## Declaring New Claims

To extend existing ``JSONWebTokenClaims`` define a new `struct` 
with proposed new claims and add a `JSONWebTokenClaims.subscript(dynamicMember:)`
in order to access the claim.

```swift
struct JSONWebTokenClaimsJwkParameters: JSONWebContainerParameters {
    typealias Container = JOSEHeader
    var subJsonWebToken: (any JsonWebKey)?

    // Key lookup to convert claim to string key.
    static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.subJsonWebToken: "sub_jwk",
    ]
}

extension JSONWebTokenClaims {
    subscript<T>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsJwkParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
```

Intrinsic supported types to be parsed by generic accessor are:

- `UnsignedInteger` conforming types, e.g. `UInt`, `UInt32`, etc.
- `SignedInteger` conforming types, e.g. `Int`, `Int32`, etc.
- `BinaryFloatingPoint` conforming types, e.g. `Double`, `Float`, etc.
- `Foundation.Decimal`
- `Foundation.Date`, serialized as unix timestamp.
- `Array<UInt8>`, `Foundation.Data`, `Foundation.NSData`, seriailzed as `Base64URL`.
- `Foundation.URL`
- `Foundation.Locale`, `Foundation.NSLocale`
- `Foundation.TimeZone`, `Foundation.NSTimeZone`
- Types conformed to ``JSONWebKey``.
- Types conformed to ``JSONWebAlgorithm``.
- Types conformed to `Foundation.Decodable`.


## Validating JWT

A JSON Web Token has a signature that can be verified before using.
Also `nbf` and `exp` claims can be verified using system date or a custom date.

### Verify Signature

See [JWS Signature Verification](jsonwebsignature#Verify-Signature)

### Verify Expiration

To verify that JWT is not expired yet,

```swift
do {
    try jws.verifyDate()
} catch let error as JSONWebValidationError {
    switch error {
    case .tokenExpired(let expiry):
        // Token is expired according to `exp`
        print(error.localizedDescription)
        await renewToken()
    case .tokenInvalidBefore(let notBefore):
        // Token is not valid yet according to `nbf`
        print(error.localizedDescription)
    case .audienceNotIntended(let audience):
        // Invalid audience.
        print(error.localizedDescription)
    }
} catch {
    print(error.localizedDescription)
}
```

A custom date can be passed to `verifyDate()`.

## Updating Signature

See [JWS Signature Update](jsonwebsignature#UpdatingAdding-Signature)

## Topics

### JOSE Headers

- ``JOSEHeader``
- ``JoseHeaderJWSRegisteredParameters``

### JWT Claims

- ``JSONWebTokenClaims``
- ``JSONWebTokenClaimsRegisteredParameters``
- ``JSONWebTokenClaimsOAuthParameters``
- ``JSONWebTokenClaimsPublicOIDCStandardParameters``
- ``JSONWebTokenClaimsPublicOIDCAuthParameters``

### Signature

- ``JSONWebSignature``
