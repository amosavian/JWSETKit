# JSON Web Token (JWT)

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

To create a JWT instance from `String` or `Data`,

```swift
let jwt = try JSONWebToken(from: authorization)
```

To assign a JWT to [`URLRequest`]()'s `Authorization` header,

```swift
var request = URLRequest(url: URL(string: "https://www.example.com")!)
request.authorizationToken = jwt
```

To convert back a JWT instance to string representation,

```swift
let jwtString = try String(jws: jwt)
```
or
```swift
let jwtString = jwt.description
```

## Accessing Claims

Various claims, including registered and claims defined by [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
are predefined for JSON Web Token's payload.

Claim names are more descriptive than keys defined by IANA Registry, 
for example `sub` claim became [`subject`](jsonwebtokenclaimsregisteredparameters/subject)
and `iat` became [`issuedAt`](jsonwebtokenclaimsregisteredparameters/issuedat).

For a complete list of predefined claims check ``JSONWebTokenClaimsRegisteredParameters``,
``JSONWebTokenClaimsOAuthParameters``, ``JSONWebTokenClaimsPublicOIDCAuthParameters`` and
``JSONWebTokenClaimsPublicOIDCStandardParameters``.

Access for claims that are not defined are possible as `dynamicMember` when 
value type is explicitly declared and is one of JWT standard types or `Codable`,
```swift
let issueAt: Date? = jwt.iat
```

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

Also `scope` items are separated by space according to standard and 
a list of items can be accessed using [scopes](jsonwebtokenclaimsoauthparameters/scopes). 

## Validating JWT

A JSON Web Token has a signature that can be verified before using.
Also `nbf` and `exp` claims can be verified using system date or a custom date.

### Verify Signature

See [JWS Signature Verification](3-jws#Verify-Signature)

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
        // Token is not valid yet accoring to `nbf`
        print(error.localizedDescription)
    }
} catch {
    print(error.localizedDescription)
}
```

A custom date can be passed to `verifyDate()`.

## Updating Signature

See [JWS Signature Update](3-jws#UpdatingAdding-Signature)

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
