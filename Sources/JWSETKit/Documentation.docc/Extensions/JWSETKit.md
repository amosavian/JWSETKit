# ``JWSETKit``

JWS / JWE / JWT Kit for Swift

## Overview

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JSON-based
[RFC7159](https://datatracker.ietf.org/doc/html/rfc7159) data structures.
The JWS cryptographic mechanisms provide integrity protection for 
an arbitrary sequence of octets.

JSON Web Token (JWT) is a compact claims representation format
intended for space constrained environments such as HTTP
Authorization headers and URI query parameters.

This module makes it possible to serialize, deserialize, create, 
and verify JWS/JWT messages.

## Getting Started

To use JWSETKit, add the following dependency to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/amosavian/JWSETKit", .upToNextMinor(from: "0.8.0"))
]
```

Note that this repository does not have a 1.0 tag yet, so the API is not stable.

You can then add the specific product dependency to your target:

```swift
dependencies: [
    .product(name: "JWSETKit", package: "JWSETKit"),
]
```

## Usage

### JSON Web Token (JWT)

Check ``JSONWebToken`` documentation for usage, validation and signing
of JWT.

### JSON Web Signature (JWS)

Check ``JSONWebSignature`` documentation for usage, validation and signing
of JWS.

### JSON Web Encryption (JWE)

Check ``JSONWebEncryption`` documentation for usage, encrypting and decrypting
payload.

## Topics

### Essentials

- ``JSONWebToken``
- ``JSONWebSignature``
- ``JSONWebEncryption``

### Cryptography

- <doc:3-Cryptography>

### Extending

- <doc:7-Extending-Container>
- ``JSONWebContainer``
- ``ProtectedWebContainer``
- ``TypedProtectedWebContainer``
- ``ProtectedJSONWebContainer``
- ``ProtectedDataWebContainer``
