# JWSETKit

A library for working with JSON Web Signature (JWS) and JSON Web Token (JWT).

[![Swift][swift-workflow-badge]][swift-workflow-url]
[![CodeQL][codeql-workflow-badge]][codeql-workflow-url]
[![License][license-badge]][license-url]
[![Release version][release-badge]][release-url]

[![][swift-versions-badge]][spi-url]
[![][platforms-badge]][spi-url]

## Overview

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JSON-based
[RFC7159][RFC7159] data structures.
The JWS cryptographic mechanisms provide integrity protection for 
an arbitrary sequence of octets.

JSON Web Token (JWT) is a compact claims representation format
intended for space constrained environments such as HTTP
Authorization headers and URI query parameters.

This module makes it possible to serialize, deserialize, create, 
and verify JWS/JWT messages.

## Supported Swift Versions

This library was introduced with support for Swift 5.8 or later.

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

For detailed usage and API documentation, check [the documentation][docs].

## Comparison To Other Libraries

### Features

|                                | JWSETKit | [jwt-kit] | [JOSESwift] | Auth0's [JWTDecode] |
|:-------------------------------|:--:|:--:|:--:|:--:|
| JSON Web Signature (JWS)       | ✅ | ❌ | ✅ | ❌ |
| JWS Multiple Signatures        | ✅ | ❌ | ❌ | ❌ |
| JWS Unencoded/Detached Payload | ✅ | ❌ | ❌ | ❌ |
| JSON Web Token (JWT)           | ✅ | ✅ | ✅ | ✅ |
| JWT Signature Verfication      | ✅ | ✅ | ✅ | ❌ |
| JWT Expire/NotBefore Validity  | ✅ | ✅ | ✅ | ❌ |
| JSON Web Encryption (JWE)      | ✅ | ❌ | ✅ | ❌ |
| Support [CommonCrypto] Keys    | ✅ | ❌ | ❌ | ❌ |
| Support [CryptoKit] Keys       | ✅ | ❌ | ❌ | ❌ |

### Supported Algorithms

#### Signature/HMAC

|       | JWSETKit | [jwt-kit] | [JOSESwift] | Auth0's [JWTDecode] |
|:------|:--:|:--:|:--:|:--:|
| HS256 | ✅ | ✅ | ✅ | ❌ |
| HS384 | ✅ | ✅ | ✅ | ❌ |
| HS512 | ✅ | ✅ | ✅ | ❌ |
| RS256 | ✅ | ✅ | ✅ | ❌ |
| RS384 | ✅ | ✅ | ✅ | ❌ |
| RS512 | ✅ | ✅ | ✅ | ❌ |
| ES256 | ✅ | ✅ | ✅ | ❌ |
| ES384 | ✅ | ✅ | ✅ | ❌ |
| ES512 | ✅ | ✅ | ✅ | ❌ |
| PS256 | ✅ | ✅ | ✅ | ❌ |
| PS384 | ✅ | ✅ | ✅ | ❌ |
| PS512 | ✅ | ✅ | ✅ | ❌ |
| PS512 | ✅ | ✅ | ✅ | ❌ |
| EdDSA | ✅ | ✅ | ✅ | ❌ |

#### Key Encryption

|                    | JWSETKit | [JOSESwift] |
|:-------------------|:--:|:--:|
| RSA1_5             | ✅ | ✅ |
| RSA-OAEP           | ✅ | ✅ |
| RSA-OAEP-256       | ✅ | ✅ |
| A128KW             | ✅ | ✅ |
| A192KW             | ✅ | ✅ |
| A256KW             | ✅ | ✅ |
| dir                | ✅ | ✅ |
| ECDH-ES            | ❌ | ❌ |
| ECDH-ES+A128KW     | ❌ | ❌ |
| ECDH-ES+A192KW     | ❌ | ❌ |
| ECDH-ES+A256KW     | ❌ | ❌ |
| A128GCMKW          | ✅ | ❌ |
| A192GCMKW          | ✅ | ❌ |
| A256GCMKW          | ✅ | ❌ |
| PBES2-HS256+A128KW | ✅ | ❌ |
| PBES2-HS384+A192KW | ✅ | ❌ |
| PBES2-HS512+A256KW | ✅ | ❌ |

#### Content Encryption

|               | JWSETKit | [JOSESwift] |
|:--------------|:--:|:--:|
| A128CBC-HS256 | ✅ | ✅ |
| A192CBC-HS384 | ✅ | ✅ |
| A256CBC-HS512 | ✅ | ✅ |
| A128GCM       | ✅ | ❌ |
| A192GCM       | ✅ | ❌ |
| A256GCM       | ✅ | ❌ |


[swift-workflow-badge]: https://github.com/amosavian/JWSETKit/actions/workflows/swift.yml/badge.svg
[swift-workflow-url]: https://github.com/amosavian/JWSETKit/actions/workflows/swift.yml
[codeql-workflow-badge]: https://github.com/amosavian/JWSETKit/actions/workflows/codeql.yml/badge.svg
[codeql-workflow-url]: https://github.com/amosavian/JWSETKit/actions/workflows/codeql.yml
[license-badge]: https://img.shields.io/github/license/amosavian/JWSETKit.svg
[license-url]: LICENSE
[release-badge]: https://img.shields.io/github/release/amosavian/JWSETKit.svg
[release-url]: https://github.com/amosavian/JWSETKit/releases
[swift-versions-badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Famosavian%2FJWSETKit%2Fbadge%3Ftype%3Dswift-versions
[spi-url]: https://swiftpackageindex.com/amosavian/JWSETKit
[platforms-badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Famosavian%2FJWSETKit%2Fbadge%3Ftype%3Dplatforms

[RFC7159]: https://www.rfc-editor.org/rfc/rfc7159
[docs]: https://amosavian.github.io/JWSETKit/documentation/jwsetkit/
[jwt-kit]: https://github.com/vapor/jwt-kit
[JOSESwift]: https://github.com/airsidemobile/JOSESwift
[JWTDecode]: https://github.com/auth0/JWTDecode.swift
[CommonCrypto]: https://developer.apple.com/documentation/security/certificate_key_and_trust_services
[CryptoKit]: https://developer.apple.com/documentation/cryptokit/
