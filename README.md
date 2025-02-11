# JWSETKit

A library for working with JSON Web Signature (JWS) and JSON Web Token (JWT).

[![Swift][swift-workflow-badge]][swift-workflow-url]
[![CodeQL][codeql-workflow-badge]][codeql-workflow-url]
[![License][license-badge]][license-url]
[![Release version][release-badge]][release-url]

[![Lines of Code][sonar-cloc-badge]][sonar-link]
[![Duplicated Lines][sonar-duplicated-lines-badge]][sonar-link]

[![Quality Gate Status][sonar-quality-badge]][sonar-link]
[![Technical Debt][sonar-tech-debt-badge]][sonar-link]
[![Maintainability Rating][sonar-maintainability-badge]][sonar-link]
[![Coverage][codecov-coverage-badge]][codecov-link]

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
    .package(url: "https://github.com/amosavian/JWSETKit", .upToNextMinor(from: "0.19.0"))
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

|                                | JWSETKit           | [jwt-kit]          | [JOSESwift]        | Auth0's [JWTDecode] |
|:-------------------------------|:------------------:|:------------------:|:------------------:|:-------------------:|
| JSON Web Signature (JWS)       | :white_check_mark: | :x:                | :white_check_mark: | :x:                 |
| JWS Multiple Signatures        | :white_check_mark: | :x:                | :x:                | :x:                 |
| JWS Unencoded/Detached Payload | :white_check_mark: | :x:                | :x:                | :x:                 |
| JSON Web Token (JWT)           | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| JWT Signature Verification     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| JWT Expire/NotBefore Validity  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| JSON Web Encryption (JWE)      | :white_check_mark: | :x:                | :white_check_mark: | :x:                 |
| Support [CommonCrypto] Keys    | :white_check_mark: | :x:                | :x:                | :x:                 |
| Support [CryptoKit] Keys       | :white_check_mark: | :x:                | :x:                | :x:                 |

### Supported Algorithms

#### Signature/HMAC

|       | JWSETKit           | [jwt-kit]          | [JOSESwift]        | Auth0's [JWTDecode] |
|:------|:------------------:|:------------------:|:------------------:|:-------------------:|
| HS256 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| HS384 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| HS512 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| RS256 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| RS384 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| RS512 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| ES256 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| ES384 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| ES512 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS256 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS384 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS512 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS512 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| EdDSA | :white_check_mark: | :white_check_mark: | :x:                | :x:                 |
| E256K | :x:                | :x:                | :x:                | :x:                 |

#### Key Encryption

|                    | JWSETKit           | [JOSESwift]        |
|:-------------------|:------------------:|:------------------:|
| RSA1_5             | :white_check_mark: | :white_check_mark: |
| RSA-OAEP           | :white_check_mark: | :white_check_mark: |
| RSA-OAEP-256       | :white_check_mark: | :white_check_mark: |
| A128KW             | :white_check_mark: | :white_check_mark: |
| A192KW             | :white_check_mark: | :white_check_mark: |
| A256KW             | :white_check_mark: | :white_check_mark: |
| dir                | :white_check_mark: | :white_check_mark: |
| ECDH-ES            | :white_check_mark: | :x:                |
| ECDH-ES+A128KW     | :white_check_mark: | :x:                |
| ECDH-ES+A192KW     | :white_check_mark: | :x:                |
| ECDH-ES+A256KW     | :white_check_mark: | :x:                |
| A128GCMKW          | :white_check_mark: | :x:                |
| A192GCMKW          | :white_check_mark: | :x:                |
| A256GCMKW          | :white_check_mark: | :x:                |
| PBES2-HS256+A128KW | :white_check_mark: | :x:                |
| PBES2-HS384+A192KW | :white_check_mark: | :x:                |
| PBES2-HS512+A256KW | :white_check_mark: | :x:                |

#### Content Encryption

|               | JWSETKit           | [JOSESwift]        |
|:--------------|:------------------:|:------------------:|
| A128CBC-HS256 | :white_check_mark: | :white_check_mark: |
| A192CBC-HS384 | :white_check_mark: | :white_check_mark: |
| A256CBC-HS512 | :white_check_mark: | :white_check_mark: |
| A128GCM       | :white_check_mark: | :x:                |
| A192GCM       | :white_check_mark: | :x:                |
| A256GCM       | :white_check_mark: | :x:                |


[swift-workflow-badge]: https://github.com/amosavian/JWSETKit/actions/workflows/swift.yml/badge.svg
[swift-workflow-url]: https://github.com/amosavian/JWSETKit/actions/workflows/swift.yml
[codeql-workflow-badge]: https://github.com/amosavian/JWSETKit/actions/workflows/codeql.yml/badge.svg
[codeql-workflow-url]: https://github.com/amosavian/JWSETKit/actions/workflows/codeql.yml
[license-badge]: https://img.shields.io/github/license/amosavian/JWSETKit.svg
[license-url]: LICENSE
[release-badge]: https://img.shields.io/github/release/amosavian/JWSETKit.svg
[release-url]: https://github.com/amosavian/JWSETKit/releases

[sonar-link]: https://sonarcloud.io/summary/new_code?id=amosavian_JWSETKit
[codecov-link]: https://codecov.io/gh/amosavian/JWSETKit
[sonar-quality-badge]: https://sonarcloud.io/api/project_badges/measure?project=amosavian_JWSETKit&metric=alert_status
[sonar-cloc-badge]: https://sonarcloud.io/api/project_badges/measure?project=amosavian_JWSETKit&metric=ncloc
[sonar-duplicated-lines-badge]: https://sonarcloud.io/api/project_badges/measure?project=amosavian_JWSETKit&metric=duplicated_lines_density
[sonar-maintainability-badge]: https://sonarcloud.io/api/project_badges/measure?project=amosavian_JWSETKit&metric=sqale_rating
[sonar-tech-debt-badge]: https://sonarcloud.io/api/project_badges/measure?project=amosavian_JWSETKit&metric=sqale_index
[codecov-coverage-badge]: https://codecov.io/gh/amosavian/JWSETKit/graph/badge.svg?token=PIYYY5XWAG

[swift-versions-badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Famosavian%2FJWSETKit%2Fbadge%3Ftype%3Dswift-versions
[spi-url]: https://swiftpackageindex.com/amosavian/JWSETKit
[platforms-badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Famosavian%2FJWSETKit%2Fbadge%3Ftype%3Dplatforms

[RFC7159]: https://www.rfc-editor.org/rfc/rfc7159
[docs]: https://swiftpackageindex.com/amosavian/JWSETKit/0.16.0/documentation/jwsetkit
[jwt-kit]: https://github.com/vapor/jwt-kit
[JOSESwift]: https://github.com/airsidemobile/JOSESwift
[JWTDecode]: https://github.com/auth0/JWTDecode.swift
[CommonCrypto]: https://developer.apple.com/documentation/security/certificate_key_and_trust_services
[CryptoKit]: https://developer.apple.com/documentation/cryptokit/
