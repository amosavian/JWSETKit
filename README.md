# JWSETKit

A library for working with JSON Web Signature (JWS) and .
**A modern, type-safe Swift library for JSON Web Token (JWT), JSON Web Signature (JWS),
 and JSON Web Encryption (JWE) with first-class Apple's CryptoKit support**

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

Building secure authentication in Swift? JWSETKit is your complete solution
for working with **JSON Web Tokens (JWT)**, **JSON Web Signatures (JWS)**,
and **JSON Web Encryption (JWE)** with native Apple CryptoKit integration.

This module makes it possible to serialize, deserialize, create, 
and verify JWS/JWT messages.


## 📖 Table of Contents

- [Features](#-features)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Comparison with Alternatives](#-comparison-with-alternatives)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Features

### Core Capabilities

✅ **JWT (JSON Web Tokens)**
- Create, sign, verify, and decode JWT tokens
- Support for standard and custom claims
- Expiration and validation handling

✅ **JWS (JSON Web Signature)**
- Digital signatures with multiple algorithms
- Message authentication codes (MACs)
- Detached signature support

✅ **JWE (JSON Web Encryption)**
- Content encryption with various algorithms
- Key wrapping and management
- Compact and JSON serialization

✅ **JWK (JSON Web Keys)**
- Key generation and management
- Key conversion and serialization
- Support for key sets (JWKS)

## Getting Started

### Swift Package Manager

Add JWSETKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/amosavian/JWSETKit", from: "1.0.0")
]
```

Then add to your target:

```swift
dependencies: [
    .product(name: "JWSETKit", package: "JWSETKit"),
]
```

### With X509 Support

For X509 certificate support (Swift 6.1+):

```swift
dependencies: [
    .package(url: "https://github.com/amosavian/JWSETKit", from: "1.0.0", traits: ["X509"])
]
```

### With P256K Support

For secp256k1 (ES256K) support (Swift 6.1+):

```swift
dependencies: [
    .package(url: "https://github.com/amosavian/JWSETKit", from: "1.0.0", traits: ["X509"])
]
```

### Xcode

1. File → Add Package Dependencies
2. Enter: `https://github.com/amosavian/JWSETKit`
3. Select version and add to your target

## Usage

For detailed usage and API documentation, check [the documentation][docs].

### Creating and Verifying JWT Signature

```swift
import JWSETKit
import CryptoKit

// Create a JWT with claims
let key = SymmetricKey(size: .bits128)
let payload = try JSONWebTokenClaims {
    $0.issuedAt = .init()
    $0.expiry = .init(timeIntervalSinceNow: 3600)
    $0.jwtUUID = .init()
    $0.subject = "user123"
}
let jwt = try JSONWebToken(payload: payload, algorithm: .hmacSHA256, using: key)

// Verify and decode
let decodedJWT = try JSONWebToken(from: jwtString)
try decodedJWT.verifySignature(using: key)
print(decodedJWT.payload.subject) // "user123"
```

### Basic JWT Authentication

```swift
// Initialize key
let key = try P256.Signing.PublicKey(pemRepresentation: publicKeyPEM)

// Verify incoming JWT
    
let token = try JSONWebToken(from: request.headers["Authorization"])
try token.verify(using: key, for: "audience-name")
```

### Working with JWS

```swift
// Sign arbitrary data with JWS
let payload = "Important message"
let jws = try JSONWebSignaturePlain(
    payload: payload.utf8,
    algorithm: .ecdsaSignatureP256SHA256,
    using: key
)
try print(String(jws))

// Verify JWS signature
let verified = try JSONWebSignaturePlain(from: String(jws))
try verified.verifySignature(using: key)
let message = String(decoding: verified.payload, as: UTF8.self)
```

### Encrypting with JWE

```swift
// Encrypt sensitive data
let sensitiveData = Data("Secret information".utf8)
let encryptionKey = JSONWebRSAPrivateKey(keySize: .bits2048) 
let jwe = try JSONWebEncryption(
    content: sensitiveData,
    keyEncryptingAlgorithm: .rsaEncryptionOAEP,
    keyEncryptionKey: encryptionKey.publicKey,
    contentEncryptionAlgorithm: .aesEncryptionGCM128
)
try print(String(jwe))

// Decrypt JWE
let jwe = try JSONWebEncryption(from: jweString)
let decrypted = jwe.decrypt(using: encryptionKey)
let secret = String(decoding: decrypted, as: UTF8.self)
```

### Managing Keys with JWK

```swift
// Create CryptoKit key
let privateKey = P256.Signing.PrivateKey()

// Import and Export as JWK data
let jwkJSON = try JSONEncoder().encode(privateKey)
let importedJWK = try JSONDecoder().decode(P256.Signing.PrivateKey.self, from: jwkJSON)

// Import PKCS#8
let importedKey = try P256.Signing.PrivateKey(importing: pkcs8Data, format: .pkcs8)
```

## 📊 Comparison with Alternatives

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

|           | JWSETKit           | [jwt-kit]          | [JOSESwift]        | Auth0's [JWTDecode] |
|:----------|:------------------:|:------------------:|:------------------:|:-------------------:|
| HS256     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| HS384     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| HS512     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| RS256     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| RS384     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| RS512     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| ES256     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| ES384     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| ES512     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS256     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS384     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS512     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| PS512     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                 |
| EdDSA     | :white_check_mark: | :white_check_mark: | :x:                | :x:                 |
| Ed25519   | :white_check_mark: | :x:                | :x:                | :x:                 |
| Ed448     | :x:                | :x:                | :x:                | :x:                 |
| ES256K    | :white_check_mark: | :x:                | :x:                | :x:                 |
| ML-DSA-44 | :x:                | :x:                | :x:                | :x:                 |
| ML-DSA-65 | :white_check_mark: | :x:                | :x:                | :x:                 |
| ML-DSA-87 | :white_check_mark: | :x:                | :x:                | :x:                 |

#### Key Encryption

|                        | JWSETKit           | [JOSESwift]        |
|:-----------------------|:------------------:|:------------------:|
| RSA1_5                 | :white_check_mark: | :white_check_mark: |
| RSA-OAEP               | :white_check_mark: | :white_check_mark: |
| RSA-OAEP-256           | :white_check_mark: | :white_check_mark: |
| A128KW                 | :white_check_mark: | :white_check_mark: |
| A192KW                 | :white_check_mark: | :white_check_mark: |
| A256KW                 | :white_check_mark: | :white_check_mark: |
| dir                    | :white_check_mark: | :white_check_mark: |
| ECDH-ES                | :white_check_mark: | :white_check_mark: |
| ECDH-ES+A128KW         | :white_check_mark: | :white_check_mark: |
| ECDH-ES+A192KW         | :white_check_mark: | :white_check_mark: |
| ECDH-ES+A256KW         | :white_check_mark: | :white_check_mark: |
| A128GCMKW              | :white_check_mark: | :x:                |
| A192GCMKW              | :white_check_mark: | :x:                |
| A256GCMKW              | :white_check_mark: | :x:                |
| PBES2-HS256+A128KW     | :white_check_mark: | :x:                |
| PBES2-HS384+A192KW     | :white_check_mark: | :x:                |
| PBES2-HS512+A256KW     | :white_check_mark: | :x:                |
| HPKE-0 (P256/AES128)   | :white_check_mark: | :x:                |
| HPKE-1 (P384/AES256)   | :white_check_mark: | :x:                |
| HPKE-2 (P521/AES256)   | :white_check_mark: | :x:                |
| HPKE-3 (X25519/AES256) | :white_check_mark: | :x:                |
| HPKE-4 (X25519/ChaCha) | :white_check_mark: | :x:                |
| HPKE-5 (X448/AES256)   | :x:                | :x:                |
| HPKE-6 (X448/ChaCha)   | :x:                | :x:                |
| HPKE-7 (P256/AES256)   | :white_check_mark: | :x:                |

#### Content Encryption

|               | JWSETKit           | [JOSESwift]        |
|:--------------|:------------------:|:------------------:|
| A128CBC-HS256 | :white_check_mark: | :white_check_mark: |
| A192CBC-HS384 | :white_check_mark: | :white_check_mark: |
| A256CBC-HS512 | :white_check_mark: | :white_check_mark: |
| A128GCM       | :white_check_mark: | :white_check_mark: |
| A192GCM       | :white_check_mark: | :white_check_mark: |
| A256GCM       | :white_check_mark: | :white_check_mark: |


## 🏗️ Use Cases

JWSETKit is perfect for:

- 🔑 **API Authentication** - Secure REST API authentication with JWT tokens
- 🌐 **OAuth 2.0 / OpenID Connect** - Implement modern authentication flows
- 📱 **Mobile App Security** - Token-based auth for iOS/macOS apps
- 🔄 **Microservices** - Service-to-service authentication
- 🎫 **Session Management** - Stateless session tokens
- 🔐 **Data Encryption** - Protect sensitive data with JWE

## 📚 Documentation

### 📖 [Full Documentation][docs]

Browse our comprehensive guides:
- [Getting Started Guide][docs]
- [API Reference][docs]
- [Security Best Practices](https://swiftpackageindex.com/amosavian/JWSETKit/documentation/jwsetkit/security)

## 🤝 Contributing

We welcome contributions!

### How to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development

```bash
# Clone the repository
git clone https://github.com/amosavian/JWSETKit.git

# Run tests
swift test

# Build the project
swift build
```

## 🌟 Support

- 🐛 [Report Issues](https://github.com/amosavian/JWSETKit/issues)
- 💬 [Discussions](https://github.com/amosavian/JWSETKit/discussions)
- 📧 [Contact](https://github.com/amosavian)

## 📄 License

JWSETKit is released under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

This library implements the following JOSE standards:
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) - JSON Web Signature (JWS)
- [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) - JSON Web Encryption (JWE)
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) - JSON Web Key (JWK)
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) - JSON Web Algorithms (JWA)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) - JSON Web Token (JWT)
- [RFC 7520](https://www.rfc-editor.org/rfc/rfc7519) - Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
- [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) - JSON Web Signature (JWS) Unencoded Payload Option
- [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)
- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) - Fully-Specified Algorithms for JOSE and COSE
- [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/) - Use of Hybrid Public Key Encryption (HPKE) with JSON Object Signing and Encryption (JOSE)
- [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) - ML-DSA for JOSE and COSE
- [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) - OpenID Connect Core 1.0 incorporating errata set 2

---

<div align="center">

**Built with ❤️ using Swift**

[![Star on GitHub](https://img.shields.io/github/stars/amosavian/JWSETKit.svg?style=social)](https://github.com/amosavian/JWSETKit/stargazers)

</div>

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

[docs]: https://swiftpackageindex.com/amosavian/JWSETKit/documentation
[jwt-kit]: https://github.com/vapor/jwt-kit
[JOSESwift]: https://github.com/airsidemobile/JOSESwift
[JWTDecode]: https://github.com/auth0/JWTDecode.swift
[CommonCrypto]: https://developer.apple.com/documentation/security/certificate_key_and_trust_services
[CryptoKit]: https://developer.apple.com/documentation/cryptokit/
