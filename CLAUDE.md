# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JWSETKit is a Swift library for working with JSON Web Signature (JWS), JSON Web Encryption (JWE), and JSON Web Token (JWT) according to JOSE (JSON Object Signing and Encryption) standards. The library provides comprehensive cryptographic functionality for signing, encrypting, and verifying JSON web tokens with support for multiple algorithms and key types.

## Development Commands

### Building and Testing
```bash
# Build the project
swift build -v

# Run all tests
swift test -v

# Run tests with code coverage
swift test -v --enable-code-coverage

# Run tests using Make
make test
```

### Cross-Platform Testing
```bash
# Test on Linux using Docker
make linuxtest

# Clean Linux test (builds fresh container)
make cleanlinuxtest
```

### Package Management
The project uses Swift Package Manager with dependencies defined in `Package.swift`. Key dependencies:
- `swift-collections` for data structures
- `swift-asn1` for ASN.1 parsing
- `swift-crypto` for cryptographic operations
- `swift-certificates` for X.509 certificate support
- `swift-testing` for testing framework

## Architecture Overview

### Core Components

**Base Layer** (`Sources/JWSETKit/Base/`):
- `WebContainer.swift`: Core protocol for JSON containers used throughout JOSE structures
- `ProtectedContainer.swift`: Base for protected (signed/encrypted) containers
- `Storage.swift`: Key-value storage abstraction for JOSE headers and payloads
- `Error.swift`: Centralized error handling for the library

**Entities** (`Sources/JWSETKit/Entities/`):
- **JWS** (`JWS/`): JSON Web Signature implementation with support for multiple signatures
- **JWE** (`JWE/`): JSON Web Encryption with recipient-based encryption
- **JWT** (`JWT/`): JSON Web Token built on top of JWS with registered claims
- **JOSE** (`JOSE/`): JOSE header implementations for different token types

**Cryptography** (`Sources/JWSETKit/Cryptography/`):
- **Algorithms** (`Algorithms/`): Algorithm abstractions and implementations for signature, key encryption, and content encryption
- **EC** (`EC/`): Elliptic curve cryptography (P-256, P-384, P-521, Ed25519, HPKE)
- **RSA** (`RSA/`): RSA cryptography with PKCS#1 and PSS padding
- **PQC** (`PQC/`): Post-quantum cryptography (ML-DSA variants)
- **Symmetric** (`Symmetric/`): Symmetric key operations (AES, HMAC, KDF)
- **Certificate** (`Certificate/`): X.509 certificate handling and JSON Web Certificate support

### Key Design Patterns

**Generic Containers**: The library uses generic `JSONWebSignature<Payload>` and similar structures where `Payload` conforms to `ProtectedWebContainer`. This allows type-safe handling of different payload types (JWT claims, arbitrary JSON, etc.).

**Algorithm Abstraction**: Cryptographic algorithms implement the `JSONWebAlgorithm` protocol, providing consistent interfaces for signature, key encryption, and content encryption algorithms.

**Storage Pattern**: JSON data is managed through `JSONWebValueStorage` which provides dynamic member lookup and type-safe access to JOSE header fields and JWT claims.

**Cross-Platform Support**: The library uses conditional imports (`FoundationEssentials` vs `Foundation`) and platform-specific implementations to support both Apple platforms and Linux.

## Key Types and Protocols

- `JSONWebContainer`: Base protocol for all JOSE JSON structures
- `ProtectedWebContainer`: Protocol for containers that can be protected (signed/encrypted)
- `JSONWebAlgorithm`: Protocol for cryptographic algorithms
- `JSONWebSignature<Payload>`: Generic JWS structure
- `JSONWebEncryption`: JWE structure with recipient support
- `JSONWebToken`: Type alias for JWS with JWT claims payload

## Supported Algorithms

The library implements extensive algorithm support including:
- **Signatures**: HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512, EdDSA, ML-DSA-65/87
- **Key Encryption**: RSA1_5, RSA-OAEP(-256,-384,-512), A128/192/256KW, ECDH-ES variants, A128/192/256GCMKW, PBES2
- **Content Encryption**: A128/192/256GCM, A128/192/256CBC-HS256/384/512

## Testing Structure

Tests are organized in `Tests/JWSETKitTests/` with:
- **Base/**: Tests for core container and storage functionality
- **Cryptography/**: Algorithm-specific tests and RFC compliance tests
- **Entities/**: Tests for JWS, JWE, JWT structures
- **Extensions/**: Tests for utility extensions

The test suite includes RFC 7520 compliance tests for encryption, decryption, and signature verification.

## Platform Support

- **Apple Platforms**: iOS 15, macOS 12+, tvOS 15+, macCatalyst 15+
- **Linux**: Supported via Docker testing
- **Swift Versions**: 6.0, 6.1, 6.2

## Notes for Development

- X.509 certificate support is optional from Swift 6.1+ and requires explicit trait activation
- The library supports both compact (base64url) and JSON serialization formats
- Post-quantum cryptography (ML-DSA) is supported on macOS/iOS 26+
- Cross-platform differences are handled through conditional compilation and traits
