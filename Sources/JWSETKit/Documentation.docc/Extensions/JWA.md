# ``JWSETKit/JSONWebAlgorithm``

Working with JSON Web Algorithms (JWA) for cryptographic operations.

## Overview

JSON Web Algorithms (JWA) defines the cryptographic algorithms used with JSON Web Signatures (JWS), JSON Web Encryption (JWE), and JSON Web Keys (JWK). The JWA specification establishes registers of algorithms for various cryptographic operations, such as digital signatures, message authentication, content encryption, and key management.

### Algorithm Categories

JWA specifies algorithms for several different use cases:

1. **Digital Signatures/MACs**: Used in JWS to sign data or generate Message Authentication Codes
2. **Key Management**: Used in JWE to encrypt or agree upon Content Encryption Keys (CEKs)
3. **Content Encryption**: Used in JWE to encrypt the actual payload
4. **Compression**: Used to compress data before encryption

## Supported Algorithms

### Signature and MAC Algorithms

The following signature and MAC algorithms are supported:

| Algorithm | Description | Type |
|-----------|-------------|------|
| `HS256` | HMAC using SHA-256 | Symmetric |
| `HS384` | HMAC using SHA-384 | Symmetric |
| `HS512` | HMAC using SHA-512 | Symmetric |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | Asymmetric |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 | Asymmetric |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 | Asymmetric |
| `PS256` | RSASSA-PSS using SHA-256 | Asymmetric |
| `PS384` | RSASSA-PSS using SHA-384 | Asymmetric |
| `PS512` | RSASSA-PSS using SHA-512 | Asymmetric |
| `ES256` | ECDSA using P-256 and SHA-256 | Asymmetric |
| `ES384` | ECDSA using P-384 and SHA-384 | Asymmetric |
| `ES512` | ECDSA using P-521 and SHA-512 | Asymmetric |
| `EdDSA` | Edwards-curve Digital Signature Algorithm | Asymmetric |

### Key Management Algorithms

The following key management algorithms are supported:

| Algorithm | Description | Type |
|-----------|-------------|------|
| `RSA1_5` | RSAES-PKCS1-v1_5 | Asymmetric |
| `RSA-OAEP` | RSAES OAEP using default parameters | Asymmetric |
| `RSA-OAEP-256` | RSAES OAEP using SHA-256 and MGF1 with SHA-256 | Asymmetric |
| `A128KW` | AES Key Wrap with 128-bit key | Symmetric |
| `A192KW` | AES Key Wrap with 192-bit key | Symmetric |
| `A256KW` | AES Key Wrap with 256-bit key | Symmetric |
| `dir` | Direct use of a shared symmetric key | Symmetric |
| `ECDH-ES` | Elliptic Curve Diffie-Hellman Ephemeral Static | Asymmetric |
| `ECDH-ES+A128KW` | ECDH-ES using Concat KDF and CEK wrapped with A128KW | Asymmetric |
| `ECDH-ES+A192KW` | ECDH-ES using Concat KDF and CEK wrapped with A192KW | Asymmetric |
| `ECDH-ES+A256KW` | ECDH-ES using Concat KDF and CEK wrapped with A256KW | Asymmetric |
| `A128GCMKW` | Key wrapping with AES GCM using 128-bit key | Symmetric |
| `A192GCMKW` | Key wrapping with AES GCM using 192-bit key | Symmetric |
| `A256GCMKW` | Key wrapping with AES GCM using 256-bit key | Symmetric |
| `PBES2-HS256+A128KW` | Password Based Encryption using PBES2 | Symmetric |
| `PBES2-HS384+A192KW` | Password Based Encryption using PBES2 | Symmetric |
| `PBES2-HS512+A256KW` | Password Based Encryption using PBES2 | Symmetric |

### Content Encryption Algorithms

The following content encryption algorithms are supported:

| Algorithm | Description |
|-----------|-------------|
| `A128CBC-HS256` | AES CBC 128-bit with HMAC SHA-256 (truncated to 128 bits) |
| `A192CBC-HS384` | AES CBC 192-bit with HMAC SHA-384 (truncated to 192 bits) |
| `A256CBC-HS512` | AES CBC 256-bit with HMAC SHA-512 (truncated to 256 bits) |
| `A128GCM` | AES GCM 128-bit |
| `A192GCM` | AES GCM 192-bit |
| `A256GCM` | AES GCM 256-bit |

### Compression Algorithms

| Algorithm | Description |
|-----------|-------------|
| `DEF` | DEFLATE compression |

## Working with Algorithms

### Creating and Using Algorithms

```swift
// Using predefined algorithm constants
let sigAlg = JSONWebSignatureAlgorithm.rsaSignaturePKCS1v15SHA256 // RS256
let encAlg = JSONWebKeyEncryptionAlgorithm.rsaEncryptionOAEP
let contEncAlg = JSONWebContentEncryptionAlgorithm.aesEncryptionGCM256

// Create an algorithm from a string
let alg = JSONWebSignatureAlgorithm("ES256")

// Set algorithm in a JWS header
var header = JOSEHeader()
header.algorithm = .rsaSignaturePKCS1v15SHA256

// Check algorithm type
if header.algorithm == .hmacSHA256 {
    // Use symmetric signing
}
```

### Using Algorithms with CryptoKit Types

```swift
// Generate keys for specific algorithms

// HMAC SHA-256 key
let hmacKey = try JSONWebKeyHMAC<SHA256>(SymmetricKey(size: .bits256))
let hmacSignature = try hmacKey.signature(data, using: .hmacSHA256)

// RSA key for RS256
let rsaPrivateKey = try JSONWebRSAPrivateKey(keySize: .bits2048)
let rsaSignature = try rsaPrivateKey.signature(data, using: .rsaSignaturePKCS1v15SHA256)

// EC key for ES256
let ecPrivateKey = P256.Signing.PrivateKey()
let ecJwk = try JSONWebECPrivateKey(storage: ecPrivateKey.storage)
let ecSignature = try ecJwk.signature(data, using: .ecdsaSignatureP256SHA256)

// EdDSA key
let edPrivateKey = Curve25519.Signing.PrivateKey()
let edJwk = try JSONWebECPrivateKey(storage: edPrivateKey.storage)
let edSignature = try edJwk.signature(data, using: .eddsaSignature)
```

### Selecting Keys Based on Algorithms

```swift
// Create a key for a specific algorithm
let key = try JSONWebRSAPrivateKey(algorithm: JSONWebSignatureAlgorithm.rsaSignaturePKCS1v15SHA256)

// Sign with a specific algorithm
let signature = try privateKey.signature(data, using: .rsaSignaturePKCS1v15SHA256)

// Verify with a specific algorithm
try publicKey.verifySignature(signature, for: data, using: .rsaSignaturePKCS1v15SHA256)

// Encrypt with a specific algorithm
let encrypted = try publicKey.encrypt(data, using: .rsaEncryptionOAEP)
let decrypted = try privateKey.decrypt(encrypted, using: .rsaEncryptionOAEP)

// Key derivation with ECDH
let ecdhSenderPrivateKey = P256.KeyAgreement.PrivateKey()
let ecdhReceiverPublicKey = /* receiver's public key */
let sharedSecret = try JSONWebECPrivateKey(storage: ecdhSenderPrivateKey.storage)
    .sharedSecretFromKeyAgreement(with: receiverPublicKey)
```

### Content Encryption with AES GCM

```swift
// Generate a symmetric key for AES-GCM-256
let aesKey = try JSONWebKeyAESGCM(.bits256)

// Encrypt content
let sealed = try aesKey.seal(plaintext, using: .aesEncryptionGCM256)

// Decrypt content
let decrypted = try aesKey.open(sealed, using: .aesEncryptionGCM256)
```

## Topics

### Signature Algorithms

- ``JSONWebSignatureAlgorithm``
- ``AnyJSONWebAlgorithm``

### Encryption Algorithms

- ``JSONWebKeyEncryptionAlgorithm``
- ``JSONWebContentEncryptionAlgorithm``

### Compression

- ``JSONWebCompressionAlgorithm``