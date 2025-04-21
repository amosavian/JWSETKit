# ``JWSETKit/JSONWebKey``

Working with JSON Web Keys (JWK) for cryptographic operations.

## Overview

JSON Web Key (JWK) is a JSON data structure that represents a cryptographic key. The JWK format provides a standardized way to represent keys used for digital signatures, encryption, or other operations in a JSON-based format.

### Structure of a JWK

A JWK is a JSON object containing information about a cryptographic key:

```json
{
  "kty": "RSA",                       // Key Type (Required)
  "use": "sig",                       // Public Key Use (Optional)
  "kid": "1234",                      // Key ID (Optional)
  "alg": "RS256",                     // Algorithm (Optional)
  
  // Key-specific parameters (Required)
  // For RSA keys:
  "n": "base64url-encoded-modulus",
  "e": "base64url-encoded-exponent",
  
  // For EC keys:
  "crv": "P-256",
  "x": "base64url-encoded-x-coordinate",
  "y": "base64url-encoded-y-coordinate",
  
  // For symmetric keys:
  "k": "base64url-encoded-key-value"
}
```

### JWK Set (JWKS)

Multiple JWKs can be grouped in a JWK Set (JWKS), which is a JSON object containing an array of keys:

```json
{
  "keys": [
    {
      "kty": "RSA",
      // ...other key parameters
    },
    {
      "kty": "EC",
      // ...other key parameters
    }
  ]
}
```

## Working with JWKs

### Creating a JWK

You can create a JWK from various sources:

```swift
// Create a new RSA key pair
let privateKey = try JSONWebRSAPrivateKey(keySize: .bits2048)
let publicKey = privateKey.publicKey

// Create a symmetric key for HMAC with SHA-256
let hmacKey = try JSONWebKeyHMAC<SHA256>(.init(size: .bits256))

// Create an EC key pair - P-256 curve
let ecPrivateKey = try JSONWebECPrivateKey(curve: .p256)

// Using CryptoKit types directly
// CryptoKit P-256 key
let p256Key = P256.Signing.PrivateKey()
let p256JWK = try JSONWebECPrivateKey(storage: p256Key.storage)

// CryptoKit Symmetric key
let symmetricKey = SymmetricKey(size: .bits256)
let hmacJWK = try JSONWebKeyHMAC<SHA256>(symmetricKey)

// CryptoKit Ed25519 key
let edKey = Curve25519.Signing.PrivateKey()
let edJWK = try JSONWebECPrivateKey(storage: edKey.storage)
```

### Importing a JWK

Import a JWK from various formats:

```swift
// Import from JWK format (JSON)
let jwkData = """
{
  "kty": "EC",
  "crv": "P-256",
  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
}
""".data(using: .utf8)!

let publicKey = try JSONWebECPublicKey(importing: jwkData, format: .jwk)

// Import from DER/PEM format
let derData = getKeyData() // Your DER-encoded key data
let rsaKey = try JSONWebRSAPublicKey(importing: derData, format: .spki)

// Import CryptoKit key from raw format
let rawKeyData = Data(repeating: 1, count: 32) // 256-bit key
let importedSymmetricKey = try SymmetricKey(data: rawKeyData)
let importedHmacKey = try JSONWebKeyHMAC<SHA256>(importedSymmetricKey)
```

### Exporting a JWK

```swift
// Export to JWK format
let jwkData = try publicKey.exportKey(format: .jwk)
let jwkString = String(data: jwkData, encoding: .utf8)

// Export to PKCS#8 or SPKI format
let derData = try privateKey.exportKey(format: .pkcs8)

// Export CryptoKit key
let p256Key = P256.Signing.PrivateKey()
let p256Data = try JSONWebECPrivateKey(storage: p256Key.storage).exportKey(format: .jwk)
```

### Using a Key Set

```swift
// Create a key set
var keySet = JSONWebKeySet()
keySet.append(publicKey)
keySet.append(anotherKey)

// Find keys by ID
let foundKey = keySet.first { $0.keyId == "key-1" }

// Extract public keys only
let publicKeySet = keySet.publicKeyset

// Export to JWKS format
let encoder = JSONEncoder()
let jwksData = try encoder.encode(keySet)
```

## Key Thumbprints

JWK thumbprints provide a unique identifier for a key:

```swift
// Create a thumbprint
let thumbprint = try publicKey.thumbprint(format: .jwk, using: SHA256.self)
let thumbprintString = thumbprint.data.urlBase64EncodedString()

// Create a thumbprint URI per RFC 9278
let thumbprintUri = try publicKey.thumbprintUri(format: .jwk, using: SHA256.self)

// Generate a key ID automatically using thumbprint
var mutableKey = try JSONWebRSAPrivateKey(keySize: .bits2048)
mutableKey.populateKeyIdIfNeeded() // Fills `kid` with thumbprint URI
```

## Topics

### Key Types

- ``JSONWebRSAPublicKey``
- ``JSONWebRSAPrivateKey``
- ``JSONWebECPublicKey``
- ``JSONWebECPrivateKey``
- ``JSONWebKeyHMAC``
- ``JSONWebKeyAESGCM``
- ``JSONWebKeyAESCBCHMAC``
- ``JSONWebKeyAESKW``

### Key Containers

- ``AnyJSONWebKey``
- ``JSONWebKeySet``

### Key Operations

- ``JSONWebValidatingKey``
- ``JSONWebSigningKey``
- ``JSONWebEncryptingKey``
- ``JSONWebDecryptingKey``
- ``JSONWebSealingKey``

### Key Formats

- ``JSONWebKeyFormat``
- ``JSONWebKeyType``
- ``JSONWebKeyCurve``
- ``JSONWebKeyUsage``
- ``JSONWebKeyOperation``

### Key Import/Export

- ``JSONWebKeyImportable``
- ``JSONWebKeyExportable``