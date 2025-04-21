# ``JWSETKit/JSONWebEncryption``

Use JWE to encrypt a payload.

## Overview

JSON Web Encryption (JWE) represents encrypted content using JSON-based 
data structures RFC7159. The JWE cryptographic mechanisms encrypt 
and provide integrity protection for an arbitrary sequence of octets.

### Structure of a Compact JWE Token

A JWE in compact serialization consists of five parts separated by dots (`.`):

```
header.encrypted_key.iv.ciphertext.tag
```

Each part is Base64URL encoded:

1. **Protected Header**: Contains metadata about encryption algorithms
2. **Encrypted Key**: Contains the content encryption key (CEK) encrypted with the recipient's key
3. **Initialization Vector**: Random data used as input to the encryption algorithm
4. **Ciphertext**: The encrypted payload data
5. **Authentication Tag**: Ensures data integrity and authenticity

Visualized structure:
```
┌─────────────┐  ┌─────────────┐  ┌─────┐  ┌───────────┐  ┌─────┐
│   Header    │  │ Encrypted   │  │ IV  │  │Ciphertext │  │ Tag │
│ {           │  │    Key      │  │     │  │           │  │     │
│  "alg":"RSA1_5"│  (encrypted   │  │     │  │ (encrypted │  │     │
│  "enc":"A256GCM"│  CEK)       │  │     │  │  data)    │  │     │
│ }           │  │             │  │     │  │           │  │     │
└─────────────┘  └─────────────┘  └─────┘  └───────────┘  └─────┘
       │                │             │          │           │
       │                │             └──────────┼───────────┘
       │                │                        │
       │                │                authenticated encryption
       │                │                        │
       │        key encryption                   │
       │                │                        │
       └────────────────┼────────────────────────┘
                        │
                   recipient key
```

## Decoding And Decrypting

To create a new instance from compact or complete serialization,

``` swift
do {
    let jwe = try JSONWebEncryption(from: jweString)
    // Work with the JWE object
} catch {
    print("Failed to parse JWE: \(error)")
}
```

Now it is possible to decrypt data using the appropriate key:

```swift
do {
    let data = try jwe.decrypt(using: keyEncryptionKey)
    // Process the decrypted data
} catch {
    print("Decryption failed: \(error)")
}
```

Decrypted content now can be deserialized. For example if content is JWT claims:

```swift
do {
    let claims = try JSONDecoder().decode(JSONWebTokenClaims.self, from: data)
    // Access the claims
    let subject = claims.subject
} catch {
    print("Failed to decode claims: \(error)")
}
```

## Encrypting & Encoding

To create a new container from plain-text data and a key, first
create a new random *Key Encryption Key* or use an existing one.

Either provide no `contentEncryptionKey` to generate new random one,
or provide an existing one.

Finally, serialize the result into string representation.

```swift
// Generate a new AES-KeyWrap key with `A256KW` algorithm.
let kek = JSONWebKeyAESKW(.bits256)

// Alternatively, simply generate a 256-bit `SymmetricKey`.
//
// This works well as `keyEncryptingAlgorithm` is provided
// in next step.
let kek = SymmetricKey(size: .bits256)

// Create JWE container with random content enc. key.
let jwe = try! JSONWebEncryption(
    content: Data("Live long and prosper.".utf8),
    keyEncryptingAlgorithm: .aesKeyWrap256,
    keyEncryptionKey: kek,
    contentEncryptionAlgorithm: .aesEncryptionGCM128
)

// Encode JWE in compact string.
let jweString = try! String(jwe: jwe)
```

In case multiple recipient support is necessary or a unknown newly registered key type
is used for encryption, you may first create encrypted key and sealed box and use 
``JSONWebEncryption/init(header:recipients:sealed:additionalAuthenticatedData:)``
to create JWE instance from parts.

## Topics

### Contents

- ``JSONWebEncryptionHeader``
- ``JSONWebEncryptionRecipient``

### Key Encryption

- ``JSONWebKeyEncryptionAlgorithm``
- ``JSONWebRSAPublicKey``
- ``JSONWebRSAPrivateKey``
- ``JSONWebKeyAESKW``

### Content Encryption

- ``JSONWebKeyAESGCM``
- ``JSONWebKeyAESCBCHMAC``

### Encoding

- ``JSONWebEncryptionRepresentation``
- ``JSONWebEncryptionCodableConfiguration``
