# ``JSONWebEncryption``

Use JWE to encrypt a payload.

## Overview

JSON Web Encryption (JWE) represents encrypted content using JSON-based 
data structures RFC7159. The JWE cryptographic mechanismsencrypt 
and provide integrity protection for an arbitrary sequence of octets.

## Decoding And Decrypting

To create a new instance from compact or complete serialization,

``` swift
let jwe = try JSONWebEncryption(from: jweString)
```

Now it is possible to decrypt data using private key,

```swift
let data = try jwe.decrypt(using: keyEncryptionKey)
```

Decrypted content now can be deserialzed. For example if content is JWT claims,

```swift
let claims = JSONDecoder().decode(JSONWebTokenClaims.self, from: data)
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

In case multiple recipient support is neccessary or a unknown newly registered key type
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
