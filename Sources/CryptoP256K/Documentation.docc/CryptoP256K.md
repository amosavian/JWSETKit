# ``CryptoP256K``

A CryptoKit-style API for the secp256k1 elliptic curve.

## Overview

`CryptoP256K` provides ECDSA signing, Schnorr (BIP-340) signing, and ECDH key
agreement on the secp256k1 (P-256K) curve — the curve used by Bitcoin and
Ethereum. The API surface mirrors Apple's `Crypto` framework: `P256K.Signing`
and `P256K.KeyAgreement` namespaces with familiar `PrivateKey` / `PublicKey`
types and the standard set of key serializations (`rawRepresentation`,
`x963Representation`, `compressedRepresentation`, `derRepresentation`,
`pemRepresentation`).

This module is distinct from CryptoKit's `P256` type, which uses the NIST
P-256 curve. secp256k1 and P-256 are different curves; keys are not
interchangeable.

The module is built on top of `libsecp256k1` and is shipped as a separate
Swift Package Manager target so applications that don't need it pay no cost.

## Getting Started

`CryptoP256K` is a separate target within the JWSETKit package. Add the
product dependency to your target:

```swift
dependencies: [
    .product(name: "CryptoP256K", package: "JWSETKit"),
]
```

Then import it where needed:

```swift
import CryptoP256K
```

## Usage

### ECDSA Signing

```swift
let privateKey = P256K.Signing.PrivateKey()
let signature = try privateKey.signature(for: message)

if privateKey.publicKey.isValidSignature(signature, for: message) {
    // Signature is valid.
}
```

See <doc:3-ECDSASignatures> for details on signature normalization, recovery,
and the available compact serialization formats.

### Schnorr Signing (BIP-340)

```swift
let privateKey = P256K.Signing.PrivateKey()
let signature = try privateKey.schnorrSignature(for: message)

if privateKey.publicKey.isValidSchnorrSignature(signature, for: message) {
    // Signature is valid.
}
```

### ECDH Key Agreement

```swift
let alice = P256K.KeyAgreement.PrivateKey()
let bob = P256K.KeyAgreement.PrivateKey()

let shared = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
```

See <doc:5-KeyAgreement> for details.

### Compact Signature Formats

ECDSA signatures can carry a recovery ID. ``P256K/Signing/ECDSASignature``
exposes five compact serialization formats — `raw`, `bitcoin`, `etherium`,
`eip155(chainId:)`, and `eip2098` — covering the common conventions used by
Bitcoin and Ethereum tooling.

```swift
let compact = try signature.compactRepresentation(format: .eip2098)
let parsed  = try P256K.Signing.ECDSASignature(compactRepresentation: compact, format: .eip2098)
```

See <doc:4-CompactSignatureFormats> for byte layouts and when to use each.

## Topics

### Essentials

- ``P256K``
- <doc:1-Overview>

### Signing

- ``P256K/Signing``
- ``P256K/Signing/PrivateKey``
- ``P256K/Signing/PublicKey``
- ``P256K/Signing/ECDSASignature``
- <doc:3-ECDSASignatures>

### Compact Representations

- <doc:4-CompactSignatureFormats>

### Key Agreement

- ``P256K/KeyAgreement``
- ``P256K/KeyAgreement/PrivateKey``
- ``P256K/KeyAgreement/PublicKey``
- <doc:5-KeyAgreement>

### Manuals

- <doc:1-Overview>
- <doc:2-KeyRepresentations>
- <doc:3-ECDSASignatures>
- <doc:4-CompactSignatureFormats>
- <doc:5-KeyAgreement>
- <doc:6-SecurityNotes>