# Key Representations

How to serialize and parse secp256k1 keys.

## Overview

A secp256k1 public key is a point `(x, y)` on the curve, with each coordinate
fitting in 32 bytes. There are several standard ways to encode that point on
the wire — the right choice depends on what you're interoperating with.
``P256K/Signing/PublicKey`` and ``P256K/KeyAgreement/PublicKey`` expose all of
them.

## Public Key Forms

| Form | Bytes | Layout | Use it when |
|------|-------|--------|-------------|
| ``P256K/Signing/PublicKey/rawRepresentation`` | 64 | `x ‖ y` | You need the bare coordinates, no prefix. Common in protocol buffers and JOSE JWK `x` + `y` fields. |
| ``P256K/Signing/PublicKey/x963Representation`` | 65 | `0x04 ‖ x ‖ y` | ANSI X9.63 uncompressed. The default for SEC1 / OpenSSL `EC_POINT_point2oct` output. |
| ``P256K/Signing/PublicKey/compressedRepresentation`` | 33 | `0x02 ‖ x` (even y) or `0x03 ‖ x` (odd y) | SEC1 compressed. Half the size; the y coordinate is recovered from x and the parity byte. Default in Bitcoin since 2012. |
| ``P256K/Signing/PublicKey/compactRepresentation`` | 32 | `x` only | BIP-340 X-only public key. Returns `nil` if y is odd — Schnorr keys are constrained to even-y. |
| ``P256K/Signing/PublicKey/derRepresentation`` | variable | DER `SubjectPublicKeyInfo` | OpenSSL/X.509-compatible, suitable for embedding in certificates. |
| ``P256K/Signing/PublicKey/pemRepresentation`` | text | PEM-wrapped DER | Human-readable; what `openssl ec -pubout` produces. |
| ``P256K/Signing/PublicKey/elligatorSwiftRepresentation`` | 64 | encoded curve point | BIP-324 v2 transport encoding — public keys indistinguishable from random bytes. |

Every form has a matching initializer. For example, given a 33-byte
compressed key:

```swift
let compressed: Data = ...
let publicKey = try P256K.Signing.PublicKey(compressedRepresentation: compressed)
```

Roundtripping between forms is supported: parse from one, emit as another.

```swift
let pem = try P256K.Signing.PublicKey(x963Representation: x963).pemRepresentation
```

## Private Key Forms

Private keys are simpler — the secret is a single 32-byte scalar.

| Form | Bytes | Use it when |
|------|-------|-------------|
| ``P256K/Signing/PrivateKey/rawRepresentation`` | 32 | The bare secret scalar. Common in BIP-340 test vectors and Ethereum keystores after decryption. |
| ``P256K/Signing/PrivateKey/x963Representation`` | 97 | ANSI X9.63: `0x04 ‖ x ‖ y ‖ d` — the public point followed by the private scalar. |
| ``P256K/Signing/PrivateKey/derRepresentation`` | variable | DER PKCS#8 (or SEC1 EC PRIVATE KEY) — what OpenSSL writes. The PEM/DER initializers accept both. |
| ``P256K/Signing/PrivateKey/pemRepresentation`` | text | PEM-wrapped DER. |

## X-Only Keys and Even-y Constraint

BIP-340 (Schnorr) treats a public key as just its X coordinate, with the
implicit convention that the y coordinate is even. The
``P256K/Signing/PublicKey/compactRepresentation`` accessor returns `nil`
when the underlying key has odd y, because there's no valid X-only encoding.

If you want a private key whose public key is guaranteed to be
X-only-representable, pass `compactRepresentable: true` (the default) when
generating it:

```swift
let key = P256K.Signing.PrivateKey()  // compactRepresentable defaults to true
let xOnly = key.publicKey.compactRepresentation  // never nil for keys created this way
```

For interop with arbitrary keys (FIPS-style flows, imported keys), pass
`compactRepresentable: false`.

## ElligatorSwift

ElligatorSwift (BIP-324) encodes a secp256k1 public key as 64 bytes
indistinguishable from uniform random data. It's used in Bitcoin P2P
protocol v2 to make handshakes traffic-analysis-resistant.

```swift
let key = P256K.Signing.PrivateKey()
let encoded = key.publicKey.elligatorSwiftRepresentation  // 64 random-looking bytes
let decoded = try P256K.Signing.PublicKey(elligatorSwiftRepresentation: encoded)
```

The encoding is non-deterministic: each call uses fresh randomness, so two
encodings of the same key won't match byte-for-byte (but both decode to the
same key).

## See Also

- <doc:1-Overview>
- <doc:3-ECDSASignatures>