# ECDSA Signatures

Signing and verifying with ECDSA, signature normalization, and key recovery.

## Overview

ECDSA (Elliptic Curve Digital Signature Algorithm) on secp256k1 produces
signatures that are pairs of 32-byte integers, conventionally called `(r, s)`.
This module exposes them as ``P256K/Signing/ECDSASignature`` values.

Signing is straightforward:

```swift
let privateKey = P256K.Signing.PrivateKey()
let signature = try privateKey.signature(for: message)  // hashes with SHA-256
```

You can also sign a pre-computed digest if your protocol uses something other
than SHA-256:

```swift
let digest = SHA256.hash(data: message)
let signature = try privateKey.signature(for: digest)
```

Verification matches that shape. ``P256K/Signing/PublicKey/isValidSignature(_:for:)``
returns a Bool — there is no thrown error for invalid signatures, only for
malformed inputs upstream.

```swift
let isValid = privateKey.publicKey.isValidSignature(signature, for: message)
```

## Schnorr Signatures (BIP-340)

For BIP-340 Schnorr, use ``P256K/Signing/PrivateKey/schnorrSignature(for:)``.
Schnorr signatures are always 64 bytes, with no recovery ID.

```swift
let signature = try privateKey.schnorrSignature(for: message)
let isValid = privateKey.publicKey.isValidSchnorrSignature(signature, for: message)
```

Schnorr verification uses the X-only public key. If the underlying key has
odd y, the verifier internally negates it — there's no public-API distinction.

## Recovery ID

Signatures produced by ``P256K/Signing/PrivateKey/signature(for:)``
internally call libsecp256k1's recoverable-signing API and carry a
``P256K/Signing/ECDSASignature/recoveryId`` (0–3). With the recovery ID and
the signed message hash, you can recover the public key that produced the
signature without knowing it ahead of time — this is the basis for
Ethereum's `ecrecover` opcode.

```swift
let signature = try privateKey.signature(for: message)
let digest = SHA256.hash(data: message)
let recovered = try signature.recoverPublicKey(from: digest)

assert(recovered.rawRepresentation == privateKey.publicKey.rawRepresentation)
```

Signatures parsed from DER do **not** carry a recovery ID — DER doesn't
encode it. If you need recovery, parse the signature in a format that
carries the recovery byte (see <doc:4-CompactSignatureFormats>).

## Compact Wire Formats

When transmitting an ECDSA signature with recovery ID, several conventions
exist. ``P256K/Signing/ECDSASignature/CompactRepresentationFormat`` covers
the common ones — `raw`, `bitcoin`, `etherium`, `eip155(chainId:)`,
`eip2098`. See <doc:4-CompactSignatureFormats> for the byte layouts and
when to use each.

## See Also

- <doc:4-CompactSignatureFormats>
- <doc:6-SecurityNotes>