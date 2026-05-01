# Key Agreement (ECDH)

Computing shared secrets with secp256k1 ECDH.

## Overview

Elliptic Curve Diffie-Hellman (ECDH) lets two parties derive the same
shared secret from one's private key and the other's public key. On
secp256k1, the shared secret is a curve point — this module returns the
**raw 32-byte X coordinate** of that point, wrapped in CryptoKit's
`SharedSecret` type.

```swift
let alice = P256K.KeyAgreement.PrivateKey()
let bob   = P256K.KeyAgreement.PrivateKey()

let aliceShared = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
let bobShared   = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)

// aliceShared and bobShared are equal — that's the point.
```

## Deriving Symmetric Keys

A raw shared secret is **not** suitable for use as an encryption key
directly — it lacks the uniformity that block ciphers expect. Run it
through a KDF first. CryptoKit's `SharedSecret` provides convenient
HKDF-based derivation:

```swift
let key = aliceShared.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: Data(),
    sharedInfo: Data("session-key".utf8),
    outputByteCount: 32
)
```

## Difference from libsecp256k1's Default

libsecp256k1's `secp256k1_ecdh` function applies SHA-256 to the X
coordinate (with a sign-byte prefix) before returning the 32-byte result.
This module returns the **un-hashed** X coordinate — matching the shape
that CryptoKit's `P256.KeyAgreement` returns. When porting code that uses
the libsecp256k1 default, you'll need to apply SHA-256 yourself, or skip
ahead and use HKDF.

## See Also

- <doc:1-Overview>
- ``P256K/KeyAgreement``
- ``P256K/KeyAgreement/PrivateKey``
- ``P256K/KeyAgreement/PublicKey``