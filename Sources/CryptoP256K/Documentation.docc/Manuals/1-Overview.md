# Overview

What secp256k1 is and how this module is organized.

## The Curve

secp256k1 is a Koblitz curve defined over the prime field
F<sub>p</sub> with p = 2<sup>256</sup> − 2<sup>32</sup> − 977, with the
equation:

```
y² = x³ + 7  (mod p)
```

It was popularized by Bitcoin and is also the curve used by Ethereum and
many other blockchains. The "K" in P-256K marks it as the **Koblitz** curve
in the SECG SEC 2 standard, distinguishing it from the NIST **prime** curve
P-256 (also known as secp256r1).

The two curves are completely separate cryptographic systems:

| Curve | Standard | Equation | Used by |
|-------|----------|----------|---------|
| secp256k1 (P-256K) | SECG | y² = x³ + 7 | Bitcoin, Ethereum |
| secp256r1 (P-256) | NIST | y² = x³ − 3x + b | TLS, JWT/JOSE, FIDO |

Keys, signatures, and shared secrets from one curve are not valid on the
other.

## Module Organization

`CryptoP256K` is split into two namespaces:

- ``P256K/Signing`` — ECDSA and Schnorr (BIP-340) signing.
- ``P256K/KeyAgreement`` — ECDH key agreement.

Each namespace exposes `PrivateKey` and `PublicKey` types whose API matches
Apple's CryptoKit conventions: the same initializers
(``P256K/Signing/PrivateKey/init(rawRepresentation:)``,
``P256K/Signing/PrivateKey/init(x963Representation:)``,
``P256K/Signing/PrivateKey/init(derRepresentation:)``,
``P256K/Signing/PrivateKey/init(pemRepresentation:)``) and the same accessors
(``P256K/Signing/PrivateKey/rawRepresentation``,
``P256K/Signing/PrivateKey/derRepresentation``).

## What's Provided

- **ECDSA** signing and verification, with optional recovery ID support and
  five compact wire formats (see <doc:4-CompactSignatureFormats>).
- **Schnorr signatures** per BIP-340, including X-only public keys and
  signature verification against BIP-340 test vectors.
- **ECDH** key agreement, returning a raw 32-byte shared secret (the X
  coordinate of the shared point).
- **ElligatorSwift** encoding for indistinguishable-from-random public keys
  (BIP-324).
- Standard key serializations: raw, ANSI X9.63, compressed, x-only, DER, and
  PEM.

## What's Not Provided

- Bitcoin/Ethereum address derivation. Hash a public key with the relevant
  algorithm (RIPEMD-160 over SHA-256 for Bitcoin P2PKH; Keccak-256 for
  Ethereum) using a hash library of your choice.
- Transaction encoding and signing. This module gives you the ECDSA
  primitive; transaction structure is the consumer's responsibility.

## See Also

- <doc:2-KeyRepresentations>
- <doc:3-ECDSASignatures>
- <doc:5-KeyAgreement>
- <doc:6-SecurityNotes>