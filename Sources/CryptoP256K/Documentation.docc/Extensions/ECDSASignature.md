# ``P256K/Signing/ECDSASignature``

A P-256K elliptic curve digital signature.

## Overview

An ECDSA signature is the pair `(r, s)` plus an optional 2-bit recovery ID
that identifies which public key produced it. See <doc:3-ECDSASignatures>
for usage and <doc:4-CompactSignatureFormats> for wire formats.

## Topics

### Creating a Signature

- ``init(rawRepresentation:recoveryId:)``
- ``init(derRepresentation:)``
- ``init(compactRepresentation:format:)``

### Inspecting the Signature

- ``rawRepresentation``
- ``recoveryId``
- ``derRepresentation``
- ``compactRepresentation(format:)``

### Recovering a Public Key

- ``recoverPublicKey(from:)-(D)``
- ``recoverPublicKey(from:)-(D1)``

### Compact Wire Formats

- ``CompactRepresentationFormat``
- <doc:4-CompactSignatureFormats>