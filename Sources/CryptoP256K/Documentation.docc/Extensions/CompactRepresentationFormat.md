# ``P256K/Signing/ECDSASignature/CompactRepresentationFormat``

Wire-format conventions for ECDSA signatures with recovery ID.

## Overview

Different ecosystems pack a recoverable ECDSA signature differently.
``P256K/Signing/ECDSASignature/CompactRepresentationFormat`` enumerates the
common ones. See <doc:4-CompactSignatureFormats> for byte layouts, source
specs, and guidance on choosing between them.

## Topics

### Formats

- ``raw``
- ``bitcoin``
- ``etherium``
- ``eip155(chainId:)``
- ``eip2098``

### Articles

- <doc:4-CompactSignatureFormats>