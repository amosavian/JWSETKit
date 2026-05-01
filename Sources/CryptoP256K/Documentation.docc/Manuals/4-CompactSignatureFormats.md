# Compact Signature Formats

Five wire formats for ECDSA signatures with recovery ID, and when to use each.

## Overview

An ECDSA signature on its own is the pair `(r, s)` — 64 bytes. Adding a
**recovery ID** lets a verifier compute the signing public key from the
signature and message hash, without it being transmitted. Different
ecosystems pack the recovery ID differently. This module supports five:

```
.raw       [ r (32) │ s (32) │ recId (1) ]                      65 bytes  (libsecp256k1 default)
.bitcoin   [ 27+recId (1) │ r (32) │ s (32) ]                   65 bytes  (BIP-137 base form)
.etherium  [ r (32) │ s (32) │ 27+recId (1) ]                   65 bytes  (legacy, pre-EIP-155)
.eip155    [ r (32) │ s (32) │ tail (1..8 bytes, big-endian) ]  65–72 bytes
.eip2098   [ r (32) │ (recId<<255 | s) (32) ]                   64 bytes  (yParityAndS)
```

Use ``P256K/Signing/ECDSASignature/compactRepresentation(format:)`` to
encode and ``P256K/Signing/ECDSASignature/init(compactRepresentation:format:)``
to decode.

## .raw

libsecp256k1's native compact serialization. The recovery byte is appended
at the end.

```swift
let compact = try signature.compactRepresentation(format: .raw)  // 65 bytes
let parsed  = try P256K.Signing.ECDSASignature(compactRepresentation: compact, format: .raw)
```

Use this when you control both ends of the wire and just want a
self-contained 65-byte blob with no semantic overhead.

## .bitcoin

The format used by Bitcoin's `signmessage` / `verifymessage` RPC for
uncompressed P2PKH addresses. The first byte is `27 + recId`, followed by
`r` then `s`.

```swift
let compact = try signature.compactRepresentation(format: .bitcoin)  // 65 bytes
```

Specified in [BIP-137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki).
BIP-137 also defines header bytes 31–34 (compressed P2PKH) and 35–38
(P2SH and SegWit variants); the ``P256K/Signing/ECDSASignature/CompactRepresentationFormat/bitcoin``
case implements only the **27/28 base form** — the uncompressed-key path.
For the other variants, encode with `.bitcoin` and adjust the header byte
yourself.

## .etherium

Legacy (pre-EIP-155) Ethereum signature layout: `r ‖ s ‖ v` with
`v = 27 + recId`. Used by `eth_sign` and Solidity's `ecrecover` for
non-replay-protected signatures.

```swift
let compact = try signature.compactRepresentation(format: .etherium)  // 65 bytes
```

Without EIP-155 chain-ID protection, these signatures are valid on any
EVM-compatible chain. For new transactions, prefer
``P256K/Signing/ECDSASignature/CompactRepresentationFormat/eip155(chainId:)``.

## .eip155

[EIP-155](https://eips.ethereum.org/EIPS/eip-155) replay-protected Ethereum
signature: `r ‖ s ‖ v` with

```
v = recId + 35 + 2 * chainId
```

The `v` value can exceed one byte for chain IDs ≥ 111 (e.g. chainId = 111
gives v ∈ {257, 258}, which encodes as `0x0101` or `0x0102`). The format
encodes the tail as a big-endian integer with leading zeros stripped — so
the total length ranges from 65 bytes (chainId ≤ 110) up to 72 bytes for
extreme chain IDs.

```swift
let compact = try signature.compactRepresentation(format: .eip155(chainId: 1))   // 65 bytes
let compact = try signature.compactRepresentation(format: .eip155(chainId: 111)) // 66 bytes
```

Decoding requires the same `chainId` you encoded with — the recovery ID is
recovered as `(v − 35 − 2*chainId) & 1`.

## .eip2098

[EIP-2098](https://eips.ethereum.org/EIPS/eip-2098) compact signature: 64
bytes, with the recovery bit packed into the high bit of `s`. Saves one byte
of calldata per signature on Ethereum — useful for gas-sensitive contracts.

```
yParityAndS = (recId << 255) | s
compact     = r ‖ yParityAndS    // 64 bytes total
```

```swift
let compact = try signature.compactRepresentation(format: .eip2098)  // 64 bytes
let parsed  = try P256K.Signing.ECDSASignature(compactRepresentation: compact, format: .eip2098)
```

## Choosing a Format

| Goal | Format |
|------|--------|
| Smallest on-chain footprint (Ethereum) | ``P256K/Signing/ECDSASignature/CompactRepresentationFormat/eip2098`` |
| Replay-protected Ethereum transaction | ``P256K/Signing/ECDSASignature/CompactRepresentationFormat/eip155(chainId:)`` |
| Compatibility with `eth_sign` / `personal_sign` | ``P256K/Signing/ECDSASignature/CompactRepresentationFormat/etherium`` |
| `bitcoin-cli signmessage` interop | ``P256K/Signing/ECDSASignature/CompactRepresentationFormat/bitcoin`` |
| Plain blob, no ecosystem semantics | ``P256K/Signing/ECDSASignature/CompactRepresentationFormat/raw`` |

## See Also

- <doc:3-ECDSASignatures>
- ``P256K/Signing/ECDSASignature``
- ``P256K/Signing/ECDSASignature/CompactRepresentationFormat``