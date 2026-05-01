# Security Notes

Known sharp edges to be aware of.

## FIPS Compliance and `compactRepresentable`

``P256K/Signing/PrivateKey/init(compactRepresentable:)`` defaults to `true`,
which means the generator rejects keys whose public point has odd y.
Restricting the keyspace this way is a deviation from standard ECDSA
keygen and is **not FIPS-140-compliant**. If your deployment requires FIPS
certification, generate keys from externally-provided random bytes via
``P256K/Signing/PrivateKey/init(rawRepresentation:)`` instead, or pass
`compactRepresentable: false`.

The constraint exists so that the resulting public key always has a valid
BIP-340 X-only encoding. If you're not using Schnorr, the compactRepresentable
constraint isn't useful.

## Signature Malleability

Raw ECDSA signatures are malleable: for any valid `(r, s)` there exists a
matching `(r, n − s)` that verifies for the same key and message. A
verifier that compares signature bytes for identity (rather than verifying
cryptographically) can be tricked into treating the two as different
signatures of the same statement.

This module always normalizes parsed signatures to **low-s** canonical
form. ``P256K/Signing/ECDSASignature/init(derRepresentation:)``,
``P256K/Signing/ECDSASignature/init(rawRepresentation:recoveryId:)``, and
``P256K/Signing/ECDSASignature/init(compactRepresentation:format:)`` all
route through the same normalization step. Signatures produced by
``P256K/Signing/PrivateKey/signature(for:)`` are low-s natively (via
libsecp256k1).

## Key Generation Rejection Sampling

``P256K/Signing/PrivateKey/init(compactRepresentable:)`` uses rejection
sampling: it generates random 32-byte values and discards any that are
`0`, ≥ the curve order, or (when `compactRepresentable: true`) produce a
public key with odd y. The expected number of attempts is < 4. The loop is
bounded only by the validity check and assumes the system RNG is sound;
on a broken RNG this is not the bug to worry about.

## See Also

- <doc:3-ECDSASignatures>
- <doc:4-CompactSignatureFormats>