# Keys and Certificates

Using cryptographic keys to sign, verify, encrypt and decrypt contents.

## Overview

This article give details about keys and their usage.

## Protocols

### JSONWebKey

An object that can represented in A JSON Web Key (JWK). data structure
represents a cryptographic key.

The key object can be fetched using [`storage`](jsonwebcontainer/storage) property.

### JSONWebValidatingKey

This protocol defines method to verify signatures,
which is usually a public or symmetric key.

### JSONWebEncryptingKey

This method defines method to encrypt a plain-text,
which is usually a public or symmetric key.

### JSONWebSigningKey

This protocol defines method to generate a new signature out of data,
which is usually a private or symmetric key.

### JSONWebDecryptingKey

This protocol defines method to decrypt a cipher-text,
which is usually a private or symmetric key.

## Implementations

### Symmetric

#### JSONWebKeyHMAC

Supports `HS256`, `HS384` and `HS512` algorithms for signature.

Usable for validating and signing. See [JSONWebKeyHMAC](jsonwebkeyhmac).

#### SymmetricKey

Supports `HS256`, `HS384` and `HS512` algorithms for signature and
`A128GCM`, `A192GCM` and `A256GCM` algorithms for encryption.

Usable for validating, signing, decryption and encrypting.
See [SymmetricKey](cryptokit/symmetrickey).

#### JSONWebKeyAESGCM

Supports `A128GCM`, `A192GCM` and `A256GCM` algorithms for encryption.

Usable for decryption and encrypting. See [JSONWebKeyAESGCM](jsonwebkeyaesgcm).

### Eliptic-Curve

#### JSONWebECPublicKey

Supports `ES256`, `ES384`, `ES512` and `EdDSA` algorithms for signature.

Usable for validating. See [JSONWebECPublicKey](jsonwebecpublickey).

#### JSONWebECPrivateKey

Supports `ES256`, `ES384`, `ES512` and `EdDSA` algorithms for signature.

Usable for validating and signing. See [JSONWebECPrivateKey](jsonwebecprivatekey).

#### P256.Signing.PublicKey

Supports `ES256` algorithm for signature.

Usable for validating.
See [P256.Signing.PublicKey](cryptokit/p256/signing/publickey).

#### P256.Signing.PrivateKey

Supports `ES256` algorithm for signature.

Usable for validating and signing.
See [P256.Signing.PrivateKey](cryptokit/p256/signing/privatekey).

##### P384.Signing.PublicKey

Supports `ES384` algorithm for signature.

Usable for validating.
See [P384.Signing.PublicKey](cryptokit/p384/signing/publickey).

#### P384.Signing.PrivateKey

Supports `ES384` algorithm for signature.

Usable for validating and signing.
See [P384.Signing.PrivateKey](cryptokit/p384/signing/privatekey).

##### P521.Signing.PublicKey

Supports `ES512` algorithm for signature.

Usable for validating.
See [P521.Signing.PublicKey](cryptokit/p521/signing/publickey).

#### P384.Signing.PrivateKey

Supports `ES512` algorithm for signature.

Usable for validating and signing.
See [P521.Signing.PrivateKey](cryptokit/p521/signing/privatekey).

##### Ed25519.Signing.PublicKey

Supports `EdDSA` algorithm for signature.

Usable for validating.
See [Curve25519.Signing.PublicKey](cryptokit/curve25519/signing/publickey).

#### Ed25519.Signing.PrivateKey

Supports `EdDSA` algorithm for signature.

Usable for validating and signing.
See [Curve25519.Signing.PrivateKey](cryptokit/curve25519/signing/privatekey).

### RSA

#### JSONWebRSAPublicKey

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` algorithms for signature and
`RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384` and `RSA-OAEP-512` for encryption.

Usable for validating and decryption. See [JSONWebRSAPublicKey](jsonwebrsapublickey).

#### JSONWebRSAPrivateKey

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` algorithms for signature and
`RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384` and `RSA-OAEP-512` for encryption.

Usable for validating, signing, decryption and encryption. See [JSONWebRSAPrivateKey](jsonwebrsaprivatekey).

#### SecKey

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`and `ES512` algorithms for signature.

Usable for validating and signing. See [SecKey](security/seckey).

#### \_RSA.Signing.PublicKey

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` algorithms for signature.

Usable for validating.

Usable for validating.
See [_CryptoExtras._RSA.Signing.PublicKey](_cryptoextras/_rsa/signing/publickey).

#### \_RSA.Signing.PrivateKey

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` algorithms for signature.

Usable for validating and signing.

Usable for validating and signing.
See [_CryptoExtras._RSA.Signing.PrivateKey](_cryptoextras/_rsa/signing/privatekey).

### X509 Certificates

#### X509.Certificate

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`and `ES512` algorithms for signature.

Usable for validating. See [X509.Certificate](x509/certificate).

#### SecCertificate

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`and `ES512` algorithms for signature.

Usable for validating. See [SecCertificate](security/seccertificate)
