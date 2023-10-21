# Cryptography

Cryptography keys and algorithms

## Protocols

### Key Protocol

An object that can represented in A JSON Web Key (JWK). data structure
represents a cryptographic key.

The key object can be fetched using ``JSONWebContainer/storage`` property.

See ``JSONWebKey``.

### Signature Validation

This protocol defines method to verify signatures,
which is usually a public or symmetric key.

See ``JSONWebValidatingKey``.

### Encryption

This method defines method to encrypt a plain-text,
which is usually a public or symmetric key.

See ``JSONWebEncryptingKey``.

### Signing

This protocol defines method to generate a new signature out of data,
which is usually a private or symmetric key.

See ``JSONWebSigningKey`` and ``JSONWebSymmetricSigningKey``.

### Decryption

This protocol defines method to decrypt a cipher-text,
which is usually a private or symmetric key.

See ``JSONWebDecryptingKey`` and ``JSONWebSymmetricDecryptingKey``.

### Sealing

This method defines method to encrypt/decrypt a plain-text with initial vector
and resulting an authentication tag, which is asymmetric key.

See ``JSONWebSealingKey``.

## Keys and Certificates

### Symmetric

#### HMAC

Supports `HS256`, `HS384` and `HS512` algorithms for signature.

Usable for validating and signing. See ``JSONWebKeyHMAC``.

#### SymmetricKey

Supports `HS256`, `HS384` and `HS512` algorithms for signature,
`A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A192CBC-HS384` and
`A256CBC-HS512` algorithms for sealing, and `A128KW`, `A192KW`, `A256KW`,
`PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` and `PBES2-HS512+A256KW` for
encryption/decryption.

Usable for validating, signing, decryption and encrypting.
See ``CryptoKit/SymmetricKey``.

##### Generating SymmetricKey using PBKDF2

To generate a symmetric key using PBKDF2 use ``CryptoKit/SymmetricKey/pbkdf2(pbkdf2Password:salt:hashFunction:iterations:)``  method.

#### AES GCM

Supports `A128GCM`, `A192GCM` and `A256GCM` algorithms for encryption.

Usable for decryption and encrypting. See ``JSONWebKeyAESGCM``.

#### AES CBC-HMAC

Supports `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512` algorithms for encryption.

Usable for decryption and encrypting. See ``JSONWebKeyAESCBCHMAC``.

### Eliptic-Curve

#### Public Key

Supports `ES256`, `ES384`, `ES512` and `EdDSA` algorithms for signature.

Usable for validating. See ``JSONWebECPublicKey``.

##### P256.Signing.PublicKey

Supports `ES256` algorithm for signature.

Usable for validating.
See [P256.Signing.PublicKey](cryptokit/p256/signing/publickey).

###### P384.Signing.PublicKey

Supports `ES384` algorithm for signature.

Usable for validating.
See [P384.Signing.PublicKey](cryptokit/p384/signing/publickey).

##### P521.Signing.PublicKey

Supports `ES512` algorithm for signature.

Usable for validating.
See [P521.Signing.PublicKey](cryptokit/p521/signing/publickey).

##### Ed25519.Signing.PublicKey

Supports `EdDSA` algorithm for signature.

Usable for validating.
See [Curve25519.Signing.PublicKey](cryptokit/curve25519/signing/publickey).

#### Private Key

Supports `ES256`, `ES384`, `ES512` and `EdDSA` algorithms for signature.

Usable for validating and signing. See ``JSONWebECPrivateKey``.

##### P256.Signing.PrivateKey

Supports `ES256` algorithm for signature.

Usable for validating and signing.
See [P256.Signing.PrivateKey](cryptokit/p256/signing/privatekey).

##### P384.Signing.PrivateKey

Supports `ES384` algorithm for signature.

Usable for validating and signing.
See [P384.Signing.PrivateKey](cryptokit/p384/signing/privatekey).

##### P384.Signing.PrivateKey

Supports `ES512` algorithm for signature.

Usable for validating and signing.
See [P521.Signing.PrivateKey](cryptokit/p521/signing/privatekey).

##### Ed25519.Signing.PrivateKey

Supports `EdDSA` algorithm for signature.

Usable for validating and signing.
See [Curve25519.Signing.PrivateKey](cryptokit/curve25519/signing/privatekey).

### RSA

#### Public Key

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` algorithms for signature and
`RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384` and `RSA-OAEP-512` for encryption.

Usable for validating and decryption. See ``JSONWebRSAPublicKey``.

#### Private Key

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` algorithms for signature and
`RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384` and `RSA-OAEP-512` for encryption.

Usable for validating, signing, decryption and encryption. See ``JSONWebRSAPrivateKey``.

#### SecKey

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`and `ES512` algorithms for signature.

Usable for validating and signing. See ``Security/SecKey``.

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

Usable for validating. See ``X509/Certificate``.

#### SecCertificate

Supports `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`and `ES512` algorithms for signature.

Usable for validating. See ``Security/SecCertificate``.

## Topics

- ``JSONWebKeyError``

### Protocols

- ``JSONWebKey``
- ``JSONWebValidatingKey``
- ``JSONWebSigningKey``
- ``JSONWebSymmetricSigningKey``
- ``JSONWebEncryptingKey``
- ``JSONWebDecryptingKey``
- ``JSONWebSymmetricDecryptingKey``
- ``JSONWebSealingKey``

### Containers

- ``AnyJSONWebKey``
- ``JSONWebKeySet``

### Symmetric

- ``CryptoKit/SymmetricKey``
- ``JSONWebKeyHMAC``
- ``JSONWebKeyAESGCM``
- ``JSONWebKeyAESCBCHMAC``
- ``JSONWebKeyAESKW``
- ``CryptoKit/SymmetricKey/pbkdf2(pbkdf2Password:salt:hashFunction:iterations:)``

### RSA

- ``JSONWebRSAPublicKey``
- ``JSONWebRSAPrivateKey``
- ``Security/SecKey``
- ``Security/SecCertificate``
- ``Security/SecTrust``

### Elliptic Curve

- ``JSONWebECPublicKey``
- ``JSONWebECPrivateKey``

### Algorithms

- ``JSONWebAlgorithm``
- ``AnyJSONWebAlgorithm``
- ``JSONWebSignatureAlgorithm``
- ``JSONWebKeyEncryptionAlgorithm``
- ``JSONWebContentEncryptionAlgorithm``
- ``JSONWebCompressionAlgorithm``
