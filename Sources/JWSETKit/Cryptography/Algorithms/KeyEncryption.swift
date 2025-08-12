//
//  KeyEncryption.swift
//
//
//  Created by Amir Abbas Mousavian on 10/13/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// JSON Web Key Encryption Algorithms
@frozen
public struct JSONWebKeyEncryptionAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    public typealias EncryptedKeyHandler = (
        _ recipientHeader: JOSEHeader,
        _ kek: (any JSONWebKey)?,
        _ cek: Data
    ) throws -> (headerFields: JOSEHeader?, cek: Data)
    
    public typealias DecryptionMutatorHandler = (
        _ header: JOSEHeader,
        _ kek: inout any JSONWebKey,
        _ cek: inout Data
    ) throws -> Void
    
    private static let keyRegistryClasses: AtomicValue < [Self: (public: any JSONWebEncryptingKey.Type, private: any JSONWebDecryptingKey.Type)]> = [
        .direct: (JSONWebDirectKey.self, JSONWebDirectKey.self),
        .aesKeyWrap128: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .aesKeyWrap192: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .aesKeyWrap256: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .aesGCM128KeyWrap: (JSONWebKeyAESGCM.self, JSONWebKeyAESGCM.self),
        .aesGCM192KeyWrap: (JSONWebKeyAESGCM.self, JSONWebKeyAESGCM.self),
        .aesGCM256KeyWrap: (JSONWebKeyAESGCM.self, JSONWebKeyAESGCM.self),
        .unsafeRSAEncryptionPKCS1: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEP: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEPSHA256: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEPSHA384: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEPSHA512: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .pbes2hmac256: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .pbes2hmac384: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .pbes2hmac512: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .ecdhEphemeralStatic: (JSONWebDirectKey.self, JSONWebDirectKey.self),
        .ecdhEphemeralStaticAESKeyWrap128: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .ecdhEphemeralStaticAESKeyWrap192: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .ecdhEphemeralStaticAESKeyWrap256: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
    ]
    
    private static let keyTypes: AtomicValue<[Self: JSONWebKeyType]> = [
        .direct: .symmetric,
        .aesKeyWrap128: .symmetric,
        .aesKeyWrap192: .symmetric,
        .aesKeyWrap256: .symmetric,
        .aesGCM128KeyWrap: .symmetric,
        .aesGCM192KeyWrap: .symmetric,
        .aesGCM256KeyWrap: .symmetric,
        .unsafeRSAEncryptionPKCS1: .rsa,
        .rsaEncryptionOAEP: .rsa,
        .rsaEncryptionOAEPSHA256: .rsa,
        .rsaEncryptionOAEPSHA384: .rsa,
        .rsaEncryptionOAEPSHA512: .rsa,
        .pbes2hmac256: .symmetric,
        .pbes2hmac384: .symmetric,
        .pbes2hmac512: .symmetric,
        .ecdhEphemeralStatic: .ellipticCurve,
        .ecdhEphemeralStaticAESKeyWrap128: .ellipticCurve,
        .ecdhEphemeralStaticAESKeyWrap192: .ellipticCurve,
        .ecdhEphemeralStaticAESKeyWrap256: .ellipticCurve,
        .internalHpkeP256SHA256AESGCM128: .ellipticCurve,
        .internalHpkeP384SHA384AESGCM256: .ellipticCurve,
        .internalHpkeP521SHA512AESGCM256: .ellipticCurve,
        .internalHpkeCurve25519SHA256AESGCM128: .octetKeyPair,
        .internalHpkeCurve25519SHA256ChachaPoly: .octetKeyPair,
    ]
    
    private static let keyLengths: AtomicValue<[Self: Int]> = [
        .aesKeyWrap128: SymmetricKeySize.bits128.bitCount,
        .aesKeyWrap192: SymmetricKeySize.bits192.bitCount,
        .aesKeyWrap256: SymmetricKeySize.bits256.bitCount,
        .aesGCM128KeyWrap: SymmetricKeySize.bits128.bitCount,
        .aesGCM192KeyWrap: SymmetricKeySize.bits192.bitCount,
        .aesGCM256KeyWrap: SymmetricKeySize.bits256.bitCount,
        .unsafeRSAEncryptionPKCS1: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount,
        .rsaEncryptionOAEP: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount,
        .rsaEncryptionOAEPSHA256: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount,
        .rsaEncryptionOAEPSHA384: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount,
        .rsaEncryptionOAEPSHA512: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount,
        .pbes2hmac256: SymmetricKeySize.bits128.bitCount,
        .pbes2hmac384: SymmetricKeySize.bits192.bitCount,
        .pbes2hmac512: SymmetricKeySize.bits256.bitCount,
        .ecdhEphemeralStaticAESKeyWrap128: SymmetricKeySize.bits128.bitCount,
        .ecdhEphemeralStaticAESKeyWrap192: SymmetricKeySize.bits192.bitCount,
        .ecdhEphemeralStaticAESKeyWrap256: SymmetricKeySize.bits256.bitCount,
    ]
    
    private static let hashFunctions: AtomicValue<[Self: any HashFunction.Type]> = [
        .aesKeyWrap128: SHA256.self,
        .aesKeyWrap192: SHA384.self,
        .aesKeyWrap256: SHA512.self,
        .aesGCM128KeyWrap: SHA256.self,
        .aesGCM192KeyWrap: SHA384.self,
        .aesGCM256KeyWrap: SHA512.self,
        .pbes2hmac256: SHA256.self,
        .pbes2hmac384: SHA384.self,
        .pbes2hmac512: SHA512.self,
        .ecdhEphemeralStatic: SHA256.self,
        .ecdhEphemeralStaticAESKeyWrap128: SHA256.self,
        .ecdhEphemeralStaticAESKeyWrap192: SHA256.self,
        .ecdhEphemeralStaticAESKeyWrap256: SHA256.self,
        .internalHpkeP256SHA256AESGCM128: SHA256.self,
        .internalHpkeP384SHA384AESGCM256: SHA384.self,
        .internalHpkeP521SHA512AESGCM256: SHA512.self,
        .internalHpkeCurve25519SHA256AESGCM128: SHA256.self,
        .internalHpkeCurve25519SHA256ChachaPoly: SHA256.self,
    ]
    
    private static let encryptedKeyHandlers: AtomicValue<[Self: EncryptedKeyHandler]> = [
        .aesGCM128KeyWrap: aesGCMKeyWrapEncryptedKey,
        .aesGCM192KeyWrap: aesGCMKeyWrapEncryptedKey,
        .aesGCM256KeyWrap: aesGCMKeyWrapEncryptedKey,
        .pbes2hmac256: pbesEncryptedKey,
        .pbes2hmac384: pbesEncryptedKey,
        .pbes2hmac512: pbesEncryptedKey,
        .ecdhEphemeralStatic: ecdhEsEncryptedKey,
        .ecdhEphemeralStaticAESKeyWrap128: ecdhEsEncryptedKey,
        .ecdhEphemeralStaticAESKeyWrap192: ecdhEsEncryptedKey,
        .ecdhEphemeralStaticAESKeyWrap256: ecdhEsEncryptedKey,
        .internalHpkeP256SHA256AESGCM128: hpkeEncryptedKey,
        .internalHpkeP384SHA384AESGCM256: hpkeEncryptedKey,
        .internalHpkeP521SHA512AESGCM256: hpkeEncryptedKey,
        .internalHpkeCurve25519SHA256AESGCM128: hpkeEncryptedKey,
        .internalHpkeCurve25519SHA256ChachaPoly: hpkeEncryptedKey,
    ]
    
    private static let decryptionMutators: AtomicValue<[Self: DecryptionMutatorHandler]> = [
        .direct: directDecryptionMutator,
        .aesGCM128KeyWrap: aesgcmDecryptionMutator,
        .aesGCM192KeyWrap: aesgcmDecryptionMutator,
        .aesGCM256KeyWrap: aesgcmDecryptionMutator,
        .pbes2hmac256: pbesDecryptionMutator,
        .pbes2hmac384: pbesDecryptionMutator,
        .pbes2hmac512: pbesDecryptionMutator,
        .ecdhEphemeralStatic: ecdhEsDecryptionMutator,
        .ecdhEphemeralStaticAESKeyWrap128: ecdhEsDecryptionMutator,
        .ecdhEphemeralStaticAESKeyWrap192: ecdhEsDecryptionMutator,
        .ecdhEphemeralStaticAESKeyWrap256: ecdhEsDecryptionMutator,
        .internalHpkeP256SHA256AESGCM128: hpkeDecryptionMutator,
        .internalHpkeP384SHA384AESGCM256: hpkeDecryptionMutator,
        .internalHpkeP521SHA512AESGCM256: hpkeDecryptionMutator,
        .internalHpkeCurve25519SHA256AESGCM128: hpkeDecryptionMutator,
        .internalHpkeCurve25519SHA256ChachaPoly: hpkeDecryptionMutator,
    ]
    
    /// Key type, either RSA, Elliptic curve, Symmetric, etc.
    public var keyType: JSONWebKeyType? {
        Self.keyTypes[self]
    }
    
    /// Returns private class appropriate for algorithm.
    public var encryptingKeyClass: (any JSONWebEncryptingKey.Type)? {
        Self.keyRegistryClasses[self]?.public
    }
    
    /// Returns public class appropriate for algorithm.
    public var decryptingKeyClass: (any JSONWebDecryptingKey.Type)? {
        Self.keyRegistryClasses[self]?.private
    }
    
    // Length of key in bits, if applicable.
    public var keyLength: Int? {
        Self.keyLengths[self]
    }
    
    /// Hash function for symmetric algorithms.
    public var hashFunction: (any HashFunction.Type)? {
        Self.hashFunctions[self]
    }
    
    /// Returns handler for encrypting content encryption key.
    public var encryptedKeyHandler: EncryptedKeyHandler? {
        Self.encryptedKeyHandlers[self]
    }
    
    /// Prepares key encryption key and content encryption before applying in decryption.
    public var decryptionMutator: DecryptionMutatorHandler? {
        Self.decryptionMutators[self]
    }
    
    /// Currently registered algorithms.
    public static var registeredAlgorithms: [Self] {
        .init(keyRegistryClasses.keys)
    }
    
    /// Registers a new algorithm for key encryption.
    ///
    /// - Parameters:
    ///   - algorithm: New algorithm name.
    ///   - type: Type of key. Can be symmetric, RSA or Elliptic curve.
    ///   - privateKeyClass: Private key class. In case the key is symmetric, it equals to `publicKeyClass`.
    ///   - keyLengthInBits:Key length in bits, if applicable.
    ///   - hashFunction: Hash function of symmetric keys.
    ///   - encryptedKeyHandler: Encrypting content encryption key.
    ///   - decryptionMutating: Prepares key encryption key and content encryption before applying in decryption.
    public static func register<Private>(
        _ algorithm: Self,
        type: JSONWebKeyType,
        decryptingKeyClass: Private.Type,
        keyLengthInBits: Int?,
        hashFunction: (any HashFunction.Type)? = nil,
        encryptedKeyHandler: EncryptedKeyHandler?,
        decryptionMutating: DecryptionMutatorHandler?
    ) where Private: JSONWebDecryptingKey {
        keyRegistryClasses[algorithm] = (decryptingKeyClass.PublicKey, decryptingKeyClass)
        keyTypes[algorithm] = type
        keyLengths[algorithm] = keyLengthInBits
        hashFunctions[algorithm] = hashFunction
        encryptedKeyHandlers[algorithm] = encryptedKeyHandler
        decryptionMutators[algorithm] = decryptionMutating
    }
    
    /// Generates new random key with minimum key length.
    ///
    /// - Returns: New random key.
    public func generateRandomKey() throws -> any JSONWebDecryptingKey {
        guard let keyClass = decryptingKeyClass else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(algorithm: self)
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    static func standardEncryptdKey(
        _ recipientHeader: JOSEHeader,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _ cekData: Data
    ) throws -> (headerFields: JOSEHeader?, cek: Data) {
        guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let kek = keyEncryptionKey as? any JSONWebEncryptingKey else {
            throw JSONWebKeyError.keyNotFound
        }
        return try (nil, kek.encrypt(cekData, using: keyEncryptingAlgorithm))
    }
    
    fileprivate static func aesGCMKeyWrapEncryptedKey(
        _ recipientHeader: JOSEHeader,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _ cekData: Data
    ) throws -> (headerFields: JOSEHeader?, cek: Data) {
        guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let kek = keyEncryptionKey.map(AnyJSONWebKey.init)?.keyValue else {
            throw JSONWebKeyError.keyNotFound
        }
        var header = JOSEHeader()
        let nonce: Data
        if let headerNonce = recipientHeader.initialVector {
            nonce = headerNonce
        } else {
            nonce = AES.GCM.Nonce().data
            header.initialVector = nonce
        }
        let sealed = try kek.seal(cekData, iv: nonce, using: JSONWebContentEncryptionAlgorithm(keyEncryptingAlgorithm.rawValue.dropLast(2)))
        if let headerTag = recipientHeader.authenticationTag {
            guard headerTag == sealed.tag else {
                throw CryptoKitError.authenticationFailure
            }
        } else {
            header.authenticationTag = sealed.tag
        }
        
        return (header, sealed.ciphertext)
    }
    
    fileprivate static func pbesEncryptedKey(
        _ recipientHeader: JOSEHeader,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _ cekData: Data
    ) throws -> (headerFields: JOSEHeader?, cek: Data) {
        guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let kek = keyEncryptionKey, let password = AnyJSONWebKey(kek).keyValue?.data else {
            throw JSONWebKeyError.keyNotFound
        }
        var header = JOSEHeader()
        let iterations: Int
        if let pbes2Count = recipientHeader.pbes2Count {
            iterations = pbes2Count
        } else {
            // Default iterations count for PBES2 regarding OWASP 2023 recommendation.
            iterations = SymmetricKey.defaultPBES2IterationCount[(keyEncryptingAlgorithm.keyLength ?? 128) / 2, default: 600_000]
            header.pbes2Count = iterations
        }
        let pbes2Salt: Data
        if let salt = recipientHeader.pbes2Salt {
            pbes2Salt = salt
        } else {
            pbes2Salt = Data.random(length: 16)
            header.pbes2Salt = pbes2Salt
        }
        let kdfSalt = Data(keyEncryptingAlgorithm.rawValue.utf8) + [0x00] + pbes2Salt
        let key = try SymmetricKey.passwordBased2DerivedSymmetricKey(
            password: password, salt: kdfSalt, iterations: iterations,
            length: keyEncryptingAlgorithm.keyLength.map { $0 / 8 }, hashFunction: keyEncryptingAlgorithm.hashFunction.unsafelyUnwrapped
        )
        return try (header, key.encrypt(cekData, using: keyEncryptingAlgorithm))
    }
    
    fileprivate static func ecdhEsEncryptedKey(
        _ recipientHeader: JOSEHeader,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _ cekData: Data
    ) throws -> (headerFields: JOSEHeader?, cek: Data) {
        guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm), let hashFunction = keyEncryptingAlgorithm.hashFunction else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let kek = keyEncryptionKey else {
            throw JSONWebKeyError.keyNotFound
        }
        
        var header = JOSEHeader()
        let secret: SharedSecret
        if let headerEphemeralKey = recipientHeader.ephemeralPublicKey {
            let ephemeralKey = try JSONWebECPublicKey(headerEphemeralKey)
            let staticKey = try JSONWebECPrivateKey(from: kek)
            secret = try staticKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        } else if let curve = kek.curve {
            let ephemeralKey = try JSONWebECPrivateKey(curve: curve)
            let staticKey = try JSONWebECPublicKey(from: kek)
            header.ephemeralPublicKey = .init(ephemeralKey.publicKey)
            secret = try ephemeralKey.sharedSecretFromKeyAgreement(with: staticKey)
        } else {
            throw JSONWebKeyError.unknownKeyType
        }
        let symmetricKey = try secret.concatDerivedSymmetricKey(
            using: hashFunction,
            algorithm: keyEncryptingAlgorithm,
            contentEncryptionAlgorithm: recipientHeader.encryptionAlgorithm,
            apu: recipientHeader.agreementPartyUInfo ?? .init(),
            apv: recipientHeader.agreementPartyVInfo ?? .init()
        )
        if keyEncryptingAlgorithm == .ecdhEphemeralStatic {
            return (header, symmetricKey.data)
        } else {
            let key = try JSONWebKeyAESKW(symmetricKey)
            return try (header, key.encrypt(cekData, using: keyEncryptingAlgorithm))
        }
    }
    
    static func hpkeEncryptedKey(
        _ recipientHeader: JOSEHeader,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _ cekData: Data
    ) throws -> (headerFields: JOSEHeader?, cek: Data) {
        if #available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *) {
            guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm) else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            guard let recipientKey = keyEncryptionKey as? (any HPKEDiffieHellmanPublicKey) else {
                throw JSONWebKeyError.unknownKeyType
            }
            var hpke = try HPKE.Sender(
                recipientKey: recipientKey,
                ciphersuite: .init(algorithm: keyEncryptingAlgorithm),
                info: .init()
            )
            if recipientHeader.encryptionAlgorithm == .integrated {
                return (nil, hpke.encapsulatedKey)
            } else {
                var header = JOSEHeader()
                header.encapsulatedKey = hpke.encapsulatedKey
                return try (header, hpke.seal(cekData))
            }
        } else {
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    fileprivate static func directDecryptionMutator(_: JOSEHeader, _ kek: inout any JSONWebKey, _ cek: inout Data) throws {
        guard let encryptedKeyData = AnyJSONWebKey(kek).keyValue?.data else {
            throw JSONWebKeyError.unknownKeyType
        }
        kek = try JSONWebDirectKey()
        cek = encryptedKeyData
    }
    
    fileprivate static func pbesDecryptionMutator(_ header: JOSEHeader, _ kek: inout any JSONWebKey, _: inout Data) throws {
        guard let algorithm = JSONWebKeyEncryptionAlgorithm(header.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.keyNotFound
        }
        guard let password = AnyJSONWebKey(kek).keyValue?.data else {
            throw JSONWebKeyError.keyNotFound
        }
        guard let iterations = header.pbes2Count else {
            throw JSONWebKeyError.keyNotFound
        }
        let salt = Data(algorithm.rawValue.utf8) + [0x00] + (header.pbes2Salt ?? .init())
        kek = try SymmetricKey.passwordBased2DerivedSymmetricKey(
            password: password, salt: salt, iterations: iterations, length: algorithm.keyLength.map { $0 / 8 },
            hashFunction: hashFunction
        )
    }
    
    fileprivate static func aesgcmDecryptionMutator(_ header: JOSEHeader, _: inout any JSONWebKey, _ cek: inout Data) throws {
        guard let iv = header.initialVector, iv.count == 12,
              let tag = header.authenticationTag, tag.count == 16
        else {
            throw CryptoKitError.authenticationFailure
        }
        cek = iv + cek + tag
    }
    
    fileprivate static func ecdhEsDecryptionMutator(_ header: JOSEHeader, _ kek: inout any JSONWebKey, _ cek: inout Data) throws {
        guard let algorithm = JSONWebKeyEncryptionAlgorithm(header.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let epk = header.ephemeralPublicKey, let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.keyNotFound
        }
        
        let privateKey = try JSONWebECPrivateKey(from: kek)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: .init(epk))
        
        let symmetricKey = try secret.concatDerivedSymmetricKey(
            using: hashFunction,
            algorithm: algorithm,
            contentEncryptionAlgorithm: header.encryptionAlgorithm,
            apu: header.agreementPartyUInfo ?? .init(),
            apv: header.agreementPartyVInfo ?? .init()
        )
        if algorithm == .ecdhEphemeralStatic {
            kek = try JSONWebDirectKey()
            cek = symmetricKey.data
        } else {
            kek = symmetricKey
        }
    }
    
    fileprivate static func hpkeDecryptionMutator(_ header: JOSEHeader, _ kek: inout any JSONWebKey, _ cek: inout Data) throws {
        if #available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *) {
            guard let algorithm = JSONWebKeyEncryptionAlgorithm(header.algorithm) else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            guard header.presharedKeyId == nil else {
                // Preshared key mode is not supported in this library
                throw HPKE.Errors.unexpectedPSK
            }
            let privateKey: any HPKEDiffieHellmanPrivateKey & JSONWebKey
            if let key = kek as? (any HPKEDiffieHellmanPrivateKey & JSONWebKey) {
                privateKey = key
            } else if let key = AnyJSONWebKey(kek).specialized() as? (any HPKEDiffieHellmanPrivateKey & JSONWebKey) {
                privateKey = key
                kek = privateKey
            } else {
                throw JSONWebKeyError.keyNotFound
            }
            let encapsulatedKey: Data
            if let headerEncapsulatedKey = header.encapsulatedKey, header.encryptionAlgorithm != .integrated {
                encapsulatedKey = headerEncapsulatedKey
            } else if header.encryptionAlgorithm == .integrated {
                encapsulatedKey = cek
            } else {
                throw JSONWebKeyError.keyNotFound
            }
            let hpke = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: .init(algorithm: algorithm),
                info: .init(),
                encapsulatedKey: encapsulatedKey
            )
            kek = JSONWebHPKERecipient(recipient: hpke)
        } else {
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

// Key Management
extension JSONWebAlgorithm where Self == JSONWebKeyEncryptionAlgorithm {
    /// **Key Management**: RSAES OAEP using default parameters.
    public static var rsaEncryptionOAEP: Self { "RSA-OAEP" }
    
    /// **Key Management**: RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    public static var rsaEncryptionOAEPSHA256: Self { "RSA-OAEP-256" }
    
    /// **Key Management**: RSA-OAEP using SHA-384 and MGF1 with SHA-384.
    public static var rsaEncryptionOAEPSHA384: Self { "RSA-OAEP-384" }
    
    /// **Key Management**: RSA-OAEP using SHA-512 and MGF1 with SHA-512.
    public static var rsaEncryptionOAEPSHA512: Self { "RSA-OAEP-512" }
    
    /// **Key Management**: RSAES-PKCS1-v1.5
    @available(*, deprecated, message: "This algorithm is intended to be deprecated regarding https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/")
    public static var rsaEncryptionPKCS1: Self { "RSA1_5" }
    
    static var unsafeRSAEncryptionPKCS1: Self { "RSA1_5" }
    
    /// **Key Management**: AES Key-Wrap using 128-bit key.
    public static var aesKeyWrap128: Self { "A128KW" }
    
    /// **Key Management**: AES Key-Wrap using 192-bit key.
    public static var aesKeyWrap192: Self { "A192KW" }
    
    /// **Key Management**: AES Key-Wrap using 256-bit key.
    public static var aesKeyWrap256: Self { "A256KW" }
    
    static func aesKeyWrap(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)KW")
    }
    
    /// **Key Management**: Key wrapping with AES GCM using 128-bit key
    public static var aesGCM128KeyWrap: Self { "A128GCMKW" }
    
    /// **Key Management**: Key wrapping with AES GCM using 192-bit key
    public static var aesGCM192KeyWrap: Self { "A192GCMKW" }
    
    /// **Key Management**: Key wrapping with AES GCM using 256-bit key
    public static var aesGCM256KeyWrap: Self { "A256GCMKW" }
    
    static func aesGCMKeyWrap(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)GCMKW")
    }
    
    /// **Key Management**: PBES2 with HMAC SHA-256 and "A128KW" wrapping.
    public static var pbes2hmac256: Self { "PBES2-HS256+A128KW" }
    
    /// **Key Management**: PBES2 with HMAC SHA-384 and "A192KW" wrapping.
    public static var pbes2hmac384: Self { "PBES2-HS384+A192KW" }
    
    /// **Key Management**: PBES2 with HMAC SHA-512 and "A256KW" wrapping.
    public static var pbes2hmac512: Self { "PBES2-HS512+A256KW" }
    
    static func pbes2hmac(keyBitCount: Int) -> Self {
        .init(rawValue: "PBES2-HS\(keyBitCount * 2)+A\(keyBitCount)KW")
    }
    
    // **Key Management**:ECDH-ES using Concat KDF and CEK encrypted directly.
    public static var ecdhEphemeralStatic: Self { "ECDH-ES" }
    
    // **Key Management**:ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
    public static var ecdhEphemeralStaticAESKeyWrap128: Self { "ECDH-ES+A128KW" }
    
    /// **Key Management**: ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
    public static var ecdhEphemeralStaticAESKeyWrap192: Self { "ECDH-ES+A192KW" }
    
    /// **Key Management**: ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
    public static var ecdhEphemeralStaticAESKeyWrap256: Self { "ECDH-ES+A256KW" }
    
    /// **Key Management**: No encryption for content key.
    public static var direct: Self { "dir" }
}
