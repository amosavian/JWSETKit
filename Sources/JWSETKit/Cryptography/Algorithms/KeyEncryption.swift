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
        _ header: inout JOSEHeader,
        _ keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        _ kek: (any JSONWebKey)?,
        _ contentEncryptionAlgorithm: JSONWebContentEncryptionAlgorithm,
        _ cek: Data
    ) throws -> Data
    
    public typealias DecryptionMutatorHandler = (
        _ header: JOSEHeader,
        _ kek: inout any JSONWebKey,
        _ cek: inout Data
    ) throws -> Void
    
    private static let keyRegistryClasses: PthreadReadWriteLockedValue < [Self: (public: any JSONWebEncryptingKey.Type, private: any JSONWebDecryptingKey.Type)]> = [
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
    
    private static let keyTypes: PthreadReadWriteLockedValue<[Self: JSONWebKeyType]> = [
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
    ]
    
    private static let keyLengths: PthreadReadWriteLockedValue<[Self: Int]> = [
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
    
    private static let hashFunctions: PthreadReadWriteLockedValue<[Self: any HashFunction.Type]> = [
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
    ]
    
    private static let encryptedKeyHandlers: PthreadReadWriteLockedValue<[Self: EncryptedKeyHandler]> = [
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
    ]
    
    private static let decryptionMutators: PthreadReadWriteLockedValue<[Self: DecryptionMutatorHandler]> = [
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
    ]
    
    /// Key type, either RSA, Elliptic curve, Symmetric, etc.
    public var keyType: JSONWebKeyType? {
        Self.keyTypes[self]
    }
    
    /// Returns private and public class appropriate for algorithm.
    public var keyClass: (public: any JSONWebEncryptingKey.Type, private: any JSONWebDecryptingKey.Type)? {
        Self.keyRegistryClasses[self]
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
    ///   - publicKeyClass: Public key class.
    ///   - privateKeyClass: Private key class. In case the key is symmetric, it equals to `publicKeyClass`.
    ///   - keyLengthInBits:Key length in bits, if applicable.
    ///   - hashFunction: Hash function of symmetric keys.
    ///   - encryptedKeyHandler: Encrypting content encryption key.
    ///   - decryptionMutating: Prepares key encryption key and content encryption before applying in decryption.
    public static func register<Public, Private>(
        _ algorithm: Self,
        type: JSONWebKeyType,
        publicKeyClass: Public.Type,
        privateKeyClass: Private.Type,
        keyLengthInBits: Int?,
        hashFunction: (any HashFunction.Type)? = nil,
        encryptedKeyHandler: EncryptedKeyHandler?,
        decryptionMutating: DecryptionMutatorHandler?
    ) where Public: JSONWebEncryptingKey, Private: JSONWebDecryptingKey {
        keyRegistryClasses[algorithm] = (publicKeyClass, privateKeyClass)
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
        guard let keyClass = keyClass?.private else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(algorithm: self)
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    static func standardEncryptdKey(
        _: inout JOSEHeader,
        _ keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _: JSONWebContentEncryptionAlgorithm,
        _ cekData: Data
    ) throws -> Data {
        guard let kek = keyEncryptionKey as? any JSONWebEncryptingKey else {
            throw JSONWebKeyError.keyNotFound
        }
        return try kek.encrypt(cekData, using: keyEncryptingAlgorithm)
    }
    
    fileprivate static func aesGCMKeyWrapEncryptedKey(
        _ header: inout JOSEHeader,
        _ keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _: JSONWebContentEncryptionAlgorithm,
        _ cekData: Data
    ) throws -> Data {
        guard let kek = keyEncryptionKey?.keyValue else {
            throw JSONWebKeyError.keyNotFound
        }
        let nonce: Data
        if let headerNonce = header.initialVector {
            nonce = headerNonce
        } else {
            nonce = AES.GCM.Nonce().data
            header.initialVector = nonce
        }
        let sealed = try kek.seal(cekData, iv: nonce, using: JSONWebContentEncryptionAlgorithm(keyEncryptingAlgorithm.rawValue.dropLast(2)))
        if let headerTag = header.authenticationTag {
            guard headerTag == sealed.tag else {
                throw CryptoKitError.authenticationFailure
            }
        } else {
            header.authenticationTag = sealed.tag
        }
        
        return sealed.ciphertext
    }
    
    fileprivate static func pbesEncryptedKey(
        _ header: inout JOSEHeader,
        _ keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _: JSONWebContentEncryptionAlgorithm,
        _ cekData: Data
    ) throws -> Data {
        guard let password = keyEncryptionKey?.keyValue?.data else {
            throw JSONWebKeyError.keyNotFound
        }
        let iterations: Int
        if let pbes2Count = header.pbes2Count {
            iterations = pbes2Count
        } else {
            // Default iterations count for PBES2 regarding OWASP 2023 recommendation.
            iterations = SymmetricKey.defaultPBES2IterationCount[(keyEncryptingAlgorithm.keyLength ?? 128) / 2] ?? 1000
            header.pbes2Count = iterations
        }
        let salt = Data(keyEncryptingAlgorithm.rawValue.utf8) + [0x00] + (header.pbes2Salt ?? .init())
        let key = try SymmetricKey.passwordBased2DerivedSymmetricKey(
            password: password, salt: salt, iterations: iterations,
            length: keyEncryptingAlgorithm.keyLength.map { $0 / 8 }, hashFunction: keyEncryptingAlgorithm.hashFunction.unsafelyUnwrapped
        )
        return try key.encrypt(cekData, using: keyEncryptingAlgorithm)
    }
    
    fileprivate static func ecdhEsEncryptedKey(
        _ header: inout JOSEHeader,
        _ keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        _ keyEncryptionKey: (any JSONWebKey)?,
        _: JSONWebContentEncryptionAlgorithm,
        _ cekData: Data
    ) throws -> Data {
        guard let kek = keyEncryptionKey else {
            throw JSONWebKeyError.keyNotFound
        }
        guard let hashFunction = keyEncryptingAlgorithm.hashFunction else {
            throw JSONWebKeyError.keyNotFound
        }
        
        let secret: SharedSecret
        if let headerEphemeralKey = header.ephemeralPublicKey {
            let ephemeralKey = JSONWebECPublicKey(storage: headerEphemeralKey.storage)
            let staticKey = JSONWebECPrivateKey(storage: kek.storage)
            secret = try staticKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        } else {
            let ephemeralKey = try JSONWebECPrivateKey(curve: kek.curve ?? .empty)
            let staticKey = JSONWebECPublicKey(storage: kek.storage)
            header.ephemeralPublicKey = .init(ephemeralKey.publicKey)
            secret = try ephemeralKey.sharedSecretFromKeyAgreement(with: staticKey)
        }
        let symmetricKey = try secret.concatDerivedSymmetricKey(
            algorithm: keyEncryptingAlgorithm,
            contentEncryptionAlgorithm: header.encryptionAlgorithm,
            apu: header.agreementPartyUInfo ?? .init(),
            apv: header.agreementPartyVInfo ?? .init(),
            hashFunction: hashFunction
        )
        if keyEncryptingAlgorithm == .ecdhEphemeralStatic {
            return symmetricKey.data
        } else {
            let key = try JSONWebKeyAESKW(symmetricKey)
            return try key.encrypt(cekData, using: keyEncryptingAlgorithm)
        }
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    fileprivate static func directDecryptionMutator(_: JOSEHeader, _ kek: inout any JSONWebKey, _ cek: inout Data) throws {
        guard let encryptedKeyData = kek.keyValue?.data else {
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
        guard let password = kek.keyValue?.data else {
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
        
        let privateKey = JSONWebECPrivateKey(storage: kek.storage)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: .init(storage: epk.storage))
        
        let symmetricKey = try secret.concatDerivedSymmetricKey(
            algorithm: algorithm,
            contentEncryptionAlgorithm: header.encryptionAlgorithm,
            apu: header.agreementPartyUInfo ?? .init(),
            apv: header.agreementPartyVInfo ?? .init(),
            hashFunction: hashFunction
        )
        if algorithm == .ecdhEphemeralStatic {
            kek = try JSONWebDirectKey()
            cek = symmetricKey.data
        } else {
            kek = symmetricKey
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
