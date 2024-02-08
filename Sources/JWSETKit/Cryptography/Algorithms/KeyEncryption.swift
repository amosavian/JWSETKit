//
//  KeyEncryption.swift
//
//
//  Created by Amir Abbas Mousavian on 10/13/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// JSON Web Key Encryption Algorithms
public struct JSONWebKeyEncryptionAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    public typealias DecryptionMutatorHandler = (_ header: JOSEHeader, _ kek: inout any JSONWebDecryptingKey, _ cek: inout Data) throws -> Void
    
    @ReadWriteLocked
    private static var keyRegistryClasses: [Self: (public: any JSONWebEncryptingKey.Type, private: any JSONWebDecryptingKey.Type)] = [
        .direct: (JSONWebDirectKey.self, JSONWebDirectKey.self),
        .aesKeyWrap128: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .aesKeyWrap192: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .aesKeyWrap256: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .aesGCM128KeyWrap: (JSONWebKeyAESGCM.self, JSONWebKeyAESGCM.self),
        .aesGCM192KeyWrap: (JSONWebKeyAESGCM.self, JSONWebKeyAESGCM.self),
        .aesGCM256KeyWrap: (JSONWebKeyAESGCM.self, JSONWebKeyAESGCM.self),
        .rsaEncryptionPKCS1: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEP: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEPSHA256: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEPSHA384: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaEncryptionOAEPSHA512: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .pbes2hmac256: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .pbes2hmac384: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
        .pbes2hmac512: (JSONWebKeyAESKW.self, JSONWebKeyAESKW.self),
    ]
    
    @ReadWriteLocked
    private static var keyTypes: [Self: JSONWebKeyType] = [
        .direct: .symmetric,
        .aesKeyWrap128: .symmetric,
        .aesKeyWrap192: .symmetric,
        .aesKeyWrap256: .symmetric,
        .aesGCM128KeyWrap: .symmetric,
        .aesGCM192KeyWrap: .symmetric,
        .aesGCM256KeyWrap: .symmetric,
        .rsaEncryptionPKCS1: .rsa,
        .rsaEncryptionOAEP: .rsa,
        .rsaEncryptionOAEPSHA256: .rsa,
        .rsaEncryptionOAEPSHA384: .rsa,
        .rsaEncryptionOAEPSHA512: .rsa,
        .pbes2hmac256: .symmetric,
        .pbes2hmac384: .symmetric,
        .pbes2hmac512: .symmetric,
    ]
    
    @ReadWriteLocked
    private static var keyLengths: [Self: Int] = [
        .aesKeyWrap128: SymmetricKeySize.bits128.bitCount,
        .aesKeyWrap192: SymmetricKeySize.bits192.bitCount,
        .aesKeyWrap256: SymmetricKeySize.bits256.bitCount,
        .aesGCM128KeyWrap: SymmetricKeySize.bits128.bitCount,
        .aesGCM192KeyWrap: SymmetricKeySize.bits192.bitCount,
        .aesGCM256KeyWrap: SymmetricKeySize.bits256.bitCount,
        .rsaEncryptionPKCS1: JSONWebRSAPrivateKey.KeySize.defaultKeyLength,
        .rsaEncryptionOAEP: JSONWebRSAPrivateKey.KeySize.defaultKeyLength,
        .rsaEncryptionOAEPSHA256: JSONWebRSAPrivateKey.KeySize.defaultKeyLength,
        .rsaEncryptionOAEPSHA384: JSONWebRSAPrivateKey.KeySize.defaultKeyLength,
        .rsaEncryptionOAEPSHA512: JSONWebRSAPrivateKey.KeySize.defaultKeyLength,
        .pbes2hmac256: 256,
        .pbes2hmac384: 384,
        .pbes2hmac512: 512,
    ]
    
    @ReadWriteLocked
    private static var hashFunctions: [Self: any HashFunction.Type] = [
        .aesKeyWrap128: SHA256.self,
        .aesKeyWrap192: SHA384.self,
        .aesKeyWrap256: SHA512.self,
        .aesGCM128KeyWrap: SHA256.self,
        .aesGCM192KeyWrap: SHA384.self,
        .aesGCM256KeyWrap: SHA512.self,
        .pbes2hmac256: SHA256.self,
        .pbes2hmac384: SHA384.self,
        .pbes2hmac512: SHA512.self,
    ]
    
    @ReadWriteLocked
    private static var decryptionMutators: [Self: DecryptionMutatorHandler] = [
        .direct: directDecryptionMutator,
        .aesGCM128KeyWrap: aesgcmDecryptionMutator,
        .aesGCM192KeyWrap: aesgcmDecryptionMutator,
        .aesGCM256KeyWrap: aesgcmDecryptionMutator,
        .pbes2hmac256: pbesDecryptionMutator(hashFunction: SHA256.self),
        .pbes2hmac384: pbesDecryptionMutator(hashFunction: SHA384.self),
        .pbes2hmac512: pbesDecryptionMutator(hashFunction: SHA512.self),
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
    ///   - decryptionMutating: Prepares key encryption key and content encryption before applying in decryption.
    public static func register<Public, Private>(
        _ algorithm: Self,
        type: JSONWebKeyType,
        publicKeyClass: Public.Type,
        privateKeyClass: Private.Type,
        keyLengthInBits: Int?,
        hashFunction: (any HashFunction.Type)? = nil,
        decryptionMutating: DecryptionMutatorHandler?
    ) where Public: JSONWebEncryptingKey, Private: JSONWebDecryptingKey {
        keyRegistryClasses[algorithm] = (publicKeyClass, privateKeyClass)
        keyTypes[algorithm] = type
        keyLengths[algorithm] = keyLengthInBits
        hashFunctions[algorithm] = hashFunction
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
    fileprivate static func directDecryptionMutator(_: JOSEHeader, _ kek: inout any JSONWebDecryptingKey, _ cek: inout Data) throws {
        guard let encryptedKeyData = kek.keyValue?.data else {
            throw JSONWebKeyError.unknownKeyType
        }
        kek = try JSONWebDirectKey()
        cek = encryptedKeyData
    }
    
    fileprivate static func pbesDecryptionMutator<H: HashFunction>(hashFunction: H.Type) -> DecryptionMutatorHandler {
        { header, kek, _ in
            guard let password = kek.keyValue?.data else {
                throw JSONWebKeyError.keyNotFound
            }
            guard let iterations = header.pbes2Count else {
                throw JSONWebKeyError.keyNotFound
            }
            let algorithm = header.algorithm
            let salt = Data(algorithm.rawValue.utf8) + [0x00] + (header.pbes2Salt ?? .init())
            kek = try SymmetricKey.pbkdf2(
                password: password, salt: salt,
                hashFunction: hashFunction,
                iterations: iterations
            )
        }
    }
    
    fileprivate static func aesgcmDecryptionMutator(_ header: JOSEHeader, _: inout any JSONWebDecryptingKey, _ cek: inout Data) throws {
        guard let iv = header.initialVector, iv.count == 12,
              let tag = header.authenticationTag, tag.count == 16
        else {
            throw CryptoKitError.authenticationFailure
        }
        cek = iv + cek + tag
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
    public static var rsaEncryptionPKCS1: Self { "RSA1_5" }
    
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
    
    static func pbes2hmac(bitCount: Int) -> Self {
        .init(rawValue: "PBES2-HS\(bitCount)+A\(bitCount / 2)KW")
    }
    
    /// **Key Management**: No encryption for content key.
    public static var direct: Self { "direct" }
}
