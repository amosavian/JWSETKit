//
//  AES.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// JSON Web Key (JWK) container for AES-GCM keys for encryption/decryption.
public struct JSONWebKeyAESGCM: MutableJSONWebKey, JSONWebSealingKey, JSONWebDecryptingKey, Sendable {
    public typealias PublicKey = Self
    
    public var publicKey: JSONWebKeyAESGCM { self }
    
    public var storage: JSONWebValueStorage
    
    /// Symmetric key using for encryption.
    public var symmetricKey: SymmetricKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            guard let keyValue = self.keyValue else {
                throw CryptoKitError.incorrectKeySize
            }
            return SymmetricKey(data: keyValue)
        }
    }
    
    public init() throws {
        self.init(size: .bits128)
    }

    public static func create(storage: JSONWebValueStorage) throws -> JSONWebKeyAESGCM {
        .init(storage: storage)
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// Returns a new AES-GCM with random key.
    ///
    /// - Parameter keySize: Size of random key in bits.
    public init(size: SymmetricKeySize) {
        self.storage = .init()
        self.algorithm = .aesEncryptionGCM(bitCount: size.bitCount)
        self.keyValue = SymmetricKey(size: size)
    }
    
    /// Initializes a AES-GCM key for encryption.
    ///
    /// - Parameter key: A symmetric cryptographic key.
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.algorithm = .aesEncryptionGCM(bitCount: key.bitCount)
        self.keyValue = key
    }
    
    public func seal<D, IV, AAD, JWA>(_ data: D, iv: IV?, authenticating: AAD?, using _: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        if let authenticating {
            return try .init(AES.GCM.seal(data, using: symmetricKey, nonce: iv.map(AES.GCM.Nonce.init(data:)), authenticating: authenticating))
        } else {
            return try .init(AES.GCM.seal(data, using: symmetricKey, nonce: iv.map(AES.GCM.Nonce.init(data:))))
        }
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using _: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        if let authenticating {
            return try AES.GCM.open(.init(data), using: symmetricKey, authenticating: authenticating)
        } else {
            return try AES.GCM.open(.init(data), using: symmetricKey)
        }
    }
    
    public func encrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try AES.GCM.open(.init(combined: data), using: symmetricKey)
    }
    
    public func decrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        let sealed = try AES.GCM.seal(data, using: symmetricKey)
        return sealed.combined ?? sealed.ciphertext
    }
}

/// JSON Web Key (JWK) container for AES Key Wrap for encryption/decryption.
public struct JSONWebKeyAESKW: MutableJSONWebKey, JSONWebSymmetricDecryptingKey, Sendable {
    public typealias PublicKey = Self
    
    public var publicKey: JSONWebKeyAESKW { self }
    
    public var storage: JSONWebValueStorage
    
    /// Symmetric key using for encryption.
    public var symmetricKey: SymmetricKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            guard let keyValue = self.keyValue else {
                throw CryptoKitError.incorrectKeySize
            }
            return SymmetricKey(data: keyValue)
        }
    }
    
    public init() throws {
        self.init(.bits128)
    }

    public static func create(storage: JSONWebValueStorage) throws -> JSONWebKeyAESKW {
        .init(storage: storage)
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// Returns a new AES-KW with random key.
    ///
    /// - Parameter keySize: Size of random key in bits.
    public init(_ keySize: SymmetricKeySize) {
        self.storage = .init()
        self.algorithm = .aesKeyWrap(bitCount: keySize.bitCount)
        self.keyValue = SymmetricKey(size: keySize)
    }
    
    /// Initializes a AES-GCM key for encryption.
    ///
    /// - Parameter key: A symmetric cryptographic key.
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.algorithm = .aesKeyWrap(bitCount: key.bitCount)
        self.keyValue = key
    }
    
    public func decrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try unwrap(data).data
    }
    
    public func encrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try wrap(.init(data: Data(data)))
    }
    
    public func unwrap<D>(_ data: D) throws -> SymmetricKey where D: DataProtocol {
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return try AES.KeyWrap.unwrap(data, using: symmetricKey)
        } else {
#if canImport(CommonCrypto)
            let wrappedKey = Data(data)
            var rawKey = Data(repeating: 0, count: CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count))
            let (result, unwrappedKeyCount) = try symmetricKey.data.withUnsafeBytes { kek in
                wrappedKey.withUnsafeBytes { wrappedKey in
                    rawKey.withUnsafeMutableBytes { rawKey in
                        var unwrappedKeyCount = 0
                        let result = CCSymmetricKeyUnwrap(
                            CCWrappingAlgorithm(kCCWRAPAES),
                            CCrfc3394_iv,
                            CCrfc3394_ivLen,
                            kek.baseAddress,
                            kek.count,
                            wrappedKey.baseAddress!,
                            wrappedKey.count,
                            rawKey.baseAddress,
                            &unwrappedKeyCount
                        )
                        return (result, unwrappedKeyCount)
                    }
                }
            }
            switch Int(result) {
            case kCCSuccess:
                return .init(data: rawKey.prefix(unwrappedKeyCount))
            case kCCParamError:
                throw CryptoKitError.incorrectParameterSize
            case kCCBufferTooSmall:
                throw CryptoKitError.incorrectKeySize
            default:
                throw CryptoKitError.underlyingCoreCryptoError(error: result)
            }
#else
            fatalError()
#endif
        }
    }
    
    public func wrap(_ key: SymmetricKey) throws -> Data {
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return try AES.KeyWrap.wrap(key, using: symmetricKey)
        } else {
#if canImport(CommonCrypto)
            let rawKey = key.data
            var wrappedKey = Data(repeating: 0, count: CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKey.count))
            let (result, wrappedKeyCount) = try symmetricKey.data.withUnsafeBytes { kek in
                rawKey.withUnsafeBytes { rawKey in
                    wrappedKey.withUnsafeMutableBytes { wrappedKey in
                        var wrappedKeyCount = 0
                        let result = CCSymmetricKeyWrap(
                            CCWrappingAlgorithm(kCCWRAPAES),
                            CCrfc3394_iv,
                            CCrfc3394_ivLen,
                            kek.baseAddress,
                            kek.count,
                            rawKey.baseAddress,
                            rawKey.count,
                            wrappedKey.baseAddress,
                            &wrappedKeyCount
                        )
                        return (result, wrappedKeyCount)
                    }
                }
            }
            switch Int(result) {
            case kCCSuccess:
                return wrappedKey.prefix(wrappedKeyCount)
            case kCCParamError:
                throw CryptoKitError.incorrectParameterSize
            case kCCBufferTooSmall:
                throw CryptoKitError.incorrectKeySize
            default:
                throw CryptoKitError.underlyingCoreCryptoError(error: result)
            }
#else
            fatalError()
#endif
        }
    }
}
