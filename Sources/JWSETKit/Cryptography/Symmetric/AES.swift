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

/// JSON Web Key (JWK) container for AES-GCM keys for encryption/decryption.
public struct JSONWebKeyAESGCM: MutableJSONWebKey, JSONWebSealingKey, Sendable {
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
    public init(_ keySize: SymmetricKeySize) {
        self.storage = .init()
        self.algorithm = .aesEncryptionGCM(bitCount: keySize.bitCount)
        self.keyValue = SymmetricKey(size: keySize)
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
}

/// JSON Web Key (JWK) container for AES Key Wrap for encryption/decryption.
@available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *)
public struct JSONWebKeyAESKW: MutableJSONWebKey, JSONWebDecryptingKey, Sendable {
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
        try unwrap(data).withUnsafeBytes { Data($0) }
    }
    
    public func encrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try wrap(.init(data: Data(data)))
    }
    
    public func unwrap<D>(_ data: D) throws -> SymmetricKey where D: DataProtocol {
        try AES.KeyWrap.unwrap(data, using: symmetricKey)
    }
    
    public func wrap(_ key: SymmetricKey) throws -> Data {
        try AES.KeyWrap.wrap(key, using: symmetricKey)
    }
}
