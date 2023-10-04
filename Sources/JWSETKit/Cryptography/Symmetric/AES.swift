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
public struct JSONWebKeyAESGCM: MutableJSONWebKey, JSONWebDecryptingKey, Sendable {
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
    
    public func decrypt<D>(_ data: D, using _: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        switch data {
        case let data as SealedData:
            return try AES.GCM.open(.init(data), using: symmetricKey)
        default:
            return try AES.GCM.open(.init(combined: data), using: symmetricKey)
        }
    }
    
    public func encrypt<D>(_ data: D, using _: JSONWebAlgorithm) throws -> SealedData where D: DataProtocol {
        try .init(AES.GCM.seal(data, using: symmetricKey))
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
    
    public func decrypt<D>(_ data: D, using _: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        try unwrap(data).withUnsafeBytes { Data($0) }
    }
    
    public func encrypt<D>(_ data: D, using _: JSONWebAlgorithm) throws -> SealedData where D: DataProtocol {
        try wrap(.init(data: Data(data)))
    }
    
    public func unwrap<D>(_ data: D) throws -> SymmetricKey where D: DataProtocol {
        try AES.KeyWrap.unwrap(data, using: symmetricKey)
    }
    
    public func wrap(_ key: SymmetricKey) throws -> SealedData {
        try .init(ciphertext: AES.KeyWrap.wrap(key, using: symmetricKey))
    }
}
