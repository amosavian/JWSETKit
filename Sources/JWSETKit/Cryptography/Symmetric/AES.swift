//
//  AES.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// JSON Web Key (JWK) container for AES-GCM keys for encryption/decryption.
@frozen
public struct JSONWebKeyAESGCM: MutableJSONWebKey, JSONWebSymmetricSealingKey, JSONWebSymmetricDecryptingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        switch algorithm {
        case .aesEncryptionGCM128, .aesGCM128KeyWrap:
            try self.init(SymmetricKey(size: .bits128))
        case .aesEncryptionGCM192, .aesGCM192KeyWrap:
            try self.init(SymmetricKey(size: .bits192))
        case .aesEncryptionGCM256, .aesGCM256KeyWrap:
            try self.init(SymmetricKey(size: .bits256))
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
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
        let nonce: AES.GCM.Nonce?
        if let iv {
            nonce = try .init(data: iv)
        } else {
            nonce = nil
        }
        if let authenticating {
            return try .init(AES.GCM.seal(data, using: .init(self), nonce: nonce, authenticating: authenticating))
        } else {
            return try .init(AES.GCM.seal(data, using: .init(self), nonce: nonce))
        }
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using _: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        if let authenticating {
            return try AES.GCM.open(.init(data), using: .init(self), authenticating: authenticating)
        } else {
            return try AES.GCM.open(.init(data), using: .init(self))
        }
    }
    
    public func encrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        let sealed = try AES.GCM.seal(data, using: .init(self))
        return sealed.combined ?? sealed.ciphertext
    }
    
    public func decrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try AES.GCM.open(.init(combined: data), using: .init(self))
    }
}

/// JSON Web Key (JWK) container for AES Key Wrap for encryption/decryption.
public struct JSONWebKeyAESKW: MutableJSONWebKey, JSONWebSymmetricDecryptingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        guard let size = AnyJSONWebAlgorithm(algorithm)?.keyLength else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        try self.init(SymmetricKeySize(bitCount: size))
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    /// Returns a new AES-KW with random key.
    ///
    /// - Parameter keySize: Size of random key in bits.
    public init(_ keySize: SymmetricKeySize) throws {
        try self.init(SymmetricKey(size: keySize))
    }
    
    /// Initializes a AES-GCM key for encryption.
    ///
    /// - Parameter key: A symmetric cryptographic key.
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        if [.bits128, .bits192, .bits256].contains(key.size) {
            self.algorithm = .aesKeyWrap(bitCount: key.bitCount)
        } else {
            throw CryptoKitError.incorrectParameterSize
        }
        self.keyValue = key
    }
    
    public func decrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try unwrap(data).data
    }
    
    public func encrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try wrap(.init(data: Data(data)))
    }
    
    /// Unwraps a key using the AES wrap algorithm.
    ///
    /// Wrap is an implementation of the AES key wrap algorithm as specified
    /// in IETF RFC 3394. The method throws an error is the key was
    /// incorrectly wrapped.
    ///
    /// - Parameters:
    ///   - data: The key to unwrap.
    ///
    /// - Returns: The unwrapped key.
    public func unwrap<D>(_ data: D) throws -> SymmetricKey where D: DataProtocol {
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return try AES.KeyWrap.unwrap(data, using: .init(self))
        } else {
#if canImport(CommonCrypto)
            return try SymmetricKey(self).ccUnwrapKey(data)
#else
            return try AES.KeyWrap.unwrap(data, using: .init(self))
#endif
        }
    }
    
    /// Wraps a key using the AES wrap algorithm.
    ///
    /// Wrap is an implementation of the AES key wrap algorithm as specified
    /// in IETF RFC 3394.
    ///
    /// - Parameters:
    ///   - key: The key to wrap.
    ///
    /// - Returns: The wrapped key.
    public func wrap(_ key: SymmetricKey) throws -> Data {
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return try AES.KeyWrap.wrap(key, using: .init(self))
        } else {
#if canImport(CommonCrypto)
            return try SymmetricKey(self).ccWrapKey(key)
#else
            return try AES.KeyWrap.wrap(key, using: .init(self))
#endif
        }
    }
}
