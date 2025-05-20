//
//  SymmetricKey.swift
//
//
//  Created by Amir Abbas Mousavian on 9/10/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

extension Crypto.SymmetricKey: Swift.Hashable, Swift.Codable {}

extension SymmetricKey: JSONWebKey {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .symmetric
        result.keyValue = self
        return result.storage
    }
    
    public var publicKey: SymmetricKey { self }
    
    public static func create(storage: JSONWebValueStorage) throws -> SymmetricKey {
        guard let key = (storage["k"] as Data?) else {
            throw CryptoKitError.incorrectKeySize
        }
        return SymmetricKey(data: key)
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        guard let data = AnyJSONWebKey(storage: storage).keyValue else {
            self.init(size: .bits128)
            return
        }
        self.init(data: data)
    }
    
    public func hash(into hasher: inout Hasher) {
        withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}

extension ContiguousBytes {
    @usableFromInline
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}

extension SymmetricKeySize {
    static func * (lhs: SymmetricKeySize, rhs: Int) -> SymmetricKeySize {
        .init(bitCount: lhs.bitCount * rhs)
    }
}

extension SymmetricKey: JSONWebSymmetricSigningKey {
    public init(algorithm: some JSONWebAlgorithm) throws {
        if let size = AnyJSONWebAlgorithm(algorithm.rawValue).keyLength {
            self.init(size: .init(bitCount: size))
        } else {
            self.init(size: .bits128)
        }
    }
    
    private func key(_ algorithm: JSONWebSignatureAlgorithm) throws -> (any JSONWebSymmetricSigningKey) {
        guard let keyClass = (algorithm.validatingKeyClass ?? (self.algorithm as? JSONWebSignatureAlgorithm)?.validatingKeyClass) as? any JSONWebSymmetricSigningKey.Type else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(self)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try key(algorithm).signature(data, using: algorithm)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try key(algorithm).verifySignature(signature, for: data, using: algorithm)
    }
}

extension SymmetricKey: JSONWebSymmetricDecryptingKey {
    private func key(_ algorithm: some JSONWebAlgorithm) throws -> (any JSONWebSymmetricDecryptingKey)? {
        if let keyClass = JSONWebKeyEncryptionAlgorithm(algorithm.rawValue).decryptingKeyClass as? any JSONWebSymmetricDecryptingKey.Type {
            return try keyClass.init(self)
        }
        return nil
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        if let key = try key(algorithm) {
            return try key.decrypt(data, using: algorithm)
        }
        
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(self).open(.init(data: data, nonceLength: 12, tagLength: 16), using: algorithm)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        if let key = try key(algorithm) {
            return try key.encrypt(data, using: algorithm)
        }
        
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(self).seal(data, using: algorithm).combined
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension SymmetricKey: JSONWebSymmetricSealingKey {
    public init(_ key: SymmetricKey) throws {
        self = key
    }
    
    private func key(_ algorithm: some JSONWebAlgorithm) throws -> any JSONWebSymmetricSealingKey {
        guard let keyClass = (algorithm as? JSONWebContentEncryptionAlgorithm)?.keyClass else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(self)
    }
    
    public func seal<D, IV, AAD, JWA>(_ data: D, iv: IV?, authenticating: AAD?, using algorithm: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        try key(algorithm).seal(data, iv: iv, authenticating: authenticating, using: algorithm)
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using algorithm: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        try key(algorithm).open(data, authenticating: authenticating, using: algorithm)
    }
}

#if !canImport(CryptoKit)
extension SymmetricKey: @unchecked Sendable {}
#endif
