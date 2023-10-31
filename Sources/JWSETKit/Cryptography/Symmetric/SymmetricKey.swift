//
//  SymmetricKey.swift
//
//
//  Created by Amir Abbas Mousavian on 9/10/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

extension SymmetricKey: JSONWebKey {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .symmetric
        result.keyValue = self
        return result.storage
    }
    
    public var publicKey: SymmetricKey { self }
    
    public static func create(storage: JSONWebValueStorage) throws -> SymmetricKey {
        guard let key = (storage["k", true] as Data?) else {
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
    
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}

extension SymmetricKey: JSONWebSigningKey {
    public init(algorithm: any JSONWebAlgorithm) throws {
        switch algorithm {
        case .hmacSHA256:
            self.init(size: .bits128)
        case .hmacSHA384:
            self.init(size: .bits192)
        case .hmacSHA512:
            self.init(size: .bits256)
        case .aesEncryptionCBC128SHA256:
            self.init(size: .bits256)
        case .aesEncryptionCBC192SHA384:
            self.init(size: .init(bitCount: 384))
        case .aesEncryptionCBC256SHA512:
            self.init(size: .init(bitCount: 512))
        default:
            if let size = JSONWebContentEncryptionAlgorithm(algorithm.rawValue).keyLength {
                self.init(size: size)
            } else if let size = JSONWebKeyEncryptionAlgorithm(algorithm.rawValue).keyLength {
                self.init(size: .init(bitCount: size))
            } else {
                self.init(size: .bits128)
            }
        }
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        var algorithm = algorithm
        if algorithm == .none {
            algorithm = .init(self.algorithm.rawValue)
        }
        guard let keyClass = algorithm.keyClass?.private as? any JSONWebSymmetricSigningKey.Type else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(self).signature(data, using: algorithm)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        var algorithm = algorithm
        if algorithm == .none {
            algorithm = .init(self.algorithm.rawValue)
        }
        
        guard let keyClass = algorithm.keyClass?.public as? any JSONWebSymmetricSigningKey.Type else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        try keyClass.init(self).verifySignature(signature, for: data, using: algorithm)
    }
}

extension SymmetricKey: JSONWebDecryptingKey {
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        if let keyClass = JSONWebKeyEncryptionAlgorithm(algorithm.rawValue).keyClass?.private as? any JSONWebSymmetricDecryptingKey.Type {
            return try keyClass.init(self).decrypt(data, using: algorithm)
        }
        
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(self).open(.init(data: data, ivLength: 12, tagLength: 16), using: algorithm)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        if let keyClass = JSONWebKeyEncryptionAlgorithm(algorithm.rawValue).keyClass?.private as? any JSONWebSymmetricDecryptingKey.Type {
            return try keyClass.init(self).encrypt(data, using: algorithm)
        }
        
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(self).seal(data, using: algorithm).combined
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension SymmetricKey: JSONWebSealingKey {
    public init(_ key: SymmetricKey) throws {
        self = key
    }
    
    public func seal<D, IV, AAD, JWA>(_ data: D, iv: IV?, authenticating: AAD?, using algorithm: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        guard let keyClass = (algorithm as? JSONWebContentEncryptionAlgorithm)?.keyClass else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(self).seal(data, iv: iv, authenticating: authenticating, using: algorithm)
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using algorithm: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        guard let keyClass = (algorithm as? JSONWebContentEncryptionAlgorithm)?.keyClass else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(self).open(data, authenticating: authenticating, using: algorithm)
    }
}
