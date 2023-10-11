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
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        var algorithm = algorithm
        if algorithm == .none {
            algorithm = .init(self.algorithm.rawValue)
        }
        switch algorithm {
        case .hmacSHA256:
            return try JSONWebKeyHMAC<SHA256>(self).signature(data, using: algorithm)
        case .hmacSHA384:
            return try JSONWebKeyHMAC<SHA384>(self).signature(data, using: algorithm)
        case .hmacSHA512:
            return try JSONWebKeyHMAC<SHA512>(self).signature(data, using: algorithm)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        var algorithm = algorithm
        if algorithm == .none {
            algorithm = .init(self.algorithm.rawValue)
        }
        switch algorithm {
        case .hmacSHA256:
            try JSONWebKeyHMAC<SHA256>(self).verifySignature(signature, for: data, using: algorithm)
        case .hmacSHA384:
            try JSONWebKeyHMAC<SHA384>(self).verifySignature(signature, for: data, using: algorithm)
        case .hmacSHA512:
            try JSONWebKeyHMAC<SHA512>(self).verifySignature(signature, for: data, using: algorithm)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension SymmetricKey: JSONWebDecryptingKey {
    fileprivate func aesGCMDecrypt<D>(_ data: D) throws -> Data where D: DataProtocol {
        switch data {
        case let data as SealedData:
            return try AES.GCM.open(.init(data), using: self)
        default:
            return try AES.GCM.open(.init(combined: data), using: self)
        }
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try aesGCMDecrypt(data)
        case .aesKeyWrap128, .aesKeyWrap192, .aesKeyWrap256,
             .pbes2hmac256, .pbes2hmac384, .pbes2hmac512:
            return try JSONWebKeyAESKW(storage: storage).unwrap(data).data
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try AES.GCM.seal(data, using: self).combined ?? .init()
        case .aesKeyWrap128, .aesKeyWrap192, .aesKeyWrap256,
             .pbes2hmac256, .pbes2hmac384, .pbes2hmac512:
            return try JSONWebKeyAESKW(storage: storage).wrap(.init(data: Data(data)))
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension SymmetricKey: JSONWebSealingKey {
    public func seal<D, IV, AAD, JWA>(_ data: D, iv: IV?, authenticating: AAD?, using algorithm: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(self).seal(data, iv: iv, authenticating: authenticating, using: algorithm)
        case .aesEncryptionCBC128SHA256, .aesEncryptionCBC192SHA384, .aesEncryptionCBC256SHA512:
            return try JSONWebKeyAESCBCHMAC(self).seal(data, iv: iv, authenticating: authenticating, using: algorithm)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using algorithm: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(self).open(data, authenticating: authenticating, using: algorithm)
        case .aesEncryptionCBC128SHA256, .aesEncryptionCBC192SHA384, .aesEncryptionCBC256SHA512:
            return try JSONWebKeyAESCBCHMAC(self).open(data, authenticating: authenticating, using: algorithm)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}
