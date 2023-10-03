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
        get {
            var result = AnyJSONWebKey()
            result.keyType = .symmetric
            withUnsafeBytes {
                result.keyValue = Data($0)
            }
            return result.storage
        }
        mutating set {
            guard let data = newValue["k", true] else { return }
            self = SymmetricKey(data: data)
        }
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
        self.init(size: .bits128)
        self.storage = storage
    }
    
    public func hash(into hasher: inout Hasher) {
        withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}

extension SymmetricKey: JSONWebSigningKey {
    public func signature<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        var algorithm = algorithm
        if algorithm == .none {
            algorithm = self.algorithm
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
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        var algorithm = algorithm
        if algorithm == .none {
            algorithm = self.algorithm
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
    
    public func decrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try aesGCMDecrypt(data)
        case .aesKeyWrap128, .aesKeyWrap192, .aesKeyWrap256:
            if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
                return try AES.KeyWrap.unwrap(data, using: self).withUnsafeBytes { Data($0) }
            } else {
                throw JSONWebKeyError.unknownAlgorithm
            }
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func encrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> SealedData where D: DataProtocol {
        switch algorithm {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try .init(AES.GCM.seal(data, using: self))
        case .aesKeyWrap128, .aesKeyWrap192, .aesKeyWrap256:
            if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
                return try .init(ciphertext: AES.KeyWrap.wrap(.init(data: Data(data)), using: self))
            } else {
                throw JSONWebKeyError.unknownAlgorithm
            }
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}
