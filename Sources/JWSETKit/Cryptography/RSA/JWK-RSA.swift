//
//  JWK-RSA.swift
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

public struct JSONWebRSAPublicKey: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebRSAPublicKey {
        .init(storage: storage)
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey(jsonWebKey: storage).validate(signature, for: data, using: algorithm)
#else
        fatalError()
#endif
    }
}

public struct JSONWebRSAPrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebRSAPrivateKey {
        .init(storage: storage)
    }
    
    public func sign<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
#if canImport(CommonCrypto)
        return try SecKey(jsonWebKey: storage).sign(data, using: algorithm)
#else
        fatalError()
#endif
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey(jsonWebKey: storage).validate(signature, for: data, using: algorithm)
#else
        fatalError()
#endif
    }
}
