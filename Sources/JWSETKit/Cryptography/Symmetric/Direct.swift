//
//  Direct.swift
//
//
//  Created by Amir Abbas Mousavian on 10/14/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

struct JSONWebDirectKey: JSONWebDecryptingKey, JSONWebSigningKey {
    var storage: JSONWebValueStorage
    
    var publicKey: Self {
        self
    }
    
    init(algorithm: some JSONWebAlgorithm) throws {
        guard algorithm == .direct else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        self.storage = .init()
    }
    
    init() throws {
        self.storage = .init()
    }
    
    init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    static func create(storage: JSONWebValueStorage) throws -> JSONWebDirectKey {
        Self(storage: storage)
    }
    
    func encrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        Data(data)
    }
    
    func decrypt<D, JWA>(_ data: D, using _: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        Data(data)
    }
    
    func verifySignature<S, D>(_ signature: S, for _: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        guard signature.isEmpty else {
            throw CryptoKitError.authenticationFailure
        }
    }
    
    func signature<D>(_: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        .init()
    }
}
