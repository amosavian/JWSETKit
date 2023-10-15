//
//  Direct.swift
//
//
//  Created by Amir Abbas Mousavian on 10/14/23.
//

import Foundation

struct JSONWebDirectKey: JSONWebDecryptingKey, JSONWebSigningKey {
    var storage: JSONWebValueStorage
    
    var publicKey: Self {
        self
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
    
    func verifySignature<S, D>(_: S, for _: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {}
    
    func signature<D>(_: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        .init()
    }
}
