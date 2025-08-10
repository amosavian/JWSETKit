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

struct JSONWebDirectKey: JSONWebDecryptingKey, JSONWebSigningKey, JSONWebSymmetricSealingKey {
    let storage: JSONWebValueStorage
    
    var publicKey: Self {
        self
    }
    
    init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(storage: .init())
    }
    
    init(_: SymmetricKey) throws {
        self.init(storage: .init())
    }
    
    init() throws {
        self.init(storage: .init())
    }
    
    init(storage _: JSONWebValueStorage) {
        self.storage = .init()
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
    
    func seal<D, IV, AAD, JWA>(_ data: D, iv _: IV?, authenticating _: AAD?, using _: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        try .init(combined: data, nonceLength: 0, tagLength: 0)
    }
    
    func open<AAD, JWA>(_ data: SealedData, authenticating _: AAD?, using _: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        data.ciphertext
    }
}
