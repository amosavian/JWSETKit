//
//  P521.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

extension P521.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p521 }
}

extension P521.Signing.PublicKey: JSONWebValidatingKey {
    public init(storage: JSONWebValueStorage) {
        self = P521.Signing.PrivateKey().publicKey
        self.storage = storage
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        var digest = SHA512()
        digest.update(data: data)
        if !isValidSignature(signature, for: digest.finalize()) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P521.Signing.PrivateKey: CryptoECPrivateKey {
    typealias PublicKey = P521.Signing.PublicKey
}

extension P521.Signing.PrivateKey: JSONWebSigningKey {
    public init(storage: JSONWebValueStorage) {
        self.init()
        self.storage = storage
    }
    
    public func signature<D>(_ data: D, using _: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        var digest = SHA512()
        digest.update(data: data)
        return try signature(for: digest.finalize()).rawRepresentation
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}
