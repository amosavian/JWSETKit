//
//  Ed25519.swift
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

extension Curve25519.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .ed25519 }
}

extension Curve25519.Signing.PublicKey: JSONWebValidatingKey {
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        self = Curve25519.Signing.PrivateKey().publicKey
        self.storage = storage
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        if !isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension Curve25519.Signing.PrivateKey: CryptoECPrivateKey {
    typealias PublicKey = Curve25519.Signing.PublicKey
}

extension Curve25519.Signing.PrivateKey: JSONWebSigningKey {
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        self = try! Self.create(storage: storage)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: data)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}
