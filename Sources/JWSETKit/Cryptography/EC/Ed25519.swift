//
//  File.swift
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
    public init(storage: JSONWebValueStorage) {
        self = Curve25519.Signing.PrivateKey().publicKey
        self.storage = storage
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D : DataProtocol {
        if !self.isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension Curve25519.Signing.PrivateKey: CryptoECPrivateKey {
    typealias PublicKey = Curve25519.Signing.PublicKey
}

extension Curve25519.Signing.PrivateKey: JSONWebSigningKey {
    public init(storage: JSONWebValueStorage) {
        self = try! Self.create(storage: storage)
    }
    
    public func sign<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D : DataProtocol {
        try self.signature(for: data)
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D : DataProtocol {
        try self.publicKey.validate(signature, for: data, using: algorithm)
    }
}
