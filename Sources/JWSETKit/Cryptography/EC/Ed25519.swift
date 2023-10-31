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
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        if !isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension Curve25519.Signing.PrivateKey: CryptoECPrivateKey {
    public init(algorithm: any JSONWebAlgorithm) throws {
        self.init()
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: data)
    }
}
