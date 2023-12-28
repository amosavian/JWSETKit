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
    
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .octetKeyPair // Ed25519 is OKP per RFC8037
        result.curve = Self.curve
        result.xCoordinate = rawRepresentation
        return result.storage
    }
}

extension Curve25519.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        if !isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension Curve25519.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey {
    public init(algorithm _: any JSONWebAlgorithm) throws {
        self.init()
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: data)
    }
}

extension Curve25519.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .x25519 }
    
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .octetKeyPair // X25519 is OKP per RFC8037
        result.curve = Self.curve
        result.xCoordinate = rawRepresentation
        return result.storage
    }
}

extension Curve25519.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public init(algorithm _: any JSONWebAlgorithm) throws {
        self.init()
    }
}
