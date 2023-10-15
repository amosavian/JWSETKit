//
//  JWK-EC.swift
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

/// JSON Web Key (JWK) container for different types of Elliptic-Curve public keys consists of P-256, P-384, P-521, Ed25519.
public struct JSONWebECPublicKey: MutableJSONWebKey, JSONWebValidatingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebECPublicKey {
        .init(storage: storage)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        // swiftformat:disable:next redundantSelf
        switch (self.keyType ?? .empty, self.curve ?? .empty) {
        case (JSONWebKeyType.ellipticCurve, .p256):
            try P256.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .p384):
            try P384.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .p521):
            try P521.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .ed25519):
            try Curve25519.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}

/// JWK container for different types of Elliptic-Curve private keys consists of P-256, P-384, P-521, Ed25519.
public struct JSONWebECPrivateKey: MutableJSONWebKey, JSONWebSigningKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public var publicKey: JSONWebECPublicKey {
        var result = JSONWebECPublicKey(storage: storage)
        result.privateKey = nil
        return result
    }
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public init() throws {
        self.storage = try P256.Signing.PrivateKey().storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebECPrivateKey {
        .init(storage: storage)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        // swiftformat:disable:next redundantSelf
        switch (self.keyType ?? .empty, self.curve ?? .empty) {
        case (JSONWebKeyType.ellipticCurve, .p256):
            return try P256.Signing.PrivateKey.create(storage: storage)
                .signature(data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .p384):
            return try P384.Signing.PrivateKey.create(storage: storage)
                .signature(data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .p521):
            return try P521.Signing.PrivateKey.create(storage: storage)
                .signature(data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .ed25519):
            return try Curve25519.Signing.PrivateKey.create(storage: storage)
                .signature(data, using: algorithm)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        // swiftformat:disable:next redundantSelf
        switch (self.keyType ?? .empty, self.curve ?? .empty) {
        case (JSONWebKeyType.ellipticCurve, .p256):
            try P256.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .p384):
            try P384.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .p521):
            try P521.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        case (JSONWebKeyType.ellipticCurve, .ed25519):
            try Curve25519.Signing.PublicKey.create(storage: storage)
                .verifySignature(signature, for: data, using: algorithm)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}
