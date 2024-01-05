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
    
    var underlyingKey: any JSONWebValidatingKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self.singingType(for: self.keyType ?? .empty, self.curve ?? .empty)
                .create(storage: storage)
        }
    }
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebECPublicKey {
        .init(storage: storage)
    }
    
    static func singingType(for keyType: JSONWebKeyType, _ curve: JSONWebKeyCurve) throws -> any JSONWebValidatingKey.Type {
        switch (keyType, curve) {
        case (JSONWebKeyType.ellipticCurve, .p256):
            return P256.Signing.PublicKey.self
        case (JSONWebKeyType.ellipticCurve, .p384):
            return P384.Signing.PublicKey.self
        case (JSONWebKeyType.ellipticCurve, .p521):
            return P521.Signing.PublicKey.self
        case (JSONWebKeyType.ellipticCurve, .ed25519), (JSONWebKeyType.octetKeyPair, .ed25519):
            return Curve25519.Signing.PublicKey.self
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try underlyingKey.verifySignature(signature, for: data, using: algorithm)
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
    
    var underlyingKey: any JSONWebSigningKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self
                .singingType(for: self.keyType ?? .empty, self.curve ?? .empty)
                .create(storage: storage)
        }
    }
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public init(algorithm: any JSONWebAlgorithm) throws {
        self.storage = try Self
            .singingType(for: algorithm.keyType ?? .empty, algorithm.curve ?? .empty)
            .init(algorithm: algorithm).storage
    }
    
    static func singingType(for keyType: JSONWebKeyType, _ curve: JSONWebKeyCurve) throws -> any JSONWebSigningKey.Type {
        switch (keyType, curve) {
        case (JSONWebKeyType.ellipticCurve, .p256):
            return P256.Signing.PrivateKey.self
        case (JSONWebKeyType.ellipticCurve, .p384):
            return P384.Signing.PrivateKey.self
        case (JSONWebKeyType.ellipticCurve, .p521):
            return P521.Signing.PrivateKey.self
        case (JSONWebKeyType.ellipticCurve, .ed25519), (JSONWebKeyType.octetKeyPair, .ed25519):
            return Curve25519.Signing.PrivateKey.self
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebECPrivateKey {
        .init(storage: storage)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try underlyingKey.signature(data, using: algorithm)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}

enum ECHelper {
    static func ecComponents(_ data: Data, keyLength: Int) throws -> [Data] {
        var data = data
        // Check if data is x.963 format, if so, remove the
        // first byte which is data compression type.
        if data.count % (keyLength / 8) == 1 {
            // Key data is uncompressed.
            guard data.removeFirst() == 0x04 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        
        return stride(from: 0, to: data.count, by: keyLength / 8).map {
            data[$0 ..< min($0 + keyLength / 8, data.count)]
        }
    }
    
    static func ecWebKey(data: Data, keyLength: Int, isPrivateKey: Bool) throws -> any JSONWebKey {
        let components = try ecComponents(data, keyLength: keyLength)
        var key = AnyJSONWebKey()

        guard !components.isEmpty else {
            throw JSONWebKeyError.unknownKeyType
        }

        key.keyType = .ellipticCurve
        key.curve = .init(rawValue: "P-\(components[0].count * 8)")
        
        switch (components.count, isPrivateKey) {
        case (2, false):
            key.xCoordinate = components[0]
            key.yCoordinate = components[1]
            return JSONWebECPublicKey(storage: key.storage)
        case (3, true):
            key.xCoordinate = components[0]
            key.yCoordinate = components[1]
            key.privateKey = components[2]
            return JSONWebECPrivateKey(storage: key.storage)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}
