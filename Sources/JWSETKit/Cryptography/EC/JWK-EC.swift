//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

import Foundation
import CryptoKit

public struct JSONWebECPublicKey: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebECPublicKey {
        .init(storage: storage)
    }
    
    public func validate<D>(_ signature: D, for data: D) throws where D : DataProtocol {
        switch (self.keyType ?? .init(rawValue: ""), self.curve ?? .init(rawValue: "")) {
        case (JSONWebKeyType.elipticCurve, .p256):
            try P256.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        case (JSONWebKeyType.elipticCurve, .p384):
            try P384.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        case (JSONWebKeyType.elipticCurve, .p521):
            try P521.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        case (JSONWebKeyType.elipticCurve, .ed25519):
            try Curve25519.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}

public struct JSONWebECPrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebECPrivateKey {
        .init(storage: storage)
    }
    
    public func sign<D>(_ data: D) throws -> Data where D : DataProtocol {
        switch (self.keyType ?? .init(rawValue: ""), self.curve ?? .init(rawValue: "")) {
        case (JSONWebKeyType.elipticCurve, .p256):
            return try P256.Signing.PrivateKey(jsonWebKey: storage).sign(data)
        case (JSONWebKeyType.elipticCurve, .p384):
            return try P384.Signing.PrivateKey(jsonWebKey: storage).sign(data)
        case (JSONWebKeyType.elipticCurve, .p521):
            return try P521.Signing.PrivateKey(jsonWebKey: storage).sign(data)
        case (JSONWebKeyType.elipticCurve, .ed25519):
            return try Curve25519.Signing.PrivateKey(jsonWebKey: storage).sign(data)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func validate<D>(_ signature: D, for data: D) throws where D : DataProtocol {
        switch (self.keyType ?? .init(rawValue: ""), self.curve ?? .init(rawValue: "")) {
        case (JSONWebKeyType.elipticCurve, .p256):
            try P256.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        case (JSONWebKeyType.elipticCurve, .p384):
            try P384.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        case (JSONWebKeyType.elipticCurve, .p521):
            try P521.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        case (JSONWebKeyType.elipticCurve, .ed25519):
            try Curve25519.Signing.PublicKey(jsonWebKey: storage).validate(signature, for: data)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}
