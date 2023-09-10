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

extension Curve25519.Signing.PublicKey: JSONWebValidatingKey {
    public init(storage: JSONWebValueStorage) {
        self = Curve25519.Signing.PrivateKey().publicKey
        self.storage = storage
    }
    
    public var storage: JSONWebValueStorage {
        get {
            var result = AnyJSONWebKey()
            let rawRepresentation = rawRepresentation
            result.keyType = .elipticCurve
            result.curve = .ed25519
            result.xCoordinate = rawRepresentation.prefix(rawRepresentation.count / 2)
            result.yCoordinate = rawRepresentation.suffix(rawRepresentation.count / 2)
            return result.storage
        }
        set {
            guard let newValue = try? Self.create(storage: newValue) else {
                assertionFailure(CryptoKitError.incorrectKeySize.localizedDescription)
                return
            }
            self = newValue
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Curve25519.Signing.PublicKey {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, x.count == 32,
              let y = keyData.yCoordinate, y.count == 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        let rawKey = x + y
        return try .init(rawRepresentation: rawKey)
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D : DataProtocol {
        if !self.isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
    
    public static func == (lhs: Curve25519.Signing.PublicKey, rhs: Curve25519.Signing.PublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension Curve25519.Signing.PrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage {
        get {
            var result = AnyJSONWebKey()
            let rawRepresentation = rawRepresentation
            result.keyType = .elipticCurve
            result.curve = .ed25519
            result.xCoordinate = publicKey.rawRepresentation.prefix(rawRepresentation.count / 2)
            result.yCoordinate = publicKey.rawRepresentation.suffix(rawRepresentation.count / 2)
            result.privateKey = rawRepresentation
            return result.storage
        }
        set {
            guard let newValue = try? Self.create(storage: newValue) else {
                assertionFailure(CryptoKitError.incorrectKeySize.localizedDescription)
                return
            }
            self = newValue
        }
    }
    
    public init(storage: JSONWebValueStorage) {
        self = try! Self.create(storage: storage)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Curve25519.Signing.PrivateKey {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let privateKey = keyData.privateKey, privateKey.count == 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        return try .init(rawRepresentation: privateKey)
    }
    
    public func sign<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D : DataProtocol {
        try self.signature(for: data)
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D : DataProtocol {
        try self.publicKey.validate(signature, for: data, using: algorithm)
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
    
    public static func == (lhs: Curve25519.Signing.PrivateKey, rhs: Curve25519.Signing.PrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}
