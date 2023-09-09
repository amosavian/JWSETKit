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

extension P256.Signing.PublicKey: JSONWebValidatingKey {
    public init(storage: JSONWebValueStorage) {
        self = P256.Signing.PrivateKey().publicKey
        self.storage = storage
    }
    
    public var storage: JSONWebValueStorage {
        get {
            var result = AnyJSONWebKey()
            let rawRepresentation = rawRepresentation
            result.keyType = .elipticCurve
            result.curve = .p256
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
    
    public static func create(storage: JSONWebValueStorage) throws -> P256.Signing.PublicKey {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, x.count == 32,
              let y = keyData.yCoordinate, y.count == 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        let rawKey = x + y
        return try .init(rawRepresentation: rawKey)
    }
    
    public func validate<D>(_ signature: D, for data: D, using algorithm: JSONWebAlgorithm) throws where D : DataProtocol {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        var digest = SHA256()
        digest.update(data: data)
        if !self.isValidSignature(signature, for: digest.finalize()) {
            throw CryptoKitError.authenticationFailure
        }
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
    
    public static func == (lhs: P256.Signing.PublicKey, rhs: P256.Signing.PublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension P256.Signing.PrivateKey: JSONWebSigningKey {
    public init(storage: JSONWebValueStorage) {
        self.init()
        self.storage = storage
    }
    
    public var storage: JSONWebValueStorage {
        get {
            var result = AnyJSONWebKey()
            let rawRepresentation = rawRepresentation
            result.keyType = .elipticCurve
            result.curve = .p256
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
    
    public static func create(storage: JSONWebValueStorage) throws -> P256.Signing.PrivateKey {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let privateKey = keyData.privateKey, privateKey.count == 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        return try .init(rawRepresentation: privateKey)
    }
    
    public func sign<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D : DataProtocol {
        var digest = SHA256()
        digest.update(data: data)
        return try self.signature(for: digest.finalize()).rawRepresentation
    }
    
    public func validate<D>(_ signature: D, for data: D, using algorithm: JSONWebAlgorithm) throws where D : DataProtocol {
        try self.publicKey.validate(signature, for: data, using: algorithm)
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
    
    public static func == (lhs: P256.Signing.PrivateKey, rhs: P256.Signing.PrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}
