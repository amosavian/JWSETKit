//
//  CryptoKitAbstract.swift
//
//
//  Created by Amir Abbas Mousavian on 9/10/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

protocol CryptoECPublicKey: JSONWebValidatingKey {
    static var curve: JSONWebKeyCurve { get }
    var rawRepresentation: Data { get }
    init(rawRepresentation: Data) throws
}

extension CryptoECPublicKey {
    public var storage: JSONWebValueStorage {
        get {
            var result = AnyJSONWebKey()
            let rawRepresentation = rawRepresentation
            result.keyType = .elipticCurve
            result.curve = Self.curve
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
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, x.count == curve.keyLengthInBytes,
              let y = keyData.yCoordinate, y.count == curve.keyLengthInBytes
        else {
            throw CryptoKitError.incorrectKeySize
        }
        let rawKey = x + y
        return try .init(rawRepresentation: rawKey)
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

protocol CryptoECPrivateKey: JSONWebSigningKey where PublicKey: CryptoECPublicKey {
    var rawRepresentation: Data { get }
    init(rawRepresentation: Data) throws
}

extension CryptoECPrivateKey {
    public var storage: JSONWebValueStorage {
        get {
            var result = AnyJSONWebKey()
            let rawRepresentation = rawRepresentation
            result.keyType = .elipticCurve
            result.curve = PublicKey.curve
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
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let privateKey = keyData.privateKey, privateKey.count == PublicKey.curve.keyLengthInBytes else {
            throw CryptoKitError.incorrectKeySize
        }
        return try .init(rawRepresentation: privateKey)
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
}
