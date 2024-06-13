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

protocol CryptoECPublicKey: JSONWebKey {
    static var curve: JSONWebKeyCurve { get }
    var rawRepresentation: Data { get }
    init(rawRepresentation: Data) throws
}

extension CryptoECPublicKey {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        let rawRepresentation = rawRepresentation
        result.keyType = .ellipticCurve
        result.curve = Self.curve
        result.xCoordinate = rawRepresentation.prefix(rawRepresentation.count / 2)
        result.yCoordinate = rawRepresentation.suffix(rawRepresentation.count / 2)
        return result.storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, !x.isEmpty, let y = keyData.yCoordinate, y.count == x.count else {
            throw CryptoKitError.incorrectKeySize
        }
        return try .init(rawRepresentation: x + y)
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

protocol CryptoECPublicKeyPortable: JSONWebKeyImportable, JSONWebKeyExportable {
    var x963Representation: Data { get }
    var derRepresentation: Data { get }
    
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
}

extension CryptoECPublicKeyPortable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            if key.regions.count == 1, let keyData = key.regions.first {
                try self.init(x963Representation: keyData)
            } else {
                try self.init(x963Representation: Data(key))
            }
        case .spki:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .raw:
            return x963Representation
        case .spki:
            return derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

protocol CryptoECPrivateKey: JSONWebKey {
    associatedtype PublicKey: CryptoECPublicKey
    
    /// Public key.
    var publicKey: PublicKey { get }
    var rawRepresentation: Data { get }
    init(rawRepresentation: Data) throws
}

extension CryptoECPrivateKey {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey(storage: publicKey.storage)
        result.privateKey = rawRepresentation
        return result.storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let privateKey = keyData.privateKey, !privateKey.isEmpty else {
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

protocol CryptoECPrivateKeyPortable: JSONWebKeyImportable, JSONWebKeyExportable {
    var x963Representation: Data { get }
    var derRepresentation: Data { get }
    
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
}

extension CryptoECPrivateKeyPortable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            if key.regions.count == 1, let keyData = key.regions.first {
                try self.init(x963Representation: keyData)
            } else {
                try self.init(x963Representation: Data(key))
            }
        case .pkcs8:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .raw:
            return x963Representation
        case .pkcs8:
            return derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}
