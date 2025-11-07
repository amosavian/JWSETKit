//
//  ModuleLatticeAbstract.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 6/17/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

public protocol JSONWebKeyAlgorithmKeyPairPublic: JSONWebKey, JSONWebKeyAlgorithmKeyPairType {}

public protocol JSONWebKeyAlgorithmKeyPairPrivate: JSONWebPrivateKey, JSONWebKeyAlgorithmKeyPairType where PublicKey: JSONWebKeyAlgorithmKeyPairPublic {
    var seedRepresentation: Data { get }
    init<D>(seedRepresentation: D, publicKey: PublicKey?) throws where D: DataProtocol
}

extension JSONWebKeyAlgorithmKeyPairPublic where Self: JSONWebKeyRawRepresentable & JSONWebKeyAlgorithmIdentified {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .algorithmKeyPair
        result.algorithm = Self.algorithm
        result.publicKeyData = rawRepresentation
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let publicKey = key.publicKeyData else {
            throw CryptoKitError.incorrectParameterSize
        }
        try self.init(rawRepresentation: publicKey)
    }
}

extension JSONWebKeyAlgorithmKeyPairPublic where Self: JSONWebKeyRawRepresentable & JSONWebKeyAlgorithmIdentified & JSONWebKeyExportable {
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        return switch format {
        case .raw:
            rawRepresentation
        case .spki where !(self is any JSONWebPrivateKey):
            try SubjectPublicKeyInfo(
                algorithmIdentifier: Self.algorithmIdentifier,
                key: [UInt8](rawRepresentation)
            ).derRepresentation
        case .pkcs8:
            throw JSONWebKeyError.operationNotAllowed
        case .jwk:
            try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension JSONWebKeyAlgorithmKeyPairPrivate where Self: JSONWebKeyAlgorithmIdentified, PublicKey: JSONWebKeyAlgorithmKeyPairPublic & JSONWebKeyRawRepresentable & JSONWebKeyAlgorithmIdentified {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .algorithmKeyPair
        result.algorithm = Self.PublicKey.algorithm
        result.publicKeyData = publicKey.rawRepresentation
        result.seed = seedRepresentation
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let seed = key.seed else {
            throw CryptoKitError.incorrectParameterSize
        }
        let publicKeyData = key.publicKeyData
        try self.init(seedRepresentation: seed, publicKey: publicKeyData.map(PublicKey.init(rawRepresentation:)))
    }
}

extension JSONWebKeyAlgorithmKeyPairPrivate where Self: JSONWebKeyAlgorithmIdentified & JSONWebKeyImportable, PublicKey: JSONWebKeyAlgorithmKeyPairPublic & JSONWebKeyRawRepresentable & JSONWebKeyAlgorithmIdentified {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(seedRepresentation: key, publicKey: nil)
        case .spki:
            throw JSONWebKeyError.invalidKeyFormat
        case .pkcs8:
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            guard let privateKey = pkcs8.privateKey as? ModuleLatticePrivateKey else {
                throw JSONWebKeyError.invalidKeyFormat
            }
            self = try .init(seedRepresentation: [UInt8](privateKey.seed.bytes), publicKey: nil)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        }
    }
}

extension JSONWebKeyAlgorithmKeyPairPrivate where Self: JSONWebKeyAlgorithmIdentified & JSONWebKeyExportable, PublicKey: JSONWebKeyAlgorithmKeyPairPublic & JSONWebKeyRawRepresentable & JSONWebKeyAlgorithmIdentified {
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        return switch format {
        case .raw:
            seedRepresentation
        case .spki:
            throw JSONWebKeyError.operationNotAllowed
        case .pkcs8:
            try PKCS8PrivateKey(
                algorithm: Self.algorithmIdentifier,
                privateKey: ModuleLatticePrivateKey(seed: .init(seedRepresentation))
            ).derRepresentation
        case .jwk:
            try jwkRepresentation
        }
    }
}

protocol CryptoModuleLatticePublicKey: JSONWebKeyAlgorithmKeyPairPublic, JSONWebKeyRawRepresentable, JSONWebKeyAlgorithmIdentified, JSONWebKeyImportable, JSONWebKeyExportable {
    func isValidSignature<S, D>(_ signature: S, for data: D) -> Bool where S: DataProtocol, D: DataProtocol
}

extension CryptoModuleLatticePublicKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        if !isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

protocol CryptoModuleLatticePrivateKey: JSONWebKeyAlgorithmKeyPairPrivate, JSONWebKeyAlgorithmIdentified, JSONWebKeyImportable, JSONWebKeyExportable where PublicKey: CryptoModuleLatticePublicKey {
    init() throws
    func signature<D>(for data: D) throws -> Data where D: DataProtocol
}

extension CryptoModuleLatticePrivateKey {
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init()
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: data)
    }
}
