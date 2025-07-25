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

protocol CryptoModuleLatticePublicKey: JSONWebKey, JSONWebKeyRawRepresentable, JSONWebKeyAlgorithmIdentified, JSONWebKeyImportable, JSONWebKeyExportable {
    func isValidSignature<S, D>(signature: S, for data: D) -> Bool where S : DataProtocol, D : DataProtocol
}

extension CryptoModuleLatticePublicKey {
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
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S : DataProtocol, D : DataProtocol {
        if !isValidSignature(signature: signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        return switch format {
        case .raw:
            self.rawRepresentation
        case .spki where !(self is any JSONWebPrivateKey):
            try SubjectPublicKeyInfo(
                algorithmIdentifier: Self.algorithmIdentifier,
                key: [UInt8](self.rawRepresentation)
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

protocol CryptoModuleLatticePrivateKey: JSONWebPrivateKey, JSONWebKeyImportable, JSONWebKeyExportable where PublicKey: CryptoModuleLatticePublicKey {
    var seedRepresentation: Data { get }
    init() throws
    init<D>(seedRepresentation: D, publicKey: PublicKey?) throws where D: DataProtocol
    func signature<D>(for data: D) throws -> Data where D : DataProtocol
}

extension CryptoModuleLatticePrivateKey {
    public static var algorithmIdentifier: RFC5480AlgorithmIdentifier {
        PublicKey.algorithmIdentifier
    }
    
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
        let publicKey = key.publicKeyData
        try self.init(seedRepresentation: seed, publicKey: publicKey.map(PublicKey.init(rawRepresentation:)))
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init()
    }
    
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
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D : DataProtocol {
        try signature(for: data)
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        return switch format {
        case .raw:
            self.seedRepresentation
        case .spki:
            throw JSONWebKeyError.operationNotAllowed
        case .pkcs8:
            try PKCS8PrivateKey(
                algorithm: Self.algorithmIdentifier,
                privateKey: ModuleLatticePrivateKey(seed: .init(self.seedRepresentation))
            ).derRepresentation
        case .jwk:
            try jwkRepresentation
        }
    }
}
