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

protocol CryptoModuleLatticePublicKey: JSONWebKey, Hashable {
    static var algorithm: any JSONWebAlgorithm { get }
    init(rawRepresentation: some DataProtocol) throws
    var rawRepresentation: Data { get }
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
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
}

protocol CryptoModuleLatticePrivateKey: JSONWebKey, Hashable {
    associatedtype PublicKey: CryptoModuleLatticePublicKey
    var publicKey: PublicKey { get }
    var seedRepresentation: Data { get }
    init() throws
    init(seedRepresentation: some DataProtocol) throws
}

extension CryptoModuleLatticePrivateKey {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .algorithmKeyPair
        result.algorithm = Self.PublicKey.algorithm
        result.publicKeyData = publicKey.publicKeyData
        result.seed = seedRepresentation
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let seed = key.seed else {
            throw CryptoKitError.incorrectParameterSize
        }
        try self.init(seedRepresentation: seed)
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init()
    }
}

protocol CryptoModuleLatticePortable: JSONWebKeyImportable, JSONWebKeyExportable {
    static var algorithmIdentifier: RFC5480AlgorithmIdentifier { get }
}

extension CryptoModuleLatticePortable where Self: CryptoModuleLatticePublicKey {
    init<D>(internalImporting key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(rawRepresentation: key)
        case .spki:
            let spki = try SubjectPublicKeyInfo(derEncoded: key)
            try self.init(rawRepresentation: spki.key.bytes)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension CryptoModuleLatticePortable where Self: CryptoModuleLatticePrivateKey {
    init<D>(internalImporting key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(seedRepresentation: key)
        case .pkcs8:
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            guard let privateKey = pkcs8.privateKey as? ModuleLatticePrivateKey else {
                throw JSONWebKeyError.invalidKeyFormat
            }
            self = try .init(seedRepresentation: [UInt8](privateKey.seed.bytes))
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension CryptoModuleLatticePortable {
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        return switch format {
        case .raw:
            switch self {
            case let self as any CryptoModuleLatticePrivateKey:
                self.seedRepresentation
            case let self as any CryptoModuleLatticePublicKey:
                self.rawRepresentation
            default:
                throw JSONWebKeyError.unknownKeyType
            }
        case .spki where self is any CryptoModuleLatticePublicKey:
            switch self {
            case let self as any CryptoModuleLatticePublicKey:
                try SubjectPublicKeyInfo(
                    algorithmIdentifier: Self.algorithmIdentifier,
                    key: [UInt8](self.rawRepresentation)
                ).derRepresentation
            default:
                throw JSONWebKeyError.operationNotAllowed
            }
        case .pkcs8 where self is any CryptoModuleLatticePrivateKey:
            switch self {
            case let self as any CryptoModuleLatticePrivateKey:
                try PKCS8PrivateKey(
                    algorithm: Self.algorithmIdentifier,
                    privateKey: ModuleLatticePrivateKey(seed: .init(self.seedRepresentation))
                ).derRepresentation
            default:
                throw JSONWebKeyError.operationNotAllowed
            }
        case .jwk:
            try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}
