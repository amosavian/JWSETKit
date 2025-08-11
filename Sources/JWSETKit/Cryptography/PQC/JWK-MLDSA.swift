//
//  JWK-MLDSA.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 5/24/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// JSON Web Key (JWK) container for different types of Post-Quantum public keys consists of MLDSA-65 and MLDSA-87.
package struct JSONWebMLDSAPublicKey: MutableJSONWebKey, JSONWebKeyAlgorithmKeyPairType, JSONWebValidatingKey, Hashable, Sendable {
    public var storage: JSONWebValueStorage
    
    var validatingKey: any JSONWebValidatingKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self.validatingType(self.algorithm)
                .init(from: self)
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init(from key: JSONWebMLDSAPrivateKey) {
        self.storage = key.storage
        self.seed = nil
    }
    
    public init(derRepresentation: some DataProtocol) throws {
        try self.init(importing: derRepresentation, format: .spki)
    }
    
    static func validatingType(_ algorithm: (any JSONWebAlgorithm)?) throws -> any (JSONWebValidatingKey & JSONWebKeyImportable).Type {
        switch algorithm ?? JSONWebSignatureAlgorithm.unsafeNone {
#if canImport(CryptoKit) && compiler(>=6.2)
        case .mldsa65Signature:
            if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *) {
                return MLDSA65.PublicKey.self
            } else {
                throw JSONWebKeyError.unknownKeyType
            }
        case .mldsa87Signature:
            if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *) {
                return MLDSA87.PublicKey.self
            } else {
                throw JSONWebKeyError.unknownKeyType
            }
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try validatingKey.verifySignature(signature, for: data, using: algorithm)
    }
}

extension JSONWebMLDSAPublicKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .spki:
            let spki = try SubjectPublicKeyInfo(derEncoded: key)
            let keyType = try Self.validatingType(spki.algorithmIdentifier.jsonWebAlgorithm)
            self = try .init(storage: keyType.init(importing: key, format: format).storage)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let underlyingKey = (try? validatingKey) as? (any JSONWebKeyExportable) else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try underlyingKey.exportKey(format: format)
    }
}

/// JWK container for different types of Elliptic-Curve private keys consists of P-256, P-384, P-521, Ed25519.
package struct JSONWebMLDSAPrivateKey: MutableJSONWebKey, JSONWebKeyAlgorithmKeyPairType, JSONWebSigningKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public var publicKey: JSONWebMLDSAPublicKey {
        JSONWebMLDSAPublicKey(from: self)
    }
    
    var signingKey: any JSONWebSigningKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self.signingType(self.algorithm)
                .init(from: self)
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        let keyType = try Self.signingType(algorithm)
        self.storage = try keyType.init(algorithm: algorithm).storage
    }
    
    public init(derRepresentation: some DataProtocol) throws {
        try self.init(importing: derRepresentation, format: .pkcs8)
    }
    
    static func signingType(_ algorithm: (any JSONWebAlgorithm)?) throws -> any (JSONWebSigningKey & JSONWebKeyImportable).Type {
        switch algorithm ?? JSONWebSignatureAlgorithm.unsafeNone {
#if canImport(CryptoKit) && compiler(>=6.2)
        case .mldsa65Signature:
            if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *) {
                return MLDSA65.PrivateKey.self
            } else {
                throw JSONWebKeyError.unknownKeyType
            }
        case .mldsa87Signature:
            if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *) {
                return MLDSA87.PrivateKey.self
            } else {
                throw JSONWebKeyError.unknownKeyType
            }
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signingKey.signature(data, using: algorithm)
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard let keyType = self.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        try checkRequiredFields(keyType.requiredFields + ["priv"])
    }
}

extension JSONWebMLDSAPrivateKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .pkcs8:
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            let keyType = try Self.signingType(pkcs8.algorithmIdentifier.jsonWebAlgorithm)
            self = try .init(storage: keyType.init(importing: key, format: format).storage)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let underlyingKey = (try? signingKey) as? (any JSONWebKeyExportable) else {
            throw JSONWebKeyError.unknownKeyType
        }
        return try underlyingKey.exportKey(format: format)
    }
}
