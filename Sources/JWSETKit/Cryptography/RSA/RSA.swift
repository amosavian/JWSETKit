//
//  RSA.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

#if canImport(_CryptoExtras)
import _CryptoExtras
import Crypto
import Foundation
import SwiftASN1

extension _RSA.Signing.PublicKey: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        // `pkcs1DERRepresentation` is always a valid ASN1 object and it should not fail.
        try! RSAHelper.rsaWebKey(data: pkcs1DERRepresentation).storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Signing.PublicKey {
        let der = try RSAHelper.pkcs1Representation(AnyJSONWebKey(storage: storage))
        return try .init(derRepresentation: der)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        guard let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        if try !isValidSignature(.init(rawRepresentation: signature), for: hashFunction.hash(data: data), padding: algorithm.rsaPadding) {
            throw CryptoKitError.authenticationFailure
        }
    }
    
    public static func == (lhs: _RSA.Signing.PublicKey, rhs: _RSA.Signing.PublicKey) -> Bool {
        lhs.pkcs1DERRepresentation == rhs.pkcs1DERRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(pkcs1DERRepresentation)
    }
}

extension _RSA.Signing.PublicKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init(importing key: Data, format: JSONWebKeyFormat) throws {
        switch format {
        case .spki:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: key)
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .spki:
            return derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension _RSA.Signing.PrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage {
        get {
            // `derRepresentation` is always a valid ASN1 object and it should not fail.
            try! RSAHelper.rsaWebKey(data: derRepresentation).storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public init(algorithm _: any JSONWebAlgorithm) throws {
        try self.init(keySize: .bits2048)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Signing.PrivateKey {
        let der = try RSAHelper.pkcs1Representation(AnyJSONWebKey(storage: storage))
        return try .init(derRepresentation: der)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        guard let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try signature(for: hashFunction.hash(data: data), padding: algorithm.rsaPadding).rawRepresentation
    }
    
    public static func == (lhs: _RSA.Signing.PrivateKey, rhs: _RSA.Signing.PrivateKey) -> Bool {
        lhs.derRepresentation =~= rhs.derRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(derRepresentation)
    }
}

extension _RSA.Signing.PrivateKey: JSONWebKeyImportable, JSONWebKeyExportable {
    var pkcs8Representation: Data {
        // PEM is always a valid Bas64.
        Data(base64Encoded: pkcs8PEMRepresentation
            .components(separatedBy: .whitespacesAndNewlines)
            .dropFirst().dropLast().joined()).unsafelyUnwrapped
    }
    
    public init(importing key: Data, format: JSONWebKeyFormat) throws {
        switch format {
        case .pkcs8:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: key)
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .pkcs8:
            return pkcs8Representation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension _RSA.Encryption.PublicKey: JSONWebEncryptingKey {
    public var storage: JSONWebValueStorage {
        get {
            // `pkcs1DERRepresentation` is always a valid ASN1 object and it should not fail.
            try! RSAHelper.rsaWebKey(data: pkcs1DERRepresentation).storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Encryption.PublicKey {
        let der = try RSAHelper.pkcs1Representation(AnyJSONWebKey(storage: storage))
        return try .init(derRepresentation: der)
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try encrypt(data, padding: algorithm.rsaEncryptionPadding)
    }
    
    public static func == (lhs: _RSA.Encryption.PublicKey, rhs: _RSA.Encryption.PublicKey) -> Bool {
        lhs.pkcs1DERRepresentation == rhs.pkcs1DERRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(pkcs1DERRepresentation)
    }
}

extension _RSA.Encryption.PrivateKey: JSONWebDecryptingKey {
    public var storage: JSONWebValueStorage {
        get {
            // `derRepresentation` is always a valid ASN1 object and it should not fail.
            try! RSAHelper.rsaWebKey(data: derRepresentation).storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public init(algorithm _: any JSONWebAlgorithm) throws {
        try self.init(keySize: .bits2048)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Encryption.PrivateKey {
        let der = try RSAHelper.pkcs1Representation(AnyJSONWebKey(storage: storage))
        return try .init(derRepresentation: der)
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try decrypt(data, padding: algorithm.rsaEncryptionPadding)
    }
    
    public static func == (lhs: _RSA.Encryption.PrivateKey, rhs: _RSA.Encryption.PrivateKey) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(derRepresentation)
    }
}

extension JSONWebAlgorithm {
    fileprivate var rsaPadding: _RSA.Signing.Padding {
        get throws {
            switch self {
            case .rsaSignaturePKCS1v15SHA256, .rsaSignaturePKCS1v15SHA384, .rsaSignaturePKCS1v15SHA512:
                return .insecurePKCS1v1_5
            case .rsaSignaturePSSSHA256, .rsaSignaturePSSSHA384, .rsaSignaturePSSSHA512:
                return .PSS
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    fileprivate var rsaEncryptionPadding: _RSA.Encryption.Padding {
        get throws {
            switch self {
            case .rsaEncryptionOAEP:
                return .PKCS1_OAEP
            case .rsaEncryptionOAEPSHA256:
                return .PKCS1_OAEP_SHA256
            case .rsaEncryptionOAEPSHA384, .rsaEncryptionOAEPSHA512:
                fallthrough
            case .rsaEncryptionPKCS1:
                fallthrough
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
}
#endif
