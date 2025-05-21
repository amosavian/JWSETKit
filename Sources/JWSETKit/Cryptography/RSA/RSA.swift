//
//  RSA.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

#if canImport(_CryptoExtras)
import _CryptoExtras
import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

extension _CryptoExtras._RSA.Signing.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Codable {}

extension _RSA.Signing.PublicKey: JSONWebValidatingKey, JSONWebKeyRSAType {
    public var storage: JSONWebValueStorage {
        // `pkcs1DERRepresentation` is always a valid ASN1 object and it should not fail.
        try! RSAHelper.rsaWebKey(pkcs1: pkcs1DERRepresentation).storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Signing.PublicKey {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent else {
            throw CryptoKitError.incorrectParameterSize
        }
        return try .init(n: modulus, e: exponent)
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

extension _CryptoExtras._RSA.Signing.PublicKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
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
        case .spki:
            return derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension _CryptoExtras._RSA.Signing.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Codable {}

extension _RSA.Signing.PrivateKey: JSONWebSigningKey, JSONWebKeyRSAType {
    public var storage: JSONWebValueStorage {
        get {
            // `derRepresentation` is always a valid ASN1 object and it should not fail.
            try! RSAHelper.rsaWebKey(pkcs1: derRepresentation).storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(keySize: .init(bitCount: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount))
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Signing.PrivateKey {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent, let privateExponent = key.privateExponent, let p = key.firstPrimeFactor, let q = key.secondPrimeFactor else {
            throw CryptoKitError.incorrectParameterSize
        }
        return try .init(n: modulus, e: exponent, d: privateExponent, p: p, q: q)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        guard let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try signature(for: hashFunction.hash(data: data), padding: algorithm.rsaPadding).rawRepresentation
    }
    
    public static func == (lhs: _RSA.Signing.PrivateKey, rhs: _RSA.Signing.PrivateKey) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension _CryptoExtras._RSA.Signing.PrivateKey: JSONWebKeyImportable, JSONWebKeyExportable {
    var pkcs8Representation: Data {
        // PEM is always a valid Bas64.
        Data(base64Encoded: pkcs8PEMRepresentation
            .components(separatedBy: .whitespacesAndNewlines)
            .dropFirst().dropLast().joined(), options: [.ignoreUnknownCharacters]).unsafelyUnwrapped
    }
    
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
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
        case .pkcs8:
            return pkcs8Representation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension _CryptoExtras._RSA.Encryption.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Codable {}

extension _RSA.Encryption.PublicKey: JSONWebEncryptingKey, JSONWebKeyRSAType {
    public var storage: JSONWebValueStorage {
        get {
            // `pkcs1DERRepresentation` is always a valid ASN1 object and it should not fail.
            try! RSAHelper.rsaWebKey(pkcs1: pkcs1DERRepresentation).storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Encryption.PublicKey {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent else {
            throw CryptoKitError.incorrectParameterSize
        }
        return try .init(n: modulus, e: exponent)
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

extension _CryptoExtras._RSA.Encryption.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Codable {}

extension _RSA.Encryption.PrivateKey: JSONWebDecryptingKey, JSONWebKeyRSAType {
    public var storage: JSONWebValueStorage {
        get {
            // `derRepresentation` is always a valid ASN1 object and it should not fail.
            try! RSAHelper.rsaWebKey(pkcs1: derRepresentation).storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(keySize: .bits2048)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Encryption.PrivateKey {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent, let privateExponent = key.privateExponent, let p = key.firstPrimeFactor, let q = key.secondPrimeFactor else {
            throw CryptoKitError.incorrectParameterSize
        }
        return try .init(n: modulus, e: exponent, d: privateExponent, p: p, q: q)
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try decrypt(data, padding: algorithm.rsaEncryptionPadding)
    }
    
    public static func == (lhs: _RSA.Encryption.PrivateKey, rhs: _RSA.Encryption.PrivateKey) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
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
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
}
#endif
