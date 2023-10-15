//
//  RSA.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

import Foundation
import SwiftASN1
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import _CryptoExtras

extension _RSA.Signing.PublicKey: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        let components = try! JSONWebRSAPublicKey.rsaComponents(pkcs1DERRepresentation)
        var key = AnyJSONWebKey()
        key.keyType = .rsa
        key.modulus = components[0]
        key.exponent = components[1]
        return key.storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Signing.PublicKey {
        let der = try JSONWebRSAPublicKey.pkcs1Representation(AnyJSONWebKey(storage: storage))
        return try .init(derRepresentation: der)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        var hashFunction = try algorithm.rsaHashFunction.init()
        hashFunction.update(data: data)
        if try !isValidSignature(.init(rawRepresentation: signature), for: hashFunction.finalize(), padding: algorithm.rsaPadding) {
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

extension _RSA.Signing.PrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage {
        get {
            let components = try! JSONWebRSAPublicKey.rsaComponents(derRepresentation)
            var key = AnyJSONWebKey()
            key.keyType = .rsa
            key.modulus = components[1]
            key.exponent = components[2]
            key.privateExponent = components[3]
            key.firstPrimeFactor = components[4]
            key.secondPrimeFactor = components[5]
            key.firstFactorCRTExponent = components[6]
            key.secondFactorCRTExponent = components[7]
            key.firstCRTCoefficient = components[8]
            return key.storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public init() throws {
        try self.init(keySize: .bits2048)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Signing.PrivateKey {
        let der = try JSONWebRSAPublicKey.pkcs1Representation(AnyJSONWebKey(storage: storage))
        return try .init(derRepresentation: der)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        var hashFunction = try algorithm.rsaHashFunction.init()
        hashFunction.update(data: data)
        return try signature(for: hashFunction.finalize(), padding: algorithm.rsaPadding).rawRepresentation
    }
    
    public static func == (lhs: _RSA.Signing.PrivateKey, rhs: _RSA.Signing.PrivateKey) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(derRepresentation)
    }
}

extension _RSA.Encryption.PublicKey: JSONWebEncryptingKey {
    public var storage: JSONWebValueStorage {
        get {
            let components = try! JSONWebRSAPublicKey.rsaComponents(pkcs1DERRepresentation)
            var key = AnyJSONWebKey()
            key.keyType = .rsa
            key.modulus = components[0]
            key.exponent = components[1]
            return key.storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Encryption.PublicKey {
        let der = try JSONWebRSAPublicKey.pkcs1Representation(AnyJSONWebKey(storage: storage))
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
            let components = try! JSONWebRSAPublicKey.rsaComponents(derRepresentation)
            var key = AnyJSONWebKey()
            key.keyType = .rsa
            key.modulus = components[1]
            key.exponent = components[2]
            key.privateExponent = components[3]
            key.firstPrimeFactor = components[4]
            key.secondPrimeFactor = components[5]
            key.firstFactorCRTExponent = components[6]
            key.secondFactorCRTExponent = components[7]
            key.firstCRTCoefficient = components[8]
            return key.storage
        }
        set {
            if let value = try? Self.create(storage: newValue) {
                self = value
            }
        }
    }
    
    public init() throws {
        try self.init(keySize: .bits2048)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> _RSA.Encryption.PrivateKey {
        let der = try JSONWebRSAPublicKey.pkcs1Representation(AnyJSONWebKey(storage: storage))
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
    
    fileprivate var rsaHashFunction: any HashFunction.Type {
        get throws {
            switch self {
            case .rsaSignaturePSSSHA256, .rsaSignaturePKCS1v15SHA256:
                return SHA256.self
            case .rsaSignaturePSSSHA384, .rsaSignaturePKCS1v15SHA384:
                return SHA384.self
            case .rsaSignaturePSSSHA512, .rsaSignaturePKCS1v15SHA512:
                return SHA512.self
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    fileprivate var rsaEncryptionPadding: _RSA.Encryption.Padding {
        get throws {
            switch self {
            case .rsaEncryptionOAEP, .rsaEncryptionOAEPSHA256, .rsaEncryptionOAEPSHA384, .rsaEncryptionOAEPSHA512:
                return .PKCS1_OAEP
            case .rsaEncryptionPKCS1:
                fallthrough
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
}
