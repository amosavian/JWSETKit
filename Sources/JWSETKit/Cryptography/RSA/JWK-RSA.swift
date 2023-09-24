//
//  JWK-RSA.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
import SwiftASN1
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#else
import _CryptoExtras
#endif

/// JSON Web Key (JWK) container for RSA public keys.
public struct JSONWebRSAPublicKey: JSONWebValidatingKey, JSONWebEncryptingKey {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public init(derRepresentaion: Data) throws {
#if canImport(CommonCrypto)
        let key: SecKey = try handle { error in
            let attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
            ] as CFDictionary
            return SecKeyCreateWithData(derRepresentaion as CFData, attributes, &error)
        }
        self.storage = key.storage
#else
        self.storage = try _RSA.Signing.PublicKey(derRepresentaion: derRepresentaion).storage
#endif
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebRSAPublicKey {
        .init(storage: storage)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey.create(storage: storage).verifySignature(signature, for: data, using: algorithm)
#else
        try _RSA.Signing.PublicKey(jsonWebKey: storage).verifySignature(signature, for: data, using: algorithm)
#endif
    }
    
    public func encrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> SealedData where D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey.create(storage: storage).encrypt(data, using: algorithm)
#else
        try _RSA.Encryption.PublicKey(jsonWebKey: storage).encrypt(data, using: algorithm)
#endif
    }
    
    static func rsaComponents(_ data: Data) throws -> [Data] {
        let der = try DER.parse([UInt8](data))
        guard let nodes = der.content.sequence else {
            throw CryptoKitASN1Error.unexpectedFieldType
        }
        guard nodes.count >= 2 else {
            throw CryptoKitASN1Error.invalidASN1Object
        }
        return try nodes.compactMap {
            guard let data = $0.content.primitive else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }
            return data
        }
    }
    
    static func pkcs1Representation(_ key: AnyJSONWebKey) throws -> Data {
        guard let modulus = key.modulus, let publicExponent = key.exponent else {
            throw CryptoKitError.incorrectKeySize
        }
        let components: [Data]
        if let privateExponent = key.privateExponent,
           let prime1 = key.firstPrimeFactor,
           let prime2 = key.secondPrimeFactor,
           let exponent1 = key.firstFactorCRTExponent,
           let exponent2 = key.secondFactorCRTExponent,
           let coefficient = key.firstCRTCoefficient
        {
            components = [
                Data([0x00]),
                modulus, publicExponent,
                privateExponent, prime1, prime2,
                exponent1, exponent2, coefficient,
            ]
        } else {
            components = [modulus, publicExponent]
        }
        var result = DER.Serializer()
        try result.appendIntegers(components)
        return Data(result.serializedBytes)
    }
}

/// JWK container for RSA private keys.
public struct JSONWebRSAPrivateKey: JSONWebSigningKey, JSONWebDecryptingKey {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public init(derRepresentaion: Data) throws {
#if canImport(CommonCrypto)
        let key: SecKey = try handle { error in
            let attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            ] as CFDictionary
            return SecKeyCreateWithData(derRepresentaion as CFData, attributes, &error)
        }
        self.storage = key.storage
#else
        self.storage = try _RSA.Signing.PrivateKey(derRepresentaion: derRepresentaion).storage
#endif
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebRSAPrivateKey {
        .init(storage: storage)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
#if canImport(CommonCrypto)
        return try SecKey.create(storage: storage).signature(data, using: algorithm)
#else
        try _RSA.Signing.PrivateKey(jsonWebKey: storage).signature(data, using: algorithm)
#endif
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey.create(storage: storage).verifySignature(signature, for: data, using: algorithm)
#else
        try _RSA.Signing.PublicKey.create(storage: storage).verifySignature(signature, for: data, using: algorithm)
#endif
    }
    
    public func encrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> SealedData where D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey.create(storage: storage).encrypt(data, using: algorithm)
#else
        try _RSA.Encryption.PublicKey(jsonWebKey: storage).encrypt(data, using: algorithm)
#endif
    }
    
    public func decrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
#if canImport(CommonCrypto)
        try SecKey.create(storage: storage).decrypt(data, using: algorithm)
#else
        try _RSA.Encryption.PublicKey(jsonWebKey: storage).decrypt(data, using: algorithm)
#endif
    }
}
