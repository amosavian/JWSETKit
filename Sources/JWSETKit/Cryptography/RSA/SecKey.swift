//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/9/23.
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

extension SecKey: JSONWebKey {
    public var storage: JSONWebValueStorage {
        get {
            try! jsonWebKey().storage
        }
        set {
            preconditionFailure("Operation not allowed.")
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        try createKeyFromComponents(.init(storage: storage)) as! Self
    }
    
    private static func createPairKey(type: JSONWebKeyType, bits length: Int) throws -> SecKey {
        let keyType: CFString
        switch type {
        case .elipticCurve:
            keyType = kSecAttrKeyTypeECSECPrimeRandom
        case .rsa:
            keyType = kSecAttrKeyTypeRSA
        case .symmetric:
            keyType = kSecAttrKeyTypeAES
        default:
            throw JSONWebKeyError.unknownKeyType
        }
        
        let attributes: [String: Any] =
        [
            kSecAttrKeyType as String: keyType,
            kSecAttrKeySizeInBits as String: length
        ]
        
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        guard let unWrapped = key else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
        return unWrapped
    }
    
    private static func createKeyFromComponents(_ key: AnyJSONWebKey) throws -> SecKey {
        guard let type = key.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        switch type {
        case .elipticCurve:
            guard let xCoordinate = key.xCoordinate, let yCoordinate = key.yCoordinate else {
                throw CryptoKitError.incorrectKeySize
            }
            return try createECFromComponents(
                [xCoordinate, yCoordinate, key.privateKey].compactMap({ $0 }))
        case .rsa:
            guard let modulus = key.modulus, let publicExponent = key.exponent else {
                throw CryptoKitError.incorrectKeySize
            }
            if let privateExponent = key.privateExponent,
               let prime1 = key.firstPrimeFactor,
               let prime2 = key.secondPrimeFactor,
               let exponent1 = key.firstFactorCRTExponent,
               let exponent2 = key.secondFactorCRTExponent,
               let coefficient = key.firstCRTCoefficient {
                return try createRSAFromComponents([
                    Data([0x00]),
                    modulus, publicExponent,
                    privateExponent, prime1, prime2,
                    exponent1, exponent2, coefficient
                ])
            } else {
                return try createRSAFromComponents([modulus, publicExponent])
            }
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    private static func createRSAFromComponents(_ components: [Data]) throws -> SecKey {
        var result = DER.Serializer()
        let keyClass: CFString
        let length: Int
        switch components.count {
        case 2:
            result.append(components, as: .integer)
            keyClass = kSecAttrKeyClassPublic
            length = components[0].count * 8
        case 9:
            result.append(components, as: .integer)
            keyClass = kSecAttrKeyClassPrivate
            length = components[1].count * 8
        default:
            throw JSONWebKeyError.unknownKeyType
        }
        
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: keyClass,
            kSecAttrKeySizeInBits as String: length,
        ]
        let key = SecKeyCreateWithData(Data(result.serializedBytes) as CFData, attributes as CFDictionary, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        guard let unWrapped = key else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
        return unWrapped
    }
    
    private static func createECFromComponents(_ components: [Data]) throws -> SecKey {
        let keyClass: CFString
        let length: Int
        switch components.count {
        case 2:
            keyClass = kSecAttrKeyClassPublic
            length = components[0].count * 8
        case 3:
            keyClass = kSecAttrKeyClassPrivate
            length = components[0].count * 8
        default:
            throw JSONWebKeyError.unknownKeyType
        }
        
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: keyClass,
            kSecAttrKeySizeInBits as String: length,
        ]
        let key = SecKeyCreateWithData((Data([0x04]) + components.joined()) as CFData, attributes as CFDictionary, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        guard let unWrapped = key else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
        return unWrapped
    }
    
    private var keyType: JSONWebKeyType {
        get throws {
            guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
                throw JSONWebKeyError.keyNotFound
            }
            let cfKeyType = (attributes[kSecAttrKeyType] as? String ?? "") as CFString
            switch cfKeyType {
            case kSecAttrKeyTypeRSA:
                return .rsa
            case kSecAttrKeyTypeEC, kSecAttrKeyTypeECDSA, kSecAttrKeyTypeECSECPrimeRandom:
                return .elipticCurve
            default:
                throw JSONWebKeyError.unknownKeyType
            }
        }
    }
    
    private var keyLength: Int {
        get throws {
            guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
                throw JSONWebKeyError.keyNotFound
            }
            guard let size = attributes[kSecAttrKeySizeInBits] as? Int else {
                throw CryptoKitError.incorrectKeySize
            }
            return size
        }
    }
    
    private var isPrivateKey: Bool {
        get throws {
            guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
                throw JSONWebKeyError.keyNotFound
            }
            return (attributes[kSecAttrKeyClass] as? String ?? "") == kSecAttrKeyClassPrivate as String
        }
    }
    
    private static func rsaComponents(_ data: Data) throws -> [Data] {
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
    
    private static func rsaWebKey(data: Data) throws -> any JSONWebKey {
        let components = try rsaComponents(data)
        var key = AnyJSONWebKey()
        switch components.count {
        case 2:
            key.keyType = .rsa
            key.modulus = components[0]
            key.exponent = components[1]
            return JSONWebRSAPublicKey(storage: key.storage)
        case 9:
            key.keyType = .rsa
            key.modulus = components[1]
            key.exponent = components[2]
            key.privateExponent = components[3]
            key.firstPrimeFactor = components[4]
            key.secondPrimeFactor = components[5]
            key.firstFactorCRTExponent = components[6]
            key.secondFactorCRTExponent = components[7]
            key.firstCRTCoefficient = components[8]
            return JSONWebRSAPrivateKey(storage: key.storage)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    private static func ecComponents(_ data: Data, isPrivateKey: Bool) throws -> [Data] {
        let data = data.dropFirst()
        let length = data.count
        if isPrivateKey {
            return [
                data[0..<(length / 3)],
                data[(length / 3)..<((2 * length / 3))],
                data[((2 * length / 3))...]
            ]
        } else {
            return [
                data[0..<(length / 2)],
                data[((length / 2))...]
            ]
        }
    }
    
    private static func ecWebKey(data: Data, isPrivateKey: Bool) throws -> any JSONWebKey {
        let components = try ecComponents(data, isPrivateKey: isPrivateKey)
        var key = AnyJSONWebKey()
        switch components.count {
        case 2:
            key.keyType = .elipticCurve
            key.xCoordinate = components[0]
            key.yCoordinate = components[1]
            return JSONWebECPublicKey(storage: key.storage)
        case 3:
            key.keyType = .elipticCurve
            key.xCoordinate = components[0]
            key.yCoordinate = components[1]
            key.privateKey = components[2]
            return JSONWebECPrivateKey(storage: key.storage)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    private func jsonWebKey() throws -> any JSONWebKey {
        var error: Unmanaged<CFError>?
        let optionalKey = SecKeyCopyExternalRepresentation(self, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        guard let keyData = optionalKey as Data? else {
            throw JSONWebKeyError.keyNotFound
        }
        switch try keyType {
        case .elipticCurve:
            return try Self.ecWebKey(data: keyData, isPrivateKey: isPrivateKey)
        case .rsa:
            return try Self.rsaWebKey(data: keyData)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}

extension SecKey: JSONWebValidatingKey {
    fileprivate static let signingAlgorithms: [JSONWebAlgorithm: SecKeyAlgorithm] = [
        .ecdsaSignatureP256SHA256: .ecdsaSignatureMessageX962SHA256,
        .ecdsaSignatureP384SHA384: .ecdsaSignatureMessageX962SHA384,
        .ecdsaSignatureP512SHA512: .ecdsaSignatureMessageX962SHA512,
        .rsaSignaturePKCS1v15SHA256: .rsaSignatureMessagePKCS1v15SHA256,
        .rsaSignaturePKCS1v15SHA384: .rsaSignatureMessagePKCS1v15SHA384,
        .rsaSignaturePKCS1v15SHA512: .rsaSignatureMessagePKCS1v15SHA512,
        .rsaSignaturePSSSHA256: .rsaSignatureMessagePSSSHA256,
        .rsaSignaturePSSSHA384: .rsaSignatureMessagePSSSHA384,
        .rsaSignaturePSSSHA384: .rsaSignatureMessagePSSSHA384,
    ]
    
    public func validate<D>(_ signature: D, for data: D, using algorithm: JSONWebAlgorithm) throws where D : DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            self, secAlgorithm,
            Data(data) as CFData, Data(signature) as CFData,
            &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        if !result {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension SecKey: JSONWebSigningKey {
    public func sign<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D : DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        var error: Unmanaged<CFError>?
        let sign = SecKeyCreateSignature(self, secAlgorithm, Data(data) as CFData, &error)
        if let error = error?.takeRetainedValue() {
            throw error
        }
        guard let unWrapped = sign else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
        return unWrapped as Data
    }
}
#endif
