//
//  SecKey.swift
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
        
        let attributes: [CFString: Any] =
            [
                kSecAttrKeyType: keyType,
                kSecAttrKeySizeInBits: length,
            ]
        
        return try handle { error in
            SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        }
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
                [xCoordinate, yCoordinate, key.privateKey].compactMap { $0 })
        case .rsa:
            let pkcs1 = try JSONWebRSAPublicKey.pkcs1Representation(key)
            
            let keyClass = key.privateExponent != nil ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic
            let length = key.modulus!.count * 8
            let attributes: [CFString: Any] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: keyClass,
                kSecAttrKeySizeInBits: length,
            ]
            return try handle { error in
                SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &error)
            }
        default:
            throw JSONWebKeyError.unknownKeyType
        }
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
        
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: length,
        ]
        return try handle { error in
            SecKeyCreateWithData((Data([0x04]) + components.joined()) as CFData, attributes as CFDictionary, &error)
        }
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
    
    private static func rsaWebKey(data: Data) throws -> any JSONWebKey {
        let components = try JSONWebRSAPublicKey.rsaComponents(data)
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
                data[0 ..< (length / 3)],
                data[(length / 3) ..< (2 * length / 3)],
                data[(2 * length / 3)...],
            ]
        } else {
            return [
                data[0 ..< (length / 2)],
                data[(length / 2)...],
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
        let keyData = try handle { error in
            SecKeyCopyExternalRepresentation(self, &error)
        } as Data
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
        .ecdsaSignatureP521SHA512: .ecdsaSignatureMessageX962SHA512,
        .rsaSignaturePKCS1v15SHA256: .rsaSignatureMessagePKCS1v15SHA256,
        .rsaSignaturePKCS1v15SHA384: .rsaSignatureMessagePKCS1v15SHA384,
        .rsaSignaturePKCS1v15SHA512: .rsaSignatureMessagePKCS1v15SHA512,
        .rsaSignaturePSSSHA256: .rsaSignatureMessagePSSSHA256,
        .rsaSignaturePSSSHA384: .rsaSignatureMessagePSSSHA384,
        .rsaSignaturePSSSHA512: .rsaSignatureMessagePSSSHA512,
    ]
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        let result = try handle { error in
            SecKeyVerifySignature(
                self, secAlgorithm,
                Data(data) as CFData, Data(signature) as CFData,
                &error
            )
        }
        if !result {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension SecKey: JSONWebSigningKey {
    public func signature<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try handle { error in
            SecKeyCreateSignature(self, secAlgorithm, Data(data) as CFData, &error)
        } as Data
    }
}

extension SecKey: JSONWebDecryptingKey {
    fileprivate static let encAlgorithms: [JSONWebAlgorithm: SecKeyAlgorithm] = [
        .rsaEncryptionPKCS1: .rsaEncryptionPKCS1,
        .rsaEncryptionOAEP: .rsaEncryptionOAEPSHA1,
        .rsaEncryptionOAEPSHA256: .rsaEncryptionOAEPSHA256,
        .rsaEncryptionOAEPSHA384: .rsaEncryptionOAEPSHA384,
        .rsaEncryptionOAEPSHA512: .rsaEncryptionOAEPSHA512,
    ]
    
    public func decrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data where D: DataProtocol {
        guard let secAlgorithm = Self.encAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try handle { error in
            SecKeyCreateDecryptedData(self, secAlgorithm, Data(data) as CFData, &error)
        } as Data
    }
    
    public func encrypt<D>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> SealedData where D: DataProtocol {
        guard let secAlgorithm = Self.encAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        
        let result = try handle { error in
            SecKeyCreateEncryptedData(self, secAlgorithm, Data(data) as CFData, &error)
        }
        return .init(ciphertext: result as Data)
    }
}

fileprivate func handle<T>(_ closure: (_ error: inout Unmanaged<CFError>?) -> T?) throws -> T {
    var error: Unmanaged<CFError>?
    let result = closure(&error)
    if let error = error?.takeRetainedValue() {
        throw error
    }
    guard let unWrapped = result else {
        throw CryptoKitError.underlyingCoreCryptoError(error: 0)
    }
    return unWrapped
}
#endif
