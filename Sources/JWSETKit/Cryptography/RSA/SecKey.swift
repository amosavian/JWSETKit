//
//  SecKey.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(CommonCrypto)
import CommonCrypto
import CryptoKit
import Foundation
import SwiftASN1

extension SecKey: JSONWebKey {
    public var storage: JSONWebValueStorage {
        try! jsonWebKey().storage
    }
    
    public var publicKey: SecKey {
        SecKeyCopyPublicKey(self)!
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        try createKeyFromComponents(.init(storage: storage)) as! Self
    }
    
    private static func createPairKey(type: JSONWebKeyType, bits length: Int) throws -> SecKey {
        let keyType: CFString
        switch type {
        case .ellipticCurve:
            keyType = kSecAttrKeyTypeECSECPrimeRandom
        case .rsa:
            keyType = kSecAttrKeyTypeRSA
        case .symmetric:
#if os(macOS)
            keyType = kSecAttrKeyTypeAES
#else
            fallthrough
#endif
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
        case .ellipticCurve:
            guard let xCoordinate = key.xCoordinate, let yCoordinate = key.yCoordinate else {
                throw CryptoKitError.incorrectKeySize
            }
            return try Self.createECFromComponents(
                [xCoordinate, yCoordinate, key.privateKey].compactMap { $0 })
        case .rsa:
            let pkcs1 = try RSAHelper.pkcs1Representation(key)
            
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
    
    private var keyType: JSONWebKeyType {
        get throws {
            guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
                throw JSONWebKeyError.keyNotFound
            }
            let cfKeyType = (attributes[kSecAttrKeyType] as? String ?? "") as CFString
            switch cfKeyType {
            case kSecAttrKeyTypeRSA:
                return .rsa
            case kSecAttrKeyTypeEC, kSecAttrKeyTypeECSECPrimeRandom:
                return .ellipticCurve
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
    
    private func jsonWebKey() throws -> any JSONWebKey {
        let keyData = try handle { error in
            SecKeyCopyExternalRepresentation(self, &error)
        } as Data
        switch try keyType {
        case .ellipticCurve:
            return try ECHelper.ecWebKey(data: keyData, isPrivateKey: isPrivateKey)
        case .rsa:
            return try RSAHelper.rsaWebKey(data: keyData)
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
}

extension SecKey: JSONWebValidatingKey {
    fileprivate static let signingAlgorithms: [JSONWebSignatureAlgorithm: SecKeyAlgorithm] = [
        .rsaSignaturePKCS1v15SHA256: .rsaSignatureMessagePKCS1v15SHA256,
        .rsaSignaturePKCS1v15SHA384: .rsaSignatureMessagePKCS1v15SHA384,
        .rsaSignaturePKCS1v15SHA512: .rsaSignatureMessagePKCS1v15SHA512,
        .rsaSignaturePSSSHA256: .rsaSignatureMessagePSSSHA256,
        .rsaSignaturePSSSHA384: .rsaSignatureMessagePSSSHA384,
        .rsaSignaturePSSSHA512: .rsaSignatureMessagePSSSHA512,
    ]
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
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

extension JSONWebSigningKey where Self: SecKey {
    public init(algorithm: any JSONWebAlgorithm) throws {
        let attributes: CFDictionary
        switch algorithm {
        case .rsaEncryptionPKCS1,
                .rsaEncryptionOAEP, .rsaEncryptionOAEPSHA256,
                .rsaEncryptionOAEPSHA384, .rsaEncryptionOAEPSHA384,
                .rsaEncryptionOAEPSHA512, .rsaSignaturePKCS1v15SHA256,
                .rsaSignaturePKCS1v15SHA384, .rsaSignaturePKCS1v15SHA512,
                .rsaSignaturePSSSHA256, .rsaSignaturePSSSHA384,
                .rsaSignaturePSSSHA512:
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: 2048,
            ] as CFDictionary
        case .ecdsaSignatureP256SHA256:
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: 256,
            ] as CFDictionary
        case .ecdsaSignatureP384SHA384:
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: 384,
            ] as CFDictionary
        case .ecdsaSignatureP521SHA512:
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: 521,
            ] as CFDictionary
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
        
        self = try handle { error in
            return SecKeyCreateRandomKey(attributes, &error) as? Self
        }
    }
}

extension SecKey: JSONWebSigningKey {
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try handle { error in
            SecKeyCreateSignature(self, secAlgorithm, Data(data) as CFData, &error)
        } as Data
    }
}

extension SecKey: JSONWebDecryptingKey {
    fileprivate static let encAlgorithms: [JSONWebKeyEncryptionAlgorithm: SecKeyAlgorithm] = [
        .rsaEncryptionPKCS1: .rsaEncryptionPKCS1,
        .rsaEncryptionOAEP: .rsaEncryptionOAEPSHA1,
        .rsaEncryptionOAEPSHA256: .rsaEncryptionOAEPSHA256,
        .rsaEncryptionOAEPSHA384: .rsaEncryptionOAEPSHA384,
        .rsaEncryptionOAEPSHA512: .rsaEncryptionOAEPSHA512,
    ]
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        guard let secAlgorithm = Self.encAlgorithms[.init(algorithm.rawValue)] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try handle { error in
            SecKeyCreateDecryptedData(self, secAlgorithm, Data(data) as CFData, &error)
        } as Data
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        guard let secAlgorithm = Self.encAlgorithms[.init(algorithm.rawValue)] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        
        let result = try handle { error in
            SecKeyCreateEncryptedData(self, secAlgorithm, Data(data) as CFData, &error)
        }
        return result as Data
    }
}

func handle<T>(_ closure: (_ error: inout Unmanaged<CFError>?) -> T?) throws -> T {
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
