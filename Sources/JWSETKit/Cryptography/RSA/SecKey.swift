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
        if let storage = try? jsonWebKey().storage {
            return storage
        } else {
            // Key is not accessible directly, e.g. stored in Secure Enclave.
            //
            // In order to get key type and other necessary information in signing
            // process, public key is returned which contains these values.
            return publicKey.storage
        }
    }
    
    public var publicKey: SecKey {
        SecKeyCopyPublicKey(self) ?? self
    }
    
    public var externalRepresentation: Data {
        get throws {
            try handle { error in
                SecKeyCopyExternalRepresentation(self, &error) as? Data
            }
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        guard let result = try createKeyFromComponents(.init(storage: storage)) as? Self else {
            throw JSONWebKeyError.unknownKeyType
        }
        return result
    }
    
    fileprivate static func createPairKey(type: JSONWebKeyType, bits length: Int) throws -> SecKey {
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
            return try SecKey(derRepresentation: pkcs1, keyType: .rsa)
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
        switch try keyType {
        case .ellipticCurve:
            return try ECHelper.ecWebKey(data: externalRepresentation, keyLength: keyLength, isPrivateKey: isPrivateKey)
        case .rsa:
            return try RSAHelper.rsaWebKey(data: externalRepresentation)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    private static func createECFromComponents(_ components: [Data]) throws -> SecKey {
        try SecKey(derRepresentation: Data([0x04]) + components.joined(), keyType: .ellipticCurve)
    }
}

extension SecKey: JSONWebValidatingKey {
    fileprivate static let signingAlgorithms: [JSONWebSignatureAlgorithm: SecKeyAlgorithm] = [
        .ecdsaSignatureP256SHA256: .ecdsaSignatureRFC4754,
        .ecdsaSignatureP384SHA384: .ecdsaSignatureRFC4754,
        .ecdsaSignatureP521SHA512: .ecdsaSignatureRFC4754,
        .rsaSignaturePKCS1v15SHA256: .rsaSignatureDigestPKCS1v15SHA256,
        .rsaSignaturePKCS1v15SHA384: .rsaSignatureDigestPKCS1v15SHA384,
        .rsaSignaturePKCS1v15SHA512: .rsaSignatureDigestPKCS1v15SHA512,
        .rsaSignaturePSSSHA256: .rsaSignatureDigestPSSSHA256,
        .rsaSignaturePSSSHA384: .rsaSignatureDigestPSSSHA384,
        .rsaSignaturePSSSHA512: .rsaSignatureDigestPSSSHA512,
    ]

    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm], let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.operationNotAllowed
        }

        let digest = hashFunction.hash(data: data).data
        let result = try handle { error in
            SecKeyVerifySignature(
                self.publicKey, secAlgorithm,
                digest as CFData, Data(signature) as CFData,
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
        guard let keyType = algorithm.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        let bits: Int
        switch (keyType, algorithm) {
        case (.rsa, _):
            bits = 2048
        case (_, .ecdsaSignatureP256SHA256):
            bits = 256
        case (_, .ecdsaSignatureP384SHA384):
            bits = 384
        case (_, .ecdsaSignatureP521SHA512):
            bits = 521
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let result = try Self.createPairKey(type: keyType, bits: bits) as? Self else {
            throw JSONWebKeyError.operationNotAllowed
        }
        self = result
    }
    
    public init(rsaBitCounts bits: Int) throws {
        guard let result = try Self.createPairKey(type: .rsa, bits: bits) as? Self else {
            throw JSONWebKeyError.operationNotAllowed
        }
        self = result
    }
    
    public init(derRepresentation: Data, keyType: JSONWebKeyType) throws {
        var derRepresentation = derRepresentation
        let secKeyType: CFString
        switch keyType {
        case .rsa:
            secKeyType = kSecAttrKeyTypeRSA
        case .ellipticCurve:
            secKeyType = kSecAttrKeyTypeECSECPrimeRandom
            if derRepresentation.count.isMultiple(of: 2) {
                derRepresentation.insert(0x04, at: 0)
            }
        default:
            throw JSONWebKeyError.unknownKeyType
        }
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: secKeyType,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        let privateKey = try? handle { error in
            SecKeyCreateWithData(derRepresentation as CFData, attributes as CFDictionary, &error)
        }
        if let privateKey = privateKey as? Self {
            self = privateKey
            return
        }
        attributes[kSecAttrKeyClass] = kSecAttrKeyClassPublic
        let publicKey = try handle { error in
            SecKeyCreateWithData(derRepresentation as CFData, attributes as CFDictionary, &error)
        }
        if let publicKey = publicKey as? Self {
            self = publicKey
            return
        }
        throw JSONWebKeyError.unknownKeyType
    }
}

extension SecKey: JSONWebSigningKey {
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        guard let secAlgorithm = Self.signingAlgorithms[algorithm], let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.operationNotAllowed
        }

        let digest = hashFunction.hash(data: data).data

        return try handle { error in
            SecKeyCreateSignature(self, secAlgorithm, digest as CFData, &error)
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
