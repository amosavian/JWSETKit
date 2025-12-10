//
//  SecKey.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(CommonCrypto)
import CommonCrypto
import CryptoKit
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

extension Security.SecKey: Swift.Decodable, Swift.Encodable {}

extension SecKey: JSONWebKeyRSAType, JSONWebKeyCurveType {
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
    
    /// Gets the public key associated with the given private key.
    ///
    /// The returned public key may be self if the app that created the private key didn’t
    /// also store the corresponding public key in the keychain,
    /// or if the system can’t reconstruct the corresponding public key.
    /// - Returns: The public key corresponding to the given private key.
    public var publicKey: SecKey {
        SecKeyCopyPublicKey(self) ?? self
    }
    
    /// Returns an external representation of the given key suitable for the key’s type.
    ///
    /// The operation fails if the key is not exportable, for example if it is bound to a smart card or to the Secure Enclave.
    /// It also fails in macOS if the key has the attribute kSecKeyExtractable set to false.
    ///
    /// The method returns data in the PKCS #1 format for an RSA key.
    /// For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string
    /// of 04 || X || Y. For an elliptic curve private key,
    /// the output is formatted as the public key concatenated with the big endian encoding of the secret scalar,
    /// or 04 || X || Y || K. All of these representations use constant size integers, including leading zeros as needed.
    ///
    /// - Throws: If the key is not exportable.
    /// - Returns: A data object representing the key in a format suitable for the key type.
    public var externalRepresentation: Data {
        get throws {
            try handle { error in
                SecKeyCopyExternalRepresentation(self, &error) as? Data
            }
        }
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
    
    fileprivate static func createKeyFromComponents(_ key: AnyJSONWebKey) throws -> SecKey {
        guard let type = key.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        switch type {
        case .ellipticCurve:
            let ecKey: some (MutableJSONWebKey & JSONWebKeyCurveType) = key
            guard let xCoordinate = key.xCoordinate, let yCoordinate = key.yCoordinate else {
                throw CryptoKitError.incorrectKeySize
            }
            return try Self.createECFromComponents(
                [xCoordinate, yCoordinate, ecKey.privateKey].compactMap { $0 })
        case .rsa:
            let pkcs1 = try RSAHelper.pkcs1Representation(key)
            return try SecKey(derRepresentation: pkcs1, keyType: .rsa)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    private func attribute<T>(_ key: CFString, as _: T.Type) throws -> T? {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
            throw JSONWebKeyError.keyNotFound
        }
        return attributes[key] as? T
    }
    
    private var keyType: JSONWebKeyType {
        get throws {
            let cfKeyType = try attribute(kSecAttrKeyType, as: CFString.self)
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
            guard let size = try attribute(kSecAttrKeySizeInBits, as: Int.self) else {
                throw CryptoKitError.incorrectKeySize
            }
            return size
        }
    }
    
    private var isPrivateKey: Bool {
        get throws {
            try (attribute(kSecAttrKeyClass, as: CFString.self)) == kSecAttrKeyClassPrivate
        }
    }
    
    private var isExtractable: Bool {
        get throws {
            try (attribute(kSecAttrIsExtractable, as: Bool.self)) != false
        }
    }
    
    public static func == (lhs: SecKey, rhs: SecKey) -> Bool {
        guard let lhsData = try? lhs.publicKey.externalRepresentation,
              let rhsData = try? rhs.publicKey.externalRepresentation
        else {
            return false
        }
        return lhsData == rhsData
    }
    
    public func hash(into hasher: inout Hasher) {
        if let value = try? publicKey.externalRepresentation {
            hasher.combine(value)
        }
    }
    
    private func jsonWebKey() throws -> any JSONWebKey {
        switch try keyType {
        case .ellipticCurve:
            return try ECHelper.ecWebKey(data: externalRepresentation, keyLength: keyLength, isPrivateKey: isPrivateKey)
        case .rsa:
            return try RSAHelper.rsaWebKey(pkcs1: externalRepresentation)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    private static func createECFromComponents(_ components: [Data]) throws -> SecKey {
        try SecKey(derRepresentation: Data([0x04]) + components.joined(), keyType: .ellipticCurve)
    }
}

extension JSONWebContainer where Self: SecKey {
    public init(storage: JSONWebValueStorage) throws {
        guard let result = try Self.createKeyFromComponents(.init(storage: storage)) as? Self else {
            throw JSONWebKeyError.unknownKeyType
        }
        self = result
    }
}

extension SecKey: JSONWebValidatingKey {
    fileprivate static let signingAlgorithms: [JSONWebSignatureAlgorithm: SecKeyAlgorithm] = {
        var result: [JSONWebSignatureAlgorithm: SecKeyAlgorithm] = [
            .rsaSignaturePKCS1v15SHA256: .rsaSignatureDigestPKCS1v15SHA256,
            .rsaSignaturePKCS1v15SHA384: .rsaSignatureDigestPKCS1v15SHA384,
            .rsaSignaturePKCS1v15SHA512: .rsaSignatureDigestPKCS1v15SHA512,
            .rsaSignaturePSSSHA256: .rsaSignatureDigestPSSSHA256,
            .rsaSignaturePSSSHA384: .rsaSignatureDigestPSSSHA384,
            .rsaSignaturePSSSHA512: .rsaSignatureDigestPSSSHA512,
        ]
        if #available(macOS 14, iOS 17, tvOS 17, watchOS 10, *) {
            result[.ecdsaSignatureP256SHA256] = .ecdsaSignatureDigestRFC4754SHA256
            result[.ecdsaSignatureP384SHA384] = .ecdsaSignatureDigestRFC4754SHA384
            result[.ecdsaSignatureP521SHA512] = .ecdsaSignatureDigestRFC4754SHA512
        } else {
            result[.ecdsaSignatureP256SHA256] = .ecdsaSignatureRFC4754
            result[.ecdsaSignatureP384SHA384] = .ecdsaSignatureRFC4754
            result[.ecdsaSignatureP521SHA512] = .ecdsaSignatureRFC4754
        }
        return result
    }()

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
    public init(algorithm: some JSONWebAlgorithm) throws {
        guard let keyType = algorithm.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        let bits: Int
        switch (keyType, algorithm) {
        case (.rsa, _):
            bits = JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount
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
        let secKeyType: CFString
        switch keyType {
        case .rsa:
            secKeyType = kSecAttrKeyTypeRSA
        case .ellipticCurve:
            secKeyType = kSecAttrKeyTypeECSECPrimeRandom
        default:
            throw JSONWebKeyError.unknownKeyType
        }
        
        let type = (try? RSAHelper.DERType(keyData: derRepresentation)) ?? .pkcs1PrivateKey
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: secKeyType,
            kSecAttrKeyClass: type.isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
        ]
        let key = try? handle { error in
            SecKeyCreateWithData(derRepresentation as CFData, attributes as CFDictionary, &error)
        }
        if let key = key as? Self {
            self = key
            return
        }
        
        guard attributes[kSecAttrKeyClass] as! CFString == kSecAttrKeyClassPrivate else {
            throw JSONWebKeyError.unknownKeyType
        }
        assertionFailure()
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
        .unsafeRSAEncryptionPKCS1: .rsaEncryptionPKCS1,
        .rsaEncryptionOAEP: .rsaEncryptionOAEPSHA1,
        .rsaEncryptionOAEPSHA256: .rsaEncryptionOAEPSHA256,
        .rsaEncryptionOAEPSHA384: .rsaEncryptionOAEPSHA384,
        .rsaEncryptionOAEPSHA512: .rsaEncryptionOAEPSHA512,
    ]
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        guard let secAlgorithm = Self.encAlgorithms[.init(algorithm)] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try handle { error in
            SecKeyCreateDecryptedData(self, secAlgorithm, Data(data) as CFData, &error)
        } as Data
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        guard let secAlgorithm = Self.encAlgorithms[.init(algorithm)] else {
            throw JSONWebKeyError.operationNotAllowed
        }
        
        let result = try handle { error in
            SecKeyCreateEncryptedData(self, secAlgorithm, Data(data) as CFData, &error)
        }
        return result as Data
    }
}

extension JSONWebKeyImportable where Self: SecKey {
    public init(importing key: Data, format: JSONWebKeyFormat) throws {
        switch format {
        case .raw:
            try self.init(derRepresentation: key, keyType: .ellipticCurve)
        case .spki:
            try self.init(derRepresentation: key, keyType: SubjectPublicKeyInfo(derEncoded: key).keyType)
        case .pkcs8:
            try self.init(derRepresentation: key, keyType: PKCS8PrivateKey(derEncoded: key).keyType)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: key)
        }
    }
}

extension SecKey: JSONWebKeyExportable {
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch try (format, keyType, isPrivateKey) {
        case (_, .ellipticCurve, false):
            return try JSONWebECPublicKey(from: self).exportKey(format: format)
        case (_, .ellipticCurve, true):
            return try JSONWebECPrivateKey(from: self).exportKey(format: format)
        case (.spki, .rsa, false):
            return try SubjectPublicKeyInfo(pkcs1: externalRepresentation).derRepresentation
        case (.pkcs8, .rsa, true):
            return try PKCS8PrivateKey(pkcs1: [UInt8](externalRepresentation)).derRepresentation
        case (.jwk, _, _):
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
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
