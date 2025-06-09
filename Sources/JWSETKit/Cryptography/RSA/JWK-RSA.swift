//
//  JWK-RSA.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1
#if canImport(CommonCrypto)
import CommonCrypto
#endif
#if canImport(_CryptoExtras)
import _CryptoExtras
#endif
#if canImport(CryptoSwift)
import CryptoSwift
#endif

/// JSON Web Key (JWK) container for RSA public keys.
@frozen
public struct JSONWebRSAPublicKey: MutableJSONWebKey, JSONWebKeyRSAType, JSONWebValidatingKey, JSONWebEncryptingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public var derRepresentation: Data {
        get throws {
#if canImport(CommonCrypto)
            return try SecKey(from: self).exportKey(format: .spki)
#elseif canImport(_CryptoExtras)
            return try _RSA.Signing.PublicKey(from: self).exportKey(format: .spki)
#else
            #error("Unimplemented")
#endif
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init<D>(derRepresentation: D) throws where D: DataProtocol {
#if canImport(CommonCrypto)
        self.storage = try SecKey(derRepresentation: Data(derRepresentation), keyType: .rsa).storage
#elseif canImport(_CryptoExtras)
        self.storage = try _RSA.Signing.PublicKey(derRepresentation: derRepresentation).storage
#else
        #error("Unimplemented")
#endif
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
#if canImport(CommonCrypto)
        return try SecKey(from: self).verifySignature(signature, for: data, using: algorithm)
#elseif canImport(_CryptoExtras)
        return try _RSA.Signing.PublicKey(from: self).verifySignature(signature, for: data, using: algorithm)
#else
        #error("Unimplemented")
#endif
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
#if canImport(CommonCrypto)
        return try SecKey(from: self).encrypt(data, using: algorithm)
#elseif canImport(CryptoSwift) && canImport(_CryptoExtras)
        if algorithm == .unsafeRSAEncryptionPKCS1 {
            return try CryptoSwift.RSA(from: self).encrypt(data, using: algorithm)
        } else {
            return try _RSA.Encryption.PublicKey(from: self).encrypt(data, using: algorithm)
        }
#elseif canImport(_CryptoExtras)
        return try _RSA.Encryption.PublicKey(from: self).encrypt(data, using: algorithm)
#else
        #error("Unimplemented")
#endif
    }
}

extension JSONWebRSAPublicKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .spki:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
            try validate()
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .spki:
            return try derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

/// JWK container for RSA private keys.
public struct JSONWebRSAPrivateKey: MutableJSONWebKey, JSONWebKeyRSAType, JSONWebSigningKey, JSONWebDecryptingKey, Sendable {
    @frozen
    public struct KeySize {
        public let bitCount: Int

        /// RSA key size of 2048 bits
        public static let bits2048 = KeySize(bitCount: 2048)

        /// RSA key size of 3072 bits
        public static let bits3072 = KeySize(bitCount: 3072)

        /// RSA key size of 4096 bits
        public static let bits4096 = KeySize(bitCount: 4096)
        
        static let defaultKeyLength = bits2048

        /// RSA key size with a custom number of bits.
        ///
        /// Params:
        ///     - bitsCount: Positive integer that is a multiple of 8.
        public init(bitCount: Int) {
            precondition(bitCount % 8 == 0 && bitCount > 0)
            self.bitCount = bitCount
        }
    }
    
    public var storage: JSONWebValueStorage
    
    public var publicKey: JSONWebRSAPublicKey {
        var result = AnyJSONWebKey(storage: storage)
        result.privateExponent = nil
        result.firstPrimeFactor = nil
        result.secondPrimeFactor = nil
        result.firstFactorCRTExponent = nil
        result.secondFactorCRTExponent = nil
        result.firstCRTCoefficient = nil
        return try! .init(from: result)
    }
    
    public var derRepresentation: Data {
        get throws {
#if canImport(CommonCrypto)
            return try SecKey(from: self).exportKey(format: .pkcs8)
#elseif canImport(_CryptoExtras)
            return try _RSA.Signing.PublicKey(from: self).exportKey(format: .pkcs8)
#else
            #error("Unimplemented")
#endif
        }
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(keySize: .defaultKeyLength)
    }
    
    public init(keySize: KeySize) throws {
#if canImport(CommonCrypto)
        self.storage = try SecKey(rsaBitCounts: keySize.bitCount).storage
#elseif canImport(_CryptoExtras)
        self.storage = try _RSA.Signing.PrivateKey(keySize: .init(bitCount: keySize.bitCount)).storage
#else
        #error("Unimplemented")
#endif
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init<D>(derRepresentation: D) throws where D: DataProtocol {
#if canImport(CommonCrypto)
        self.storage = try SecKey(derRepresentation: Data(derRepresentation), keyType: .rsa).storage
#elseif canImport(_CryptoExtras)
        self.storage = try _RSA.Signing.PrivateKey(derRepresentation: derRepresentation).storage
#else
        #error("Unimplemented")
#endif
    }
    
    public func validate() throws {
        try checkRequiredFields("n", "e", "d", "p", "q", "dp", "dq")
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
#if canImport(CommonCrypto)
        return try SecKey(from: self).signature(data, using: algorithm)
#elseif canImport(_CryptoExtras)
        return try _RSA.Signing.PrivateKey(from: self).signature(data, using: algorithm)
#else
        #error("Unimplemented")
#endif
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
#if canImport(CommonCrypto)
        return try SecKey(from: self).decrypt(data, using: algorithm)
#elseif canImport(CryptoSwift) && canImport(_CryptoExtras)
        if algorithm == .unsafeRSAEncryptionPKCS1 {
            return try CryptoSwift.RSA(from: self).decrypt(data, using: algorithm)
        } else {
            return try _RSA.Encryption.PrivateKey(from: self).decrypt(data, using: algorithm)
        }
#elseif canImport(_CryptoExtras)
        return try _RSA.Encryption.PrivateKey(from: self).decrypt(data, using: algorithm)
#else
        #error("Unimplemented")
#endif
    }
}

extension JSONWebRSAPrivateKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .pkcs8:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
            try validate()
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .pkcs8:
            return try derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

enum RSAHelper {
    enum DERType {
        case pkcs1PrivateKey
        case pkcs1PublicKey
        case pkcs8PrivateKey
        case subjectPublicKey
        
        var isPublic: Bool {
            switch self {
            case .pkcs1PrivateKey, .pkcs8PrivateKey:
                false
            case .pkcs1PublicKey, .subjectPublicKey:
                true
            }
        }
        
        init?(keyData data: Data) {
            do {
                let der = try DER.parse([UInt8](data))
                guard der.identifier == .sequence, let rootNodes = der.content.sequence else {
                    throw CryptoKitASN1Error.unexpectedFieldType
                }
                guard rootNodes.count >= 2 else {
                    throw CryptoKitASN1Error.invalidASN1Object
                }
                
                // Private keys start with an INTEGER version field.
                // PKCS#8 Private Key second element is a SEQUENCE (algorithm identifier)
                // PKCS#1 Public Key is a SEQUENCE of two INTEGERs (modulus and exponent).
                switch (rootNodes[0].identifier, rootNodes[1].identifier) {
                case (.sequence, .bitString):
                    self = .subjectPublicKey
                    return
                case (.integer, .sequence) where rootNodes[0].content.primitive == [0x00]:
                    self = .pkcs8PrivateKey
                    return
                case (.integer, .integer):
                    self = rootNodes[0].content.primitive == [0x00] ? .pkcs1PrivateKey : .pkcs1PublicKey
                    return
                default:
                    break
                }
            } catch {}
            
            return nil
        }
    }
    
    private static func pkcs1Integers(_ data: Data) throws -> [Data] {
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
            return Data(data)
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
    
    static func rsaWebKey(pkcs1: Data) throws -> any JSONWebKey {
        let components = try pkcs1Integers(pkcs1)
        var key = AnyJSONWebKey()
        key.keyType = .rsa
        if components[0] == Data([0x00]), components.count >= 9 {
            key.modulus = components[1]
            key.exponent = components[2]
            key.privateExponent = components[3]
            key.firstPrimeFactor = components[4]
            key.secondPrimeFactor = components[5]
            key.firstFactorCRTExponent = components[6]
            key.secondFactorCRTExponent = components[7]
            key.firstCRTCoefficient = components[8]
            return try JSONWebRSAPrivateKey(key)
        } else {
            key.modulus = components[0]
            key.exponent = components[1]
            return try JSONWebRSAPublicKey(key)
        }
    }
}

#if canImport(CryptoSwift)
extension CryptoSwift.RSA: Swift.Hashable, Swift.Codable {}

extension CryptoSwift.RSA: JSONWebDecryptingKey, JSONWebKeyRSAType {
    public var publicKey: CryptoSwift.RSA {
        Self(n: n, e: e)
    }
        
    public var storage: JSONWebValueStorage {
        do {
            if d != nil {
                return try _RSA.Encryption.PrivateKey(derRepresentation: externalRepresentation()).storage
            } else {
                return try _RSA.Encryption.PublicKey(n: n.serialize(), e: e.serialize()).storage
            }
        } catch {
            return .init()
        }
    }
    
    public convenience init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent else {
            throw CryptoKitError.incorrectParameterSize
        }
        if let privateExponent = key.privateExponent,
           let prime1 = key.firstPrimeFactor,
           let prime2 = key.secondPrimeFactor
        {
            try self.init(
                n: .init(modulus),
                e: .init(exponent),
                d: .init(privateExponent),
                p: .init(prime1),
                q: .init(prime2)
            )
        } else {
            self.init(n: .init(modulus), e: .init(exponent))
        }
    }
    
    public convenience init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(keySize: JSONWebRSAPrivateKey.KeySize.defaultKeyLength.bitCount)
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        guard algorithm == .unsafeRSAEncryptionPKCS1 else {
            throw CryptoKitError.incorrectParameterSize
        }
        return try .init(encrypt([UInt8](data), variant: .pksc1v15))
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        guard algorithm == .unsafeRSAEncryptionPKCS1 else {
            throw CryptoKitError.incorrectParameterSize
        }
        let rawDecrypted = try decrypt([UInt8](data), variant: .raw)
        // CryptoSwift only asserts padding and does not throw error. We check the padding manually.
        guard !rawDecrypted.isEmpty, rawDecrypted.starts(with: [0x02]) else {
            throw CryptoKitError.incorrectParameterSize
        }
        let decrypted = Padding.eme_pkcs1v15.remove(from: [0x00] + rawDecrypted, blockSize: keySizeBytes)
        return .init(decrypted)
    }
    
    public static func == (lhs: CryptoSwift.RSA, rhs: CryptoSwift.RSA) -> Bool {
        (try? lhs.publicKey.externalRepresentation()) == (try? rhs.publicKey.externalRepresentation())
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(n)
        hasher.combine(e)
    }
}
#endif
