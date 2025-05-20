//
//  X509Certificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1
import X509
#if canImport(_CryptoExtras)
import _CryptoExtras
#endif

extension X509.Certificate.PublicKey: Swift.Codable {}

extension Certificate.PublicKey: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        (try? jsonWebKey().storage) ?? .init()
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Certificate.PublicKey {
        let key = AnyJSONWebKey(storage: storage)
        
        switch (key.keyType, key.curve) {
        case (.some(.ellipticCurve), .some(.p256)):
            return try .init(P256.Signing.PublicKey.create(storage: storage))
        case (.some(.ellipticCurve), .some(.p384)):
            return try .init(P384.Signing.PublicKey.create(storage: storage))
        case (.some(.ellipticCurve), .some(.p521)):
            return try .init(P521.Signing.PublicKey.create(storage: storage))
        case (.some(.octetKeyPair), .some(.ed25519)):
            return try .init(Curve25519.Signing.PublicKey.create(storage: storage))
        case (.some(.rsa), _):
#if canImport(CommonCrypto)
            let der = try SecKey.create(storage: storage).externalRepresentation
            return try .init(derEncoded: der)
#elseif canImport(_CryptoExtras)
            return try .init(_RSA.Signing.PublicKey.create(storage: storage))
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try jsonWebKey().verifySignature(signature, for: data, using: algorithm)
    }
    
    /// Generates a key object from the public key inside certificate.
    ///
    /// - Returns: A public key to validate signatures.
    public func jsonWebKey() throws -> any JSONWebValidatingKey {
        guard let key = try AnyJSONWebKey(importing: subjectPublicKeyInfoBytes, format: .spki).specialized() as? any JSONWebValidatingKey else {
            throw JSONWebKeyError.unknownKeyType
        }
        return key
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try jsonWebKey().thumbprint(format: format, using: hashFunction)
    }
}

extension X509.Certificate.PrivateKey: Swift.Codable {}

extension Certificate.PrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage {
        (try? jsonWebKey().storage) ?? .init()
    }
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        switch algorithm {
        case .ecdsaSignatureP256SHA256:
            self.init(P256.Signing.PrivateKey())
        case .ecdsaSignatureP384SHA384:
            self.init(P384.Signing.PrivateKey())
        case .ecdsaSignatureP521SHA512:
            self.init(P521.Signing.PrivateKey())
        case .eddsaSignature, .eddsa25519Signature:
            self.init(Curve25519.Signing.PrivateKey())
        case .rsaSignaturePSSSHA256, .rsaSignaturePSSSHA384, .rsaSignaturePSSSHA512,
             .rsaSignaturePKCS1v15SHA256, .rsaSignaturePKCS1v15SHA384, .rsaSignaturePKCS1v15SHA512:
#if canImport(CommonCrypto)
            let secKey = try SecKey(algorithm: algorithm)
            try self.init(secKey)
#elseif canImport(_CryptoExtras)
            try self.init(_RSA.Signing.PrivateKey(keySize: .bits2048))
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Certificate.PrivateKey {
        let key = AnyJSONWebKey(storage: storage)
        
        switch (key.keyType, key.curve) {
        case (.some(.ellipticCurve), .some(.p256)):
            return try .init(P256.Signing.PrivateKey.create(storage: storage))
        case (.some(.ellipticCurve), .some(.p384)):
            return try .init(P384.Signing.PrivateKey.create(storage: storage))
        case (.some(.ellipticCurve), .some(.p521)):
            return try .init(P521.Signing.PrivateKey.create(storage: storage))
        case (.some(.octetKeyPair), .some(.ed25519)):
            return try .init(Curve25519.Signing.PrivateKey.create(storage: storage))
        case (.some(.rsa), _):
#if canImport(CommonCrypto)
            let secKey = try SecKey.create(storage: storage)
            return try Certificate.PrivateKey(secKey)
#elseif canImport(_CryptoExtras)
            return try .init(_RSA.Signing.PrivateKey.create(storage: storage))
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try jsonWebKey().signature(data, using: algorithm)
    }
    
    /// Generates a key object from the public key inside certificate.
    ///
    /// - Returns: A public key to validate signatures.
    public func jsonWebKey() throws -> any JSONWebSigningKey {
        let der = try serializeAsPEM().derBytes
        let pkcs8 = try PKCS8PrivateKey(derEncoded: der)
        switch try (pkcs8.keyType, pkcs8.keyCurve) {
        case (.ellipticCurve, .p256):
            return try P256.Signing.PrivateKey(derRepresentation: der)
        case (.ellipticCurve, .p384):
            return try P384.Signing.PrivateKey(derRepresentation: der)
        case (.ellipticCurve, .p521):
            return try P521.Signing.PrivateKey(derRepresentation: der)
        case (.octetKeyPair, .ed25519):
            return try Curve25519.Signing.PrivateKey(importing: der, format: .pkcs8)
        case (.rsa, _):
#if canImport(CommonCrypto)
            return try SecKey(derRepresentation: Data(der), keyType: .rsa)
#elseif canImport(_CryptoExtras)
            return try _RSA.Signing.PrivateKey(derRepresentation: der)
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try publicKey.jsonWebKey().thumbprint(format: format, using: hashFunction)
    }
}

extension DERImplicitlyTaggable {
    /// Initializes a DER serializable object from given data.
    ///
    /// - Parameter derEncoded: DER encoded object.
    @usableFromInline
    init<D>(derEncoded: D) throws where D: DataProtocol {
        try self.init(derEncoded: [UInt8](derEncoded))
    }
    
    /// DER serialized data representation of object.
    @usableFromInline
    var derRepresentation: Data {
        get throws {
            var derSerializer = DER.Serializer()
            try serialize(into: &derSerializer)
            return Data(derSerializer.serializedBytes)
        }
    }
}

extension X509.Certificate: Swift.Codable {}

extension Certificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        var key = AnyJSONWebKey(storage: publicKey.storage)
        key.certificateChain = [self]
        return key.storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Certificate {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first else {
            throw JSONWebKeyError.keyNotFound
        }
        return certificate
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}

extension Certificate: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        if currentDate > notValidAfter {
            throw JSONWebValidationError.tokenExpired(expiry: notValidAfter)
        }
        if currentDate < notValidBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notValidBefore)
        }
    }
}
