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

extension DERImplicitlyTaggable {
    /// Initializes a DER serializable object from given data.
    ///
    /// - Parameter derEncoded: DER encoded object.
    init<D>(derEncoded: D) throws where D: DataProtocol {
        try self.init(derEncoded: [UInt8](derEncoded))
    }
    
    /// DER serialized data representation of object.
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
