//
//  X509Certificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

import Foundation
import SwiftASN1
import X509
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(_CryptoExtras)
import _CryptoExtras
#endif

extension Certificate.PublicKey: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        (try? jsonWebKey().storage) ?? .init()
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> X509.Certificate.PublicKey {
        if let key = try? P256.Signing.PublicKey.create(storage: storage) {
            return .init(key)
        } else if let key = try? P384.Signing.PublicKey.create(storage: storage) {
            return .init(key)
        } else if let key = try? P521.Signing.PublicKey.create(storage: storage) {
            return .init(key)
        }
#if canImport(CommonCrypto)
        if let key = try? SecKey.create(storage: storage).publicKey {
            let der = try handle { error in
                SecKeyCopyExternalRepresentation(key, &error)
            }
            return try .init(derEncoded: der as Data)
        }
#elseif canImport(_CryptoExtras)
        if let key = try? _RSA.Signing.PublicKey.create(storage: storage) {
            return .init(key)
        }
#else
        // This should never happen as CommonCrypto is available on Darwin platforms
        // and CryptoSwift is used on non-Darwin platform.
        fatalError("Unimplemented")
#endif
        throw JSONWebKeyError.unknownKeyType
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try jsonWebKey().verifySignature(signature, for: data, using: algorithm)
    }
    
    /// Generates a key object from the public key inside certificate.
    ///
    /// - Returns: A public key to validate signatures.
    private func jsonWebKey() throws -> any JSONWebValidatingKey {
        if let key = P256.Signing.PublicKey(self) {
            return key
        } else if let key = P384.Signing.PublicKey(self) {
            return key
        } else if let key = P521.Signing.PublicKey(self) {
            return key
        }
#if canImport(CommonCrypto)
        let rsaKey = try? handle { error in
            let attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
            ] as CFDictionary
            return try? SecKeyCreateWithData(derRepresentation as CFData, attributes, &error)
        }
        if let rsaKey {
            return rsaKey
        }
#elseif canImport(_CryptoExtras)
        if let key = _RSA.Signing.PublicKey(self) {
            return key
        }
#else
        // This should never happen as CommonCrypto is available on Darwin platforms
        // and CryptoSwift is used on non-Darwin platform.
        fatalError("Unimplemented")
#endif
        throw JSONWebKeyError.unknownKeyType
    }
}

extension DERImplicitlyTaggable {
    /// Initializes a DER serializable object from give data.
    ///
    /// - Parameter derEncoded: DER encoded object.
    public init(derEncoded: Data) throws {
        try self.init(derEncoded: [UInt8](derEncoded))
    }
    
    /// DER serialized data representation of object.
    public var derRepresentation: Data {
        get throws {
            var derSerializer = DER.Serializer()
            try serialize(into: &derSerializer)
            return Data(derSerializer.serializedBytes)
        }
    }
}

extension Certificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        var key = AnyJSONWebKey(storage: publicKey.storage)
        key.certificateChain = [self]
        return key.storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> X509.Certificate {
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
