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
import _CryptoExtras

extension Certificate.PublicKey {
    /// Generates a key object from the public key inside certificate.
    ///
    /// - Returns: A public key to validate signatures.
    public func jsonWebKey() throws -> any JSONWebValidatingKey {
        if let key = P256.Signing.PublicKey(self) {
            return key
        } else if let key = P256.Signing.PublicKey(self) {
            return key
        } else if let key = P384.Signing.PublicKey(self) {
            return key
        } else if let key = P521.Signing.PublicKey(self) {
            return key
        } else if let key = _RSA.Signing.PublicKey(self) {
            return key
        } else {
            throw JSONWebKeyError.unknownKeyType
        }
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
        var key = try! AnyJSONWebKey(storage: publicKey.jsonWebKey().storage)
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
        try publicKey.jsonWebKey().verifySignature(signature, for: data, using: algorithm)
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
