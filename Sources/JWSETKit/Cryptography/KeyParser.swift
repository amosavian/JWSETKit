//
//  KeyParser.swift
//
//
//  Created by Amir Abbas Mousavian on 9/8/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import SwiftASN1

extension AnyJSONWebKey {
    /// Returns related specific type with available capabilities like signing,
    /// verify encrypting and decrypting regarding key type (`kty`) and curve.
    ///
    /// Returning type:
    ///   - `JSONWebRSAPublicKey` if key type is `RSA` and private key is **not** present.
    ///   - `JSONWebRSAPrivateKey` if key type is `RSA` and private key is present.
    ///   - `JSONWebECPublicKey`  if key type is `EC` and private key is **not** present.
    ///   - `JSONWebECPrivateKey` if key type is `EC` and private key is present.
    ///   - `JSONWebKeyHMAC` if key type is `oct` and algorithm is `HS256/384/512`.
    ///   - `JSONWebKeyAESGCM` if key type is `oct` and algorithm is `AEDGCM256/384/512`.
    ///   - `CryptKit.Symmetric` if key type is `oct` and no algorithm is present.
    public func specialized() throws -> any JSONWebKey {
        // swiftformat:disable:next redundantSelf
        guard let keyType = self.keyType else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        
        // swiftformat:disable:next redundantSelf
        switch (keyType, self.algorithm) {
        case (.ellipticCurve, _):
            // swiftformat:disable:next redundantSelf
            if self.privateKey != nil {
                return try JSONWebECPrivateKey.create(storage: storage)
            } else {
                return try JSONWebECPublicKey.create(storage: storage)
            }
        case (.rsa, _):
            // swiftformat:disable:next redundantSelf
            if self.privateExponent != nil {
                return try JSONWebRSAPrivateKey.create(storage: storage)
            } else {
                return try JSONWebRSAPublicKey.create(storage: storage)
            }
        case (.symmetric, .aesEncryptionGCM128),
             (.symmetric, .aesEncryptionGCM192),
             (.symmetric, .aesEncryptionGCM256):
            return try JSONWebKeyAESGCM.create(storage: storage)
        case (.symmetric, .aesKeyWrap128),
             (.symmetric, .aesKeyWrap192),
             (.symmetric, .aesKeyWrap256):
            if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
                return try JSONWebKeyAESKW.create(storage: storage)
            } else {
                throw JSONWebKeyError.unknownKeyType
            }
        case (.symmetric, .aesEncryptionCBC128SHA256),
             (.symmetric, .aesEncryptionCBC192SHA384),
             (.symmetric, .aesEncryptionCBC256SHA512):
            return try JSONWebKeyAESCBCHMAC.create(storage: storage)
        case (.symmetric, .hmacSHA256):
            return try JSONWebKeyHMAC<SHA256>.create(storage: storage)
        case (.symmetric, .hmacSHA384):
            return try JSONWebKeyHMAC<SHA384>.create(storage: storage)
        case (.symmetric, .hmacSHA512):
            return try JSONWebKeyHMAC<SHA512>.create(storage: storage)
        case (.symmetric, _):
            return try SymmetricKey.create(storage: storage)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    /// Deserializes JSON and converts to the most appropriate key.
    ///
    /// - Parameter jsonWebKey: JWK in JSON string.
    /// - Returns: Related specific key object.
    public static func deserialize(_ jsonWebKey: Data) throws -> any JSONWebKey {
        let webKey = try JSONDecoder().decode(AnyJSONWebKey.self, from: jsonWebKey)
        return try webKey.specialized()
    }
}

extension [any JSONWebKey] {
    func bestMatch(for algorithm: any JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        guard let keyType = algorithm.keyType else { return nil }
        let candidates = filter {
            $0.keyType == keyType && $0.curve == algorithm.curve
        }
        if let key = candidates.first(where: { $0.keyId == id }) {
            return key
        } else {
            return candidates.first
        }
    }
}

extension [any JSONWebSigningKey] {
    func bestMatch(for algorithm: any JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        (self as [any JSONWebKey]).bestMatch(for: algorithm, id: id) as? Self.Element
    }
}

extension [any JSONWebValidatingKey] {
    func bestMatch(for algorithm: any JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        (self as [any JSONWebKey]).bestMatch(for: algorithm, id: id) as? Self.Element
    }
}

extension [any JSONWebDecryptingKey] {
    func bestMatch(for algorithm: any JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        (self as [any JSONWebKey]).bestMatch(for: algorithm, id: id) as? Self.Element
    }
}

extension [any JSONWebEncryptingKey] {
    func bestMatch(for algorithm: any JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        (self as [any JSONWebKey]).bestMatch(for: algorithm, id: id) as? Self.Element
    }
}

extension [any JSONWebSealingKey] {
    func bestMatch(for algorithm: any JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        (self as [any JSONWebKey]).bestMatch(for: algorithm, id: id) as? Self.Element
    }
}
