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
        case (.elipticCurve, _):
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

private let keyTypeTable: [JSONWebAlgorithm: JSONWebKeyType] = [
    .hmacSHA256: .symmetric, .hmacSHA384: .symmetric, .hmacSHA512: .symmetric,
    .aesEncryptionGCM128: .symmetric, .aesEncryptionGCM192: .symmetric, .aesEncryptionGCM256: .symmetric,
    .ecdsaSignatureP256SHA256: .elipticCurve, .ecdsaSignatureP384SHA384: .elipticCurve,
    .ecdsaSignatureP521SHA512: .elipticCurve, .eddsaSignature: .elipticCurve,
    .rsaSignaturePSSSHA256: .rsa, .rsaSignaturePSSSHA384: .rsa, .rsaSignaturePSSSHA512: .rsa,
    .rsaEncryptionPKCS1: .rsa, .rsaSignaturePKCS1v15SHA256: .rsa,
    .rsaSignaturePKCS1v15SHA384: .rsa, .rsaSignaturePKCS1v15SHA512: .rsa,
    .rsaEncryptionOAEP: .rsa, .rsaEncryptionOAEPSHA256: .rsa,
    .rsaEncryptionOAEPSHA384: .rsa, .rsaEncryptionOAEPSHA512: .rsa,
]

private let curveTable: [JSONWebAlgorithm: JSONWebKeyCurve] = [
    .ecdsaSignatureP256SHA256: .p256, .ecdsaSignatureP384SHA384: .p384,
    .ecdsaSignatureP521SHA512: .p521, .eddsaSignature: .ed25519,
]

extension [any JSONWebSigningKey] {
    func bestMatch(for algorithm: JSONWebAlgorithm, id: String? = nil) -> (any JSONWebSigningKey)? {
        guard let keyType = keyTypeTable[algorithm] else { return nil }
        let candidates = filter {
            $0.keyType == keyType && $0.curve == curveTable[algorithm]
        }
        if let key = candidates.first(where: { $0.keyId == id }) {
            return key
        } else {
            return candidates.first
        }
    }
}

extension [any JSONWebValidatingKey] {
    func bestMatch(for algorithm: JSONWebAlgorithm, id: String? = nil) -> (any JSONWebValidatingKey)? {
        guard let keyType = keyTypeTable[algorithm] else { return nil }
        let candidates = filter {
            $0.keyType == keyType && $0.curve == curveTable[algorithm]
        }
        if let key = candidates.first(where: { $0.keyId == id }) {
            return key
        } else {
            return candidates.first
        }
    }
}
