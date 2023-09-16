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
