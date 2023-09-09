//
//  File.swift
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
    public static func deserialize(jsonWebKey: Data) throws -> any JSONWebKey {
        let webKey = try JSONDecoder().decode(AnyJSONWebKey.self, from: jsonWebKey)
        guard let keyType = webKey.keyType else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        
        switch (keyType, webKey.algorithm) {
        case (.elipticCurve, _):
            if webKey.privateKey != nil {
                return try JSONWebECPrivateKey(jsonWebKey: webKey.storage)
            } else {
                return try JSONWebECPublicKey(jsonWebKey: webKey.storage)
            }
        case (.rsa, _):
            if webKey.privateExponent != nil {
                return try JSONWebRSAPrivateKey(jsonWebKey: webKey.storage)
            } else {
                return try JSONWebRSAPublicKey(jsonWebKey: webKey.storage)
            }
        case (.symmetric, .aesEncryptionGCM128),
            (.symmetric, .aesEncryptionGCM192),
            (.symmetric, .aesEncryptionGCM256):
            return try JSONWebKeyAESGCM(jsonWebKey: webKey.storage)
        case (.symmetric, _):
            return try SymmetricKey(jsonWebKey: webKey.storage)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}
