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

public enum JSONWebKeyCoder {
    public static func deserialize(jsonWebKey: Data) throws -> any JSONWebKey {
        let webKey = try JSONDecoder().decode(JSONWebKeyData.self, from: jsonWebKey)
        guard let keyType = webKey.keyType else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        
        switch (keyType, webKey.algorithm) {
        case (.elipticCurve, _):
            fatalError()
        case (.rsa, _):
            fatalError()
        case (.symmetric, _):
            return try SymmetricKey(jsonWebKey: webKey.storage)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    static func deserializeEC(jsonWebKey: JSONWebKeyData) throws -> any JSONWebKey {
        let curve = jsonWebKey.curve ?? .init(rawValue: "")
        switch curve {
        case .p256:
            fatalError()
        case .p384:
            fatalError()
        case .p521:
            fatalError()
        case .ed25519:
            fatalError()
        case .x25519:
            fatalError()
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}
