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
    ///   - `JSONWebECPublicKey`  if key type is `EC`/`OKP` and private key is **not** present.
    ///   - `JSONWebECPrivateKey` if key type is `EC`/`OKP` and private key is present.
    ///   - `JSONWebKeyHMAC` if key type is `oct` and algorithm is `HS256/384/512`.
    ///   - `JSONWebKeyAESGCM` if key type is `oct` and algorithm is `AEDGCM256/384/512`.
    ///   - `CryptKit.Symmetric` if key type is `oct` and no algorithm is present.
    ///   - `JSONWebCertificateChain` if no key type is present but `x5c` has certificates.
    public func specialized() -> any JSONWebKey {
        for specializer in AnyJSONWebKey.specializers {
            if let specialized = try? specializer.specialize(self) {
                return specialized
            }
        }
        return self
    }
    
    /// Deserializes JSON and converts to the most appropriate key.
    ///
    /// - Parameter jsonWebKey: JWK in JSON string.
    /// - Returns: Related specific key object.
    public static func deserialize(_ data: Data) throws -> any JSONWebKey {
        let webKey = try JSONDecoder().decode(AnyJSONWebKey.self, from: data)
        return webKey.specialized()
    }
}

/// A specializer that can convert a `AnyJSONWebKey` to a specific `JSONWebKey` type.
public protocol JSONWebKeySpecializer {
    /// Specializes a `AnyJSONWebKey` to a specific `JSONWebKey` type, returns nil if key is appropiate.
    ///
    /// - Parameter key: The key to specialize.
    /// - Returns: A specific `JSONWebKey` type, or nil if the key is not appropiate.
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)?
}

enum JSONWebKeyRSASpecializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        guard key.keyType == .rsa else { return nil }
        if key.privateExponent != nil {
            return try JSONWebRSAPrivateKey.create(storage: key.storage)
        } else {
            return try JSONWebRSAPublicKey.create(storage: key.storage)
        }
    }
}

enum JSONWebKeyEllipticCurveSpecializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        guard key.keyType == .ellipticCurve else { return nil }
        guard let curve = key.curve else { return nil }
        switch curve {
        case .p256, .p384, .p521:
            if key.privateKey != nil {
                return try JSONWebECPrivateKey.create(storage: key.storage)
            } else {
                return try JSONWebECPublicKey.create(storage: key.storage)
            }
        default:
            return nil
        }
    }
}

enum JSONWebKeyCurve25519Specializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        guard key.keyType == .octetKeyPair else { return nil }
        guard let curve = key.curve else { return nil }
        switch curve {
        case .ed25519, .x25519:
            if key.privateKey != nil {
                return try JSONWebECPrivateKey.create(storage: key.storage)
            } else {
                return try JSONWebECPublicKey.create(storage: key.storage)
            }
        default:
            return nil
        }
    }
}

enum JSONWebKeySymmetricSpecializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        guard key.keyType == .symmetric else { return nil }
        guard key.keyValue != nil else {
            throw CryptoKitError.incorrectKeySize
        }
        
        switch key.algorithm {
        case .none:
            return try SymmetricKey.create(storage: key.storage)
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM.create(storage: key.storage)
        case .aesKeyWrap128, .aesKeyWrap192, .aesKeyWrap256:
            return try JSONWebKeyAESKW.create(storage: key.storage)
        case .aesEncryptionCBC128SHA256, .aesEncryptionCBC192SHA384, .aesEncryptionCBC256SHA512:
            return try JSONWebKeyAESCBCHMAC.create(storage: key.storage)
        case .hmacSHA256:
            return try JSONWebKeyHMAC<SHA256>.create(storage: key.storage)
        case .hmacSHA384:
            return try JSONWebKeyHMAC<SHA384>.create(storage: key.storage)
        case .hmacSHA512:
            return try JSONWebKeyHMAC<SHA512>.create(storage: key.storage)
        default:
            return try SymmetricKey.create(storage: key.storage)
        }
    }
}

enum JSONWebKeyCertificateChainSpecializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        if !key.certificateChain.isEmpty {
            return try JSONWebCertificateChain.create(storage: key.storage)
        }
        return nil
    }
}

extension AnyJSONWebKey {
    @ReadWriteLocked
    fileprivate static var specializers: [any JSONWebKeySpecializer.Type] = [
        JSONWebKeyRSASpecializer.self,
        JSONWebKeyEllipticCurveSpecializer.self,
        JSONWebKeyCurve25519Specializer.self,
        JSONWebKeyCertificateChainSpecializer.self,
        JSONWebKeySymmetricSpecializer.self,
    ]
    
    /// Registers a new key specializer.
    ///
    /// - Important: The specializer will be checked against before already registered ones,
    ///     to allow overriding default registry.
    ///
    /// - Parameter specializer: The specializer to register.
    public static func registerSpecializer(_ specializer: any JSONWebKeySpecializer.Type) {
        guard !specializers.contains(where: { $0 == specializer }) else { return }
        specializers.insert(specializer, at: 0)
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
