//
//  KeyParser.swift
//
//
//  Created by Amir Abbas Mousavian on 9/8/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
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
    /// - Parameters:
    ///   - data: The key data to deserialize.
    ///   - format: The format of the key data.
    /// - Returns: Related specific key object.
    public static func deserialize(_ data: Data, format _: JSONWebKeyFormat) throws -> any JSONWebKey {
        let webKey = try JSONDecoder().decode(AnyJSONWebKey.self, from: data)
        return webKey.specialized()
    }
}

/// A specializer that can convert a `AnyJSONWebKey` to a specific `JSONWebKey` type.
public protocol JSONWebKeySpecializer {
    /// Specializes a `AnyJSONWebKey` to a specific `JSONWebKey` type, returns `nil` if key is not appropriate.
    ///
    /// - Parameter key: The key to specialize.
    /// - Returns: A specific `JSONWebKey` type, or `nil` if the key is not appropriate.
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)?
    
    /// Deserializes a key from a data, returns `nil` if key is not appropriate.
    ///
    /// - Parameters:
    ///   - key: The key data to deserialize.
    ///   - format: The format of the key data.
    ///   - Returns: A specific `JSONWebKey` type, or `nil` if the key is not appropriate.
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol
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
    
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        switch format {
        case .pkcs8:
            guard try PKCS8PrivateKey(derEncoded: key).keyType == .rsa else { return nil }
            return try JSONWebRSAPrivateKey(importing: key, format: format)
        case .spki:
            guard try SubjectPublicKeyInfo(derEncoded: key).keyType == .rsa else { return nil }
            return try JSONWebRSAPublicKey(importing: key, format: format)
        default:
            return nil
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
    
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        switch format {
        case .pkcs8:
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            guard try pkcs8.keyType == .ellipticCurve else { return nil }
            guard pkcs8.keyCurve != nil else { return nil }
            return try JSONWebECPrivateKey(importing: key, format: format)
        case .spki:
            let spki = try SubjectPublicKeyInfo(derEncoded: key)
            guard try spki.keyType == .ellipticCurve else { return nil }
            guard spki.keyCurve != nil else { return nil }
            return try JSONWebECPublicKey(importing: key, format: format)
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
    
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        switch format {
        case .pkcs8:
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            guard try pkcs8.keyType == .octetKeyPair else { return nil }
            guard pkcs8.keyCurve == .ed25519 else { return nil }
            return try JSONWebECPrivateKey(importing: key, format: format)
        case .spki:
            let spki = try SubjectPublicKeyInfo(derEncoded: key)
            guard try spki.keyType == .octetKeyPair else { return nil }
            guard spki.keyCurve == .ed25519 else { return nil }
            return try JSONWebECPublicKey(importing: key, format: format)
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
        
        switch key.algorithm ?? JSONWebSignatureAlgorithm("") {
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
    
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        switch format {
        case .raw:
            return try AnyJSONWebKey(storage: SymmetricKey(importing: key, format: .raw).storage).specialized()
        case .pkcs8, .spki, .jwk:
            return nil
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
    
    static func deserialize<D>(key _: D, format _: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        nil
    }
}

extension AnyJSONWebKey {
    static let specializers: PthreadReadWriteLockedValue<[any JSONWebKeySpecializer.Type]> = [
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
    public static func registerSpecializer<S>(_ specializer: S.Type) where S: JSONWebKeySpecializer {
        guard !specializers.contains(where: { $0 == specializer }) else { return }
        specializers.insert(specializer, at: 0)
    }
}
