//
//  Signature.swift
//
//
//  Created by Amir Abbas Mousavian on 10/13/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// JSON Web Signature Algorithms
public struct JSONWebSignatureAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

extension JSONWebSignatureAlgorithm {
    private static var keyRegistryClass: [Self: (public: any JSONWebValidatingKey.Type, private: any JSONWebSigningKey.Type)] = [
        .none: (JSONWebDirectKey.self, JSONWebDirectKey.self),
        .hmacSHA256: (JSONWebKeyHMAC<SHA256>.self, JSONWebKeyHMAC<SHA256>.self),
        .hmacSHA384: (JSONWebKeyHMAC<SHA384>.self, JSONWebKeyHMAC<SHA384>.self),
        .hmacSHA512: (JSONWebKeyHMAC<SHA512>.self, JSONWebKeyHMAC<SHA512>.self),
        .ecdsaSignatureP256SHA256: (P256.Signing.PublicKey.self, P256.Signing.PrivateKey.self),
        .ecdsaSignatureP384SHA384: (P384.Signing.PublicKey.self, P384.Signing.PrivateKey.self),
        .ecdsaSignatureP521SHA512: (P521.Signing.PublicKey.self, P521.Signing.PrivateKey.self),
        .eddsaSignature: (Curve25519.Signing.PublicKey.self, Curve25519.Signing.PrivateKey.self),
        .rsaSignaturePSSSHA256: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaSignaturePSSSHA384: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaSignaturePSSSHA512: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaSignaturePKCS1v15SHA256: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaSignaturePKCS1v15SHA384: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
        .rsaSignaturePKCS1v15SHA512: (JSONWebRSAPublicKey.self, JSONWebRSAPrivateKey.self),
    ]
    
    private static var keyType: [Self: JSONWebKeyType] = [
        .none: .symmetric,
        .hmacSHA256: .symmetric,
        .hmacSHA384: .symmetric,
        .hmacSHA512: .symmetric,
        .ecdsaSignatureP256SHA256: .ellipticCurve,
        .ecdsaSignatureP384SHA384: .ellipticCurve,
        .ecdsaSignatureP521SHA512: .ellipticCurve,
        .eddsaSignature: .ellipticCurve,
        .rsaSignaturePSSSHA256: .rsa,
        .rsaSignaturePSSSHA384: .rsa,
        .rsaSignaturePSSSHA512: .rsa,
        .rsaSignaturePKCS1v15SHA256: .rsa,
        .rsaSignaturePKCS1v15SHA384: .rsa,
        .rsaSignaturePKCS1v15SHA512: .rsa,
    ]
    
    private static var curveTable: [Self: JSONWebKeyCurve] = [
        .ecdsaSignatureP256SHA256: .p256, .ecdsaSignatureP384SHA384: .p384,
        .ecdsaSignatureP521SHA512: .p521, .eddsaSignature: .ed25519,
    ]
    
    public var keyType: JSONWebKeyType? {
        Self.keyType[self]
    }
    
    public var curve: JSONWebKeyCurve? {
        Self.curveTable[self]
    }
    
    /// Returns private and public class appropriate for algorithm.
    public var keyClass: (public: any JSONWebValidatingKey.Type, private: any JSONWebSigningKey.Type)? {
        Self.keyRegistryClass[self]
    }
    
    /// Registers a new algorithm for signature.
    /// 
    /// - Parameters:
    ///   - algorithm: New algorithm name.
    ///   - type: Type of key. Can be symmetric, RSA or Elliptic curve.
    ///   - curve: Curve if key is elliptic curve.
    ///   - publicKeyClass: Public key class.
    ///   - privateKeyClass: Private key class. In case the key is symmetric, it equals to `publicKeyClass`.
    public static func register<Public, Private>(
        _ algorithm: Self,
        type: JSONWebKeyType,
        curve: JSONWebKeyCurve? = nil,
        publicKeyClass: Public.Type,
        privateKeyClass: Private.Type
    ) where Public: JSONWebValidatingKey, Private: JSONWebSigningKey {
        keyRegistryClass[algorithm] = (publicKeyClass, privateKeyClass)
        keyType[algorithm] = type
        curveTable[algorithm] = curve
    }
}

extension JSONWebSignatureAlgorithm {
    /// Generates new random key with minimum key length.
    ///
    /// - Returns: New random key.
    public func generateRandomKey() throws -> any JSONWebSigningKey {
        guard let keyClass = keyClass?.private else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init()
    }
}

// Signatures
extension JSONWebAlgorithm where Self == JSONWebSignatureAlgorithm {
    /// **Signature**: No digital signature or MAC performed.
    public static var none: Self { "none" }
    
    /// **Signature**: HMAC using SHA-256.
    public static var hmacSHA256: Self { "HS256" }
    
    /// **Signature**: HMAC using SHA-384.
    public static var hmacSHA384: Self { "HS384" }
    
    /// **Signature**: HMAC using SHA-512.
    public static var hmacSHA512: Self { "HS512" }
    
    static func hmac(bitCount: Int) -> Self {
        .init(rawValue: "HS\(bitCount)")
    }
    
    /// **Signature**: RSASSA-PKCS1-v1.5 using SHA-256.
    public static var rsaSignaturePKCS1v15SHA256: Self { "RS256" }
    
    /// **Signature**: RSASSA-PKCS1-v1.5 using SHA-384.
    public static var rsaSignaturePKCS1v15SHA384: Self { "RS384" }
    
    /// **Signature**: RSASSA-PKCS1-v1.5 using SHA-512 .
    public static var rsaSignaturePKCS1v15SHA512: Self { "RS512" }
    
    /// **Signature**: RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    public static var rsaSignaturePSSSHA256: Self { "PS256" }
    
    /// **Signature**: RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    public static var rsaSignaturePSSSHA384: Self { "PS384" }
    
    /// **Signature**: RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    public static var rsaSignaturePSSSHA512: Self { "PS512" }
    
    /// **Signature**: ECDSA using P-256 and SHA-256.
    public static var ecdsaSignatureP256SHA256: Self { "ES256" }
    
    /// **Signature**: EdDSA signature algorithms
    public static var eddsaSignature: Self { "EdDSA" }
    
    /// **Signature**: ECDSA using P-384 and SHA-384.
    public static var ecdsaSignatureP384SHA384: Self { "ES384" }
    
    /// **Signature**: ECDSA using P-521 and SHA-512.
    public static var ecdsaSignatureP521SHA512: Self { "ES512" }
}
