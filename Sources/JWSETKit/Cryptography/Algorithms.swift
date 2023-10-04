//
//  Algorithms.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// JSON Web Signature and Encryption Algorithms
public struct JSONWebAlgorithm: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

// Signatures
extension JSONWebAlgorithm {
    /// **Signature**: No digital signature or MAC performed.
    public static let none: Self = "none"
    
    /// **Signature**: HMAC using SHA-256.
    public static let hmacSHA256: Self = "HS256"
    
    /// **Signature**: HMAC using SHA-384.
    public static let hmacSHA384: Self = "HS384"
    
    /// **Signature**: HMAC using SHA-512.
    public static let hmacSHA512: Self = "HS512"
    
    static func hmac(bitCount: Int) -> Self {
        .init(rawValue: "HS\(bitCount)")
    }
    
    /// **Signature**: RSASSA-PKCS1-v1.5 using SHA-256.
    public static let rsaSignaturePKCS1v15SHA256: Self = "RS256"
    
    /// **Signature**: RSASSA-PKCS1-v1.5 using SHA-384.
    public static let rsaSignaturePKCS1v15SHA384: Self = "RS384"
    
    /// **Signature**: RSASSA-PKCS1-v1.5 using SHA-512 .
    public static let rsaSignaturePKCS1v15SHA512: Self = "RS512"
    
    /// **Signature**: RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    public static let rsaSignaturePSSSHA256: Self = "PS256"
    
    /// **Signature**: RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    public static let rsaSignaturePSSSHA384: Self = "PS384"
    
    /// **Signature**: RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    public static let rsaSignaturePSSSHA512: Self = "PS512"
    
    /// **Signature**: ECDSA using P-256 and SHA-256.
    public static let ecdsaSignatureP256SHA256: Self = "ES256"
    
    /// **Signature**: EdDSA signature algorithms
    public static let eddsaSignature: Self = "EdDSA"
    
    /// **Signature**: ECDSA using P-384 and SHA-384.
    public static let ecdsaSignatureP384SHA384: Self = "ES384"
    
    /// **Signature**: ECDSA using P-521 and SHA-512.
    public static let ecdsaSignatureP521SHA512: Self = "ES512"
}

// Key Management
extension JSONWebAlgorithm {
    /// **Key Management**: RSAES-PKCS1-v1.5
    public static let rsaEncryptionPKCS1: Self = "RSA1_5"
    
    /// **Key Management**: RSAES OAEP using default parameters.
    public static let rsaEncryptionOAEP: Self = "RSA-OAEP"
    
    /// **Key Management**: RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    public static let rsaEncryptionOAEPSHA256: Self = "RSA-OAEP-256"
    
    /// **Key Management**: RSA-OAEP using SHA-384 and MGF1 with SHA-384.
    public static let rsaEncryptionOAEPSHA384: Self = "RSA-OAEP-384"
    
    /// **Key Management**: RSA-OAEP using SHA-512 and MGF1 with SHA-512.
    public static let rsaEncryptionOAEPSHA512: Self = "RSA-OAEP-512"
    
    /// **Key Management**: AES Key-Wrap using 128-bit key.
    public static let aesKeyWrap128: Self = "A128KW"
    
    /// **Key Management**: AES Key-Wrap using 192-bit key.
    public static let aesKeyWrap192: Self = "A192KW"
    
    /// **Key Management**: AES Key-Wrap using 256-bit key.
    public static let aesKeyWrap256: Self = "A256KW"
    
    static func aesKeyWrap(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)KW")
    }
    
    /// **Key Management**: No encryption for content key.
    public static let direct: Self = "direct"
}

// Content Encryption
extension JSONWebAlgorithm {
    /// **Content Encryption**: AES GCM using 128-bit key.
    public static let aesEncryptionGCM128: Self = "A128GCM"
    
    /// **Content Encryption**: AES GCM using 192-bit key.
    public static let aesEncryptionGCM192: Self = "A192GCM"
    
    /// **Content Encryption**: AES GCM using 256-bit key.
    public static let aesEncryptionGCM256: Self = "A256GCM"
    
    static func aesEncryptionGCM(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)GCM")
    }
}

/// JSON Key Type, e.g. `RSA`, `EC`, etc.
public struct JSONWebKeyType: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension JSONWebKeyType {
    static let empty: Self = ""
    
    /// Elliptic Curve
    public static let elipticCurve: Self = "EC"
    
    /// RSA
    public static let rsa: Self = "RSA"
    
    /// Octet sequence
    public static let symmetric: Self = "oct"
}

/// JSON EC Curves.
public struct JSONWebKeyCurve: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension JSONWebKeyCurve {
    static let empty: Self = ""
    
    /// NIST P-256 (secp256r1) curve.
    public static let p256: Self = "P-256"
    
    /// NIST P-384 (secp384r1) curve.
    public static let p384: Self = "P-384"
    
    /// NIST P-521 (secp521r1) curve.
    public static let p521: Self = "P-521"
    
    /// EC-25519 for signing curve.
    public static let ed25519: Self = "Ed25519"
    
    /// EC-25519 for Diffie-Hellman curve.
    public static let x25519: Self = "X25519"
}

extension JSONWebKeyCurve {
    var keyLengthInBytes: Int {
        switch self {
        case .p256, .ed25519, .x25519:
            return 32
        case .p384:
            return 48
        case .p521:
            return 66
        default:
            preconditionFailure()
        }
    }
}

/// JSON Web Compression Algorithms.
public struct JSONWebCompressionAlgorithm: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension JSONWebCompressionAlgorithm {
    /// Compression with the DEFLATE [RFC1951](https://www.rfc-editor.org/rfc/rfc1951) algorithm
    public static let deflate: Self = "DEF"
}

extension JSONWebAlgorithm {
    private static let keyTypeTable: [JSONWebAlgorithm: JSONWebKeyType] = [
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
    
    private static let curveTable: [JSONWebAlgorithm: JSONWebKeyCurve] = [
        .ecdsaSignatureP256SHA256: .p256, .ecdsaSignatureP384SHA384: .p384,
        .ecdsaSignatureP521SHA512: .p521, .eddsaSignature: .ed25519,
    ]
    
    var keyType: JSONWebKeyType? {
        JSONWebAlgorithm.keyTypeTable[self]
    }
    
    var curve: JSONWebKeyCurve? {
        JSONWebAlgorithm.curveTable[self]
    }
}
