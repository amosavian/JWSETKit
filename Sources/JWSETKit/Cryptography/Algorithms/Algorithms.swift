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

public protocol JSONWebAlgorithm: RawRepresentable<String>, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
    var keyType: JSONWebKeyType? { get }
    var curve: JSONWebKeyCurve? { get }
    init<S: StringProtocol>(_ rawValue: S)
}

extension JSONWebAlgorithm {
    public var curve: JSONWebKeyCurve? { nil }
    
    public init(rawValue: String) {
        self.init(rawValue.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    
    public init(stringLiteral value: String) {
        self.init(value)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(container.decode(String.self))
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

@_documentation(visibility: private)
public func == <RHS: JSONWebAlgorithm>(lhs: any JSONWebAlgorithm, rhs: RHS) -> Bool {
    lhs.rawValue == rhs.rawValue
}

@_documentation(visibility: private)
public func == <RHS: JSONWebAlgorithm>(lhs: (any JSONWebAlgorithm)?, rhs: RHS) -> Bool {
    lhs?.rawValue == rhs.rawValue
}

@_documentation(visibility: private)
public func == <LHS: JSONWebAlgorithm>(lhs: LHS, rhs: any JSONWebAlgorithm) -> Bool {
    lhs.rawValue == rhs.rawValue
}

@_documentation(visibility: private)
public func == <LHS: JSONWebAlgorithm>(lhs: LHS, rhs: (any JSONWebAlgorithm)?) -> Bool {
    lhs.rawValue == rhs?.rawValue
}

@_documentation(visibility: private)
public func == <LHS: JSONWebAlgorithm, RHS: JSONWebAlgorithm>(lhs: LHS, rhs: RHS) -> Bool {
    lhs.rawValue == rhs.rawValue
}

@_documentation(visibility: private)
public func ~= <JWA: JSONWebAlgorithm>(lhs: JWA, rhs: JWA) -> Bool {
    lhs.rawValue == rhs.rawValue
}

@_documentation(visibility: private)
public func ~= <LHS: JSONWebAlgorithm, RHS: JSONWebAlgorithm>(lhs: LHS, rhs: RHS) -> Bool {
    lhs.rawValue == rhs.rawValue
}

extension JSONWebAlgorithm {
    static func specialized(_ rawValue: String) -> any JSONWebAlgorithm {
        if JSONWebSignatureAlgorithm(rawValue: rawValue).keyType != nil {
            return JSONWebSignatureAlgorithm(rawValue: rawValue)
        } else if JSONWebKeyEncryptionAlgorithm(rawValue: rawValue).keyType != nil {
            return JSONWebKeyEncryptionAlgorithm(rawValue: rawValue)
        } else if JSONWebContentEncryptionAlgorithm(rawValue: rawValue).keyType != nil {
            return JSONWebContentEncryptionAlgorithm(rawValue: rawValue)
        }
        return AnyJSONWebAlgorithm(rawValue)
    }
}

/// JSON Web Signature Algorithms
public struct AnyJSONWebAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public var keyType: JSONWebKeyType? {
        if JSONWebSignatureAlgorithm(rawValue: rawValue).keyType != nil {
            return JSONWebSignatureAlgorithm(rawValue: rawValue).keyType
        } else if JSONWebKeyEncryptionAlgorithm(rawValue: rawValue).keyType != nil {
            return JSONWebKeyEncryptionAlgorithm(rawValue: rawValue).keyType
        } else if JSONWebContentEncryptionAlgorithm(rawValue: rawValue).keyType != nil {
            return JSONWebContentEncryptionAlgorithm(rawValue: rawValue).keyType
        }
        return nil
    }
    
    public var curve: JSONWebKeyCurve? {
        JSONWebSignatureAlgorithm(rawValue: rawValue).curve
    }
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

/// JSON Web Signature Algorithms
public struct JSONWebSignatureAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
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

/// JSON Web Key Encryption Algorithms
public struct JSONWebKeyEncryptionAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

// Key Management
extension JSONWebAlgorithm where Self == JSONWebKeyEncryptionAlgorithm {
    /// **Key Management**: RSAES-PKCS1-v1.5
    public static var rsaEncryptionPKCS1: Self { "RSA1_5" }
    
    /// **Key Management**: RSAES OAEP using default parameters.
    public static var rsaEncryptionOAEP: Self { "RSA-OAEP" }
    
    /// **Key Management**: RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    public static var rsaEncryptionOAEPSHA256: Self { "RSA-OAEP-256" }
    
    /// **Key Management**: RSA-OAEP using SHA-384 and MGF1 with SHA-384.
    public static var rsaEncryptionOAEPSHA384: Self { "RSA-OAEP-384" }
    
    /// **Key Management**: RSA-OAEP using SHA-512 and MGF1 with SHA-512.
    public static var rsaEncryptionOAEPSHA512: Self { "RSA-OAEP-512" }
    
    /// **Key Management**: AES Key-Wrap using 128-bit key.
    public static var aesKeyWrap128: Self { "A128KW" }
    
    /// **Key Management**: AES Key-Wrap using 192-bit key.
    public static var aesKeyWrap192: Self { "A192KW" }
    
    /// **Key Management**: AES Key-Wrap using 256-bit key.
    public static var aesKeyWrap256: Self { "A256KW" }
    
    static func aesKeyWrap(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)KW")
    }
    
    /// **Key Management**: Key wrapping with AES GCM using 128-bit key
    public static var aesGCM128KeyWrap: Self { "A128GCMKW" }
    
    /// **Key Management**: Key wrapping with AES GCM using 192-bit key
    public static var aesGCM192KeyWrap: Self { "A192GCMKW" }
    
    /// **Key Management**: Key wrapping with AES GCM using 256-bit key
    public static var aesGCM256KeyWrap: Self { "A256GCMKW" }
    
    static func aesGCMKeyWrap(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)GCMKW")
    }
    
    /// **Key Management**: PBES2 with HMAC SHA-256 and "A128KW" wrapping.
    public static var pbes2hmac256: Self { "PBES2-HS256+A128KW" }
    
    /// **Key Management**: PBES2 with HMAC SHA-384 and "A192KW" wrapping.
    public static var pbes2hmac384: Self { "PBES2-HS384+A192KW" }
    
    /// **Key Management**: PBES2 with HMAC SHA-512 and "A256KW" wrapping.
    public static var pbes2hmac512: Self { "PBES2-HS512+A256KW" }
    
    static func pbes2hmac(bitCount: Int) -> Self {
        .init(rawValue: "PBES2-HS\(bitCount)+A\(bitCount / 2)KW")
    }
    
    /// **Key Management**: No encryption for content key.
    public static var direct: Self { "direct" }
}

extension JSONWebKeyEncryptionAlgorithm {
    var keyLength: Int {
        switch self {
        case .aesKeyWrap128, .aesGCM128KeyWrap, .pbes2hmac256:
            return SHA256.byteCount
        case .aesKeyWrap192, .aesGCM192KeyWrap, .pbes2hmac384:
            return SHA384.byteCount
        case .aesKeyWrap256, .aesGCM256KeyWrap, .pbes2hmac512:
            return SHA512.byteCount
        default:
            return 0
        }
    }
}

/// JSON Web Key Encryption Algorithms
public struct JSONWebContentEncryptionAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

// Content Encryption
extension JSONWebAlgorithm where Self == JSONWebContentEncryptionAlgorithm {
    /// **Content Encryption**: AES GCM using 128-bit key.
    public static var aesEncryptionGCM128: Self { "A128GCM" }
    
    /// **Content Encryption**: AES GCM using 192-bit key.
    public static var aesEncryptionGCM192: Self { "A192GCM" }
    
    /// **Content Encryption**: AES GCM using 256-bit key.
    public static var aesEncryptionGCM256: Self { "A256GCM" }
    
    static func aesEncryptionGCM(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)GCM")
    }
    
    /// **Content Encryption**: `AES_128_CBC_HMAC_SHA_256` authenticated encryption algorithm.
    public static var aesEncryptionCBC128SHA256: Self { "A128CBC-HS256" }
    
    /// **Content Encryption**: `AES_192_CBC_HMAC_SHA_384` authenticated encryption algorithm.
    public static var aesEncryptionCBC192SHA384: Self { "A192CBC-HS384" }
    
    /// **Content Encryption**: `AES_256_CBC_HMAC_SHA_512` authenticated encryption algorithm.
    public static var aesEncryptionCBC256SHA512: Self { "A256CBC-HS512" }
    
    static func aesEncryptionCBCSHA(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)CBC-HS\(bitCount * 2)")
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
    public static let ellipticCurve: Self = "EC"
    
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

extension JSONWebSignatureAlgorithm {
    private static let curveTable: [Self: JSONWebKeyCurve] = [
        .ecdsaSignatureP256SHA256: .p256, .ecdsaSignatureP384SHA384: .p384,
        .ecdsaSignatureP521SHA512: .p521, .eddsaSignature: .ed25519,
    ]
    
    public var keyType: JSONWebKeyType? {
        switch rawValue.prefix(2) {
        case "RS", "PS":
            return .rsa
        case "ES", "Ed":
            return .ellipticCurve
        default:
            return .symmetric
        }
    }
    
    public var curve: JSONWebKeyCurve? {
        Self.curveTable[self]
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    private static let keyTypeTable: [Self: JSONWebKeyType] = [
        .aesKeyWrap128: .symmetric, .aesKeyWrap192: .symmetric, .aesKeyWrap256: .symmetric,
        .rsaEncryptionPKCS1: .rsa, .rsaEncryptionOAEP: .rsa, .rsaEncryptionOAEPSHA256: .rsa,
        .rsaEncryptionOAEPSHA384: .rsa, .rsaEncryptionOAEPSHA512: .rsa,
    ]
    
    public var keyType: JSONWebKeyType? {
        switch rawValue.prefix(1) {
        case "R":
            return .rsa
        default:
            return .symmetric
        }
    }
}

extension JSONWebContentEncryptionAlgorithm {
    public var keyType: JSONWebKeyType? {
        .symmetric
    }
}
