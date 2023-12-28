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

/// JSON Web Signature Algorithms.
public protocol JSONWebAlgorithm: StringRepresentable {
    /// Key type, which is either `RSA`, `EC` for elliptic curve or `oct` for symmetric keys.
    var keyType: JSONWebKeyType? { get }
    
    /// Elliptic key curve, if key type is `EC`.
    var curve: JSONWebKeyCurve? { get }
    
    /// Initialize algorithm from name.
    ///
    /// - Parameter rawValue: JWA registered name.
    init<S: StringProtocol>(_ rawValue: S)
}

extension JSONWebAlgorithm {
    public var curve: JSONWebKeyCurve? { nil }
    
    public init(rawValue: String) {
        self.init(rawValue.trimmingCharacters(in: .whitespacesAndNewlines))
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

/// JSON Web Signature Algorithms.
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

/// JSON Key Type, e.g. `RSA`, `EC`, etc.
public struct JSONWebKeyType: StringRepresentable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
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
    
    /// Octet key pair [RFC-8037](https://tools.ietf.org/html/rfc8037)
    public static let octetKeyPair: Self = "OKP"
}

/// JSON EC Curves.
public struct JSONWebKeyCurve: StringRepresentable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
}

extension JSONWebKeyCurve {
    @ReadWriteLocked
    private static var keySizes: [Self: Int] = [
        .p256: 32, .ed25519: 32, .x25519: 32,
        .p384: 48,
        .p521: 66,
    ]
    
    /// Key size in bytes.
    public var keySize: Int? {
        Self.keySizes[self]
    }
    
    /// Currently registered algorithms.
    public static var registeredCurves: [Self] {
        .init(keySizes.keys)
    }
    
    /// Registers a new curve for ECDSA/EdDSA.
    ///
    /// - Parameters:
    ///   - curve: Curve name.
    ///   - keySize: Uncompressed key size in bytes.
    public static func register(_ curve: Self, keySize: Int) async {
        keySizes[curve] = keySize
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
    
    /// Ed-25519 for signing curve.
    public static let ed25519: Self = "Ed25519"
    
    /// Ed-25519 for Diffie-Hellman curve.
    public static let x25519: Self = "X25519"
}

/// JSON Key Usage, e.g. `sig`, `enc`, etc.
public struct JSONWebKeyUsage: StringRepresentable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
}

extension JSONWebKeyUsage {
    /// Signature
    public static let signature: Self = "sig"
    
    /// Encryption
    public static let encryption: Self = "enc"
}

/// JSON Key Usage, e.g. `sign`, `decrypt`, `deriveKey`, etc.
public struct JSONWebKeyOperation: StringRepresentable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
}

extension JSONWebKeyOperation {
    /// Compute digital signature or MAC.
    public static let sign: Self = "sign"
    
    /// Verify digital signature or MAC.
    public static let verify: Self = "verify"
    
    /// Encrypt content.
    public static let encrypt: Self = "encrypt"
    
    /// decrypt content and validate decryption, if applicable.
    public static let decrypt: Self = "decrypt"
    
    /// Encrypt key.
    public static let wrapKey: Self = "wrapKey"
    
    /// decrypt key and validate decryption, if applicable.
    public static let unwrapKey: Self = "unwrapKey"
    
    /// Encrypt key.
    public static let deriveKey: Self = "deriveKey"
    
    /// Derive bits not to be used as a key.
    public static let deriveBits: Self = "deriveBits"
}
