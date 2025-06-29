//
//  Algorithms.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

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
    init?(_ algorithm: (any JSONWebAlgorithm)?) {
        guard let rawValue = algorithm?.rawValue else { return nil }
        self.init(rawValue: rawValue)
    }
    
    @usableFromInline
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
    
    /// Returns value with appropriate algorithm type.
    func specialized() -> any JSONWebAlgorithm {
        Self.specialized(rawValue)
    }
}

/// JSON Web Signature Algorithms.
@frozen
public struct AnyJSONWebAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
        
    public var keyType: JSONWebKeyType? {
        specialized().keyType
    }
    
    public var curve: JSONWebKeyCurve? {
        specialized().curve
    }
    
    var keyLength: Int? {
        if let result = JSONWebSignatureAlgorithm(rawValue: rawValue).curve?.coordinateSize {
            return result * 8
        } else if let result = JSONWebKeyEncryptionAlgorithm(rawValue: rawValue).keyLength {
            return result
        } else if let result = JSONWebContentEncryptionAlgorithm(rawValue: rawValue).keyLength {
            return result.bitCount
        }
        return nil
    }
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

/// JSON Key Type, e.g. `RSA`, `EC`, etc.
@frozen
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
    
    /// The Algorithm Key Pair (AKP) Type is used to express Public and Private Keys for use with Algorithms.
    /// See [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) .
    public static let algorithmKeyPair: Self = "AKP"
}

extension JSONWebKeyType {
    private static let requiredFields: PthreadReadWriteLockedValue<[Self: [String]]> = [
        .ellipticCurve: ["x", "y"],
        .rsa: ["n", "e"],
        .symmetric: ["k"],
        .octetKeyPair: ["x"],
        .algorithmKeyPair: ["pub"],
    ]
    
    var requiredFields: [String] {
        Self.requiredFields[self] ?? []
    }
}

/// JSON EC Curves.
public struct JSONWebKeyCurve: StringRepresentable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
}

extension JSONWebKeyCurve {
    private static let keySizes: PthreadReadWriteLockedValue<[Self: Int]> = [
        .p256: 32, .ed25519: 32, .x25519: 32,
        .p384: 48,
        .p521: 66,
    ]
    
    /// Key size in bytes.
    public var coordinateSize: Int? {
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
    
    /// X-25519 for Diffie-Hellman curve.
    public static let x25519: Self = "X25519"
}

/// JSON Key Usage, e.g. `sig`, `enc`, etc.
@frozen
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
@frozen
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
