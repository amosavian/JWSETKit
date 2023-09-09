//
//  File.swift
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

/// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) [RFC7159]
/// data structure that represents a cryptographic key.
@dynamicMemberLookup
public protocol JSONWebKey: JSONWebContainer {
}

extension JSONWebKey {
    /// Creates a new JWK using json data.
    public init(jsonWebKeyData data: Data) throws {
        self = try Self.create(storage: JSONDecoder().decode(JSONWebValueStorage.self, from: data))
    }
    
    /// Creates a new JWK using json data.
    public init(jsonWebKey value: JSONWebValueStorage) throws {
        self = try Self.create(storage: value)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(JSONWebValueStorage.self)
        self = try Self.create(storage: value)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
}

public protocol JSONWebEncryptingKey: JSONWebKey {
    /// Encrypts plain-text data using current key.
    func encrypt<D: DataProtocol>(_ data: D) throws -> SealedData
}

public protocol JSONWebDecryptingKey: JSONWebEncryptingKey {
    /// Encrypts ciphered data using current key.
    func decrypt<D: DataProtocol>(_ data: D) throws -> Data
}

public protocol JSONWebValidatingKey: JSONWebKey {
    /// Validates a signature for given data using current key.
    func validate<D: DataProtocol>(_ signature: D, for data: D) throws
}

public protocol JSONWebSigningKey: JSONWebValidatingKey {
    /// Creates a new signature for given data.
    func sign<D: DataProtocol>(_ data: D) throws -> Data
}

struct JSONWebKeyData: JSONWebKey {
    var storage: JSONWebValueStorage
    
    static func create(storage: JSONWebValueStorage) throws -> JSONWebKeyData {
        JSONWebKeyData(storage: storage)
    }
    
    init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    init() {
        self.storage = .init()
    }
}

/// JSON Web Compression Algorithms.
public struct JSONWebKeyType: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral {
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
    /// Elliptic Curve
    public static let elipticCurve: Self = "EC"
    
    /// RSA
    public static let rsa: Self = "RSA"
    
    /// Octet sequence
    public static let symmetric: Self = "oct"
}


/// JSON EC Curves.
public struct JSONWebKeyCurve: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral {
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
