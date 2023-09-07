//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
import CryptoKit

/// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) [RFC7159]
/// data structure that represents a cryptographic key.
@dynamicMemberLookup
public protocol JsonWebKey: JsonWebContainer {
    /// Returns a new concrete key using json data.
    static func create(jsonWebKey: JsonWebValueStorage) throws -> Self
}

func deserializeJsonWebKey(jsonWebKey: Data) throws -> any JsonWebKey {
    let storage = try JSONDecoder().decode(JsonWebValueStorage.self, from: jsonWebKey)
    guard let algorithm = (storage.alg as String?).map(JsonWebAlgorithm.init(rawValue:)) else {
        throw JsonWebKeyError.unknownAlgorithm
    }
    
    switch algorithm {
    case .hmacSHA256:
        return try JsonWebKeyHMAC<SHA256>(jsonWebKey: storage)
    case .hmacSHA384:
        return try JsonWebKeyHMAC<SHA384>(jsonWebKey: storage)
    case .hmacSHA512:
        return try JsonWebKeyHMAC<SHA512>(jsonWebKey: storage)
    case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
        return try JsonWebKeyAESGCM(jsonWebKey: storage)
    default:
        if let data = storage["k", true] {
            return SymmetricKey(data: data)
        } else {
            throw JsonWebKeyError.unknownAlgorithm
        }
    }
}

extension JsonWebKey {
    /// Creates a new JWK using json data.
    public init(jsonWebKeyData data: Data) throws {
        self = try Self.create(jsonWebKey: JSONDecoder().decode(JsonWebValueStorage.self, from: data))
    }
    
    /// Creates a new JWK using json data.
    public init(jsonWebKey value: JsonWebValueStorage) throws {
        self = try Self.create(jsonWebKey: value)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(JsonWebValueStorage.self)
        self = try Self.create(jsonWebKey: value)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
}

public protocol JsonWebEncryptingKey: JsonWebKey {
    /// Encrypts plain-text data using current key.
    func encrypt<D: DataProtocol>(_ data: D) throws -> SealedData
}

public protocol JsonWebDecryptingKey: JsonWebEncryptingKey {
    /// Encrypts ciphered data using current key.
    func decrypt<D: DataProtocol>(_ data: D) throws -> Data
}

public protocol JsonWebValidatingKey: JsonWebKey {
    /// Validates a signature for given data using current key.
    func validate<D: DataProtocol>(_ signature: D, for data: D) throws
}

public protocol JsonWebSigningKey: JsonWebValidatingKey {
    /// Creates a new signature for given data.
    func sign<D: DataProtocol>(_ data: D) throws -> Data
}

/// JSON Web Compression Algorithms.
public struct JsonWebKeyType: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral {
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

extension JsonWebKeyType {
    /// Elliptic Curve
    public static let elipticCurve: Self = "EC"
    
    /// RSA
    public static let rsa: Self = "RSA"
    
    /// Octet sequence
    public static let symmetric: Self = "oct"
}
