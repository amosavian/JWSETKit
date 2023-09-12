//
//  Keys.swift
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
public protocol JSONWebKey: JSONWebContainer {}

extension JSONWebKey {
    /// Creates a new JWK using json data.
    public init(jsonWebKeyData data: Data) throws {
        self = try Self.create(storage: JSONDecoder().decode(JSONWebValueStorage.self, from: data))
    }
    
    /// Creates a new JWK using json data.
    ///
    /// - Parameter value: JSON key-value storage.
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
    ///
    /// - Parameters:
    ///   - data: Plain-text to be ecnrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data.
    func encrypt<D: DataProtocol>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> SealedData
}

public protocol JSONWebDecryptingKey: JSONWebEncryptingKey {
    /// Encrypts ciphered data using current key.
    ///
    /// - Parameters:
    ///   - data: Cipher-text that ought to be decrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Plain-text data
    func decrypt<D: DataProtocol>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data
}

public protocol JSONWebValidatingKey: JSONWebKey {
    /// Verifies the cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that must be validated.
    ///   - data: The data that was signed.
    ///   - algorithm: The algorithm that was used to create the signature.
    func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol
}

public protocol JSONWebSigningKey: JSONWebValidatingKey {
    /// Creates the cryptographic signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - algorithm: The signing algorithm to use.
    /// - Returns: The digital signature or throws error on failure.
    func sign<D: DataProtocol>(_ data: D, using algorithm: JSONWebAlgorithm) throws -> Data
}

public struct AnyJSONWebKey: JSONWebKey {
    public var storage: JSONWebValueStorage
    
    public static func create(storage: JSONWebValueStorage) throws -> AnyJSONWebKey {
        AnyJSONWebKey(storage: storage)
    }
    
    init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    init(_ key: any JSONWebKey) {
        self.storage = key.storage
    }
    
    init() {
        self.storage = .init()
    }
}

/// A JWK Set is a JSON object that represents a set of JWKs.
///
/// The JSON object MUST have a "keys" member, with its value being an array of JWKs.
/// This JSON object MAY contain whitespace and/or line breaks.
public struct JSONWebKeySet: Codable, Hashable {
    enum CodingKeys: CodingKey {
        case keys
    }
    
    /// The value of the "keys" parameter is an array of JWK values.
    ///
    /// By default, the order of the JWK values within the array does not imply
    /// an order of preference among them, although applications of JWK Sets
    /// can choose to assign a meaning to the order for their purposes, if desired.
    public var keys: [any JSONWebKey]
    
    init(keys: [any JSONWebKey]) {
        self.keys = keys
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let keys = try container.decode([AnyJSONWebKey].self, forKey: .keys)
        self.keys = try keys.map { try $0.specialized() }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(keys.map(\.storage), forKey: .keys)
    }
    
    public static func == (lhs: JSONWebKeySet, rhs: JSONWebKeySet) -> Bool {
        lhs.keys.map(\.storage) == rhs.keys.map(\.storage)
    }
    
    public func hash(into hasher: inout Hasher) {
        keys.forEach { hasher.combine($0) }
    }
}
