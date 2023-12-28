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
public protocol JSONWebKey: Codable, Hashable {
    /// Storage of container values.
    var storage: JSONWebValueStorage { get }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    ///
    /// - Returns: A new instance of current class.
    static func create(storage: JSONWebValueStorage) throws -> Self
    
    /// Validates contents and required fields if applicable.
    func validate() throws
}

/// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) [RFC7159]
/// data structure that represents a cryptographic key.
@dynamicMemberLookup
public protocol MutableJSONWebKey: JSONWebKey {
    /// Storage of container values.
    var storage: JSONWebValueStorage { get set }
}

extension JSONWebKey {
    /// Creates a new JWK using json data.
    public init(jsonWebKeyData data: Data) throws {
        self = try Self.create(storage: JSONDecoder().decode(JSONWebValueStorage.self, from: data))
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self = try Self.create(storage: container.decode(JSONWebValueStorage.self))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard let keyType = self.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        switch keyType {
        case .rsa:
            // swiftformat:disable:next redundantSelf
            guard self.modulus != nil, self.exponent != nil else {
                throw JSONWebKeyError.keyNotFound
            }
        case .ellipticCurve:
            // swiftformat:disable:next redundantSelf
            guard self.xCoordinate != nil else {
                throw JSONWebKeyError.keyNotFound
            }
        case .symmetric:
            // swiftformat:disable:next redundantSelf
            guard self.keyValue != nil else {
                throw JSONWebKeyError.keyNotFound
            }
        default:
            break
        }
    }
}

/// A JSON Web Key (JWK) able to encrypt plain-texts.
public protocol JSONWebEncryptingKey: JSONWebKey {
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be encrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data.
    func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm
}

/// A JSON Web Key (JWK) able to decrypt cipher-texts.
public protocol JSONWebDecryptingKey: JSONWebEncryptingKey {
    associatedtype PublicKey: JSONWebEncryptingKey
    
    /// Public key.
    var publicKey: PublicKey { get }
    
    /// Generates new random key.
    init(algorithm: any JSONWebAlgorithm) throws
    
    /// Decrypts ciphered data using current key.
    ///
    /// - Parameters:
    ///   - data: Cipher-text that ought to be decrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Plain-text data
    func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm
}

extension JSONWebDecryptingKey {
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try publicKey.encrypt(data, using: algorithm)
    }
}

/// A JSON Web Key (JWK) able to decrypt cipher-texts using a symmetric key.
public protocol JSONWebSymmetricDecryptingKey: JSONWebDecryptingKey where PublicKey == Self {
    init(_ key: SymmetricKey) throws
}

extension JSONWebSymmetricDecryptingKey {
    public var publicKey: Self { self }
    
    public init() throws {
        try self.init(.init(size: .bits128))
    }
}

/// A JSON Web Key (JWK) able to encrypt/decrypt plain-texts with authentication-tag.
public protocol JSONWebSealingKey: JSONWebKey {
    /// Initializes a key for encryption with given `SymmetricKey`.
    ///
    /// - Parameter key: A symmetric cryptographic key.
    init(_ key: SymmetricKey) throws
    
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - iv: Initial vector/Nouce.
    ///   - authenticating: Additional data to be authenticated.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, IV, AAD, JWA>(
        _ data: D, iv: IV?,
        authenticating: AAD?,
        using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm
    
    /// Decrypts cipher-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be decrypted.
    ///   - authenticating: Additional data to be authenticated.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using algorithm: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm
}

extension JSONWebSealingKey {
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, JWA>(
        _ data: D, using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, iv: Data?.none, authenticating: Data?.none, using: algorithm)
    }
    
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - iv: Initial vector/Nouce.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, IV, JWA>(
        _ data: D, iv: IV,
        using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, IV: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, iv: iv, authenticating: Data?.none, using: algorithm)
    }
    
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - authenticating: Additional data to be authenticated.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, AAD, JWA>(
        _ data: D, authenticating: AAD,
        using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, iv: Data?.none, authenticating: authenticating, using: algorithm)
    }
    
    /// Decrypts cipher-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be decrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func open<JWA>(_ data: SealedData, using algorithm: JWA) throws -> Data where JWA: JSONWebAlgorithm {
        try open(data, authenticating: Data?.none, using: algorithm)
    }
}

/// A JSON Web Key (JWK) able to validate a signaute.
public protocol JSONWebValidatingKey: JSONWebKey {
    /// Verifies the cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that must be validated.
    ///   - data: The data that was signed.
    ///   - algorithm: The algorithm that was used to create the signature.
    func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol
}

/// A JSON Web Key (JWK) able to generate a signature.
public protocol JSONWebSigningKey: JSONWebValidatingKey {
    associatedtype PublicKey: JSONWebValidatingKey
    
    /// Public key.
    var publicKey: PublicKey { get }
    
    /// Generates new random key.
    init(algorithm: any JSONWebAlgorithm) throws
    
    /// Creates the cryptographic signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - algorithm: The signing algorithm to use.
    /// - Returns: The digital signature or throws error on failure.
    func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol
}

extension JSONWebSigningKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}

/// A JSON Web Key (JWK) able to generate a signature using a symmetric key.
public protocol JSONWebSymmetricSigningKey: JSONWebSigningKey {
    init(_ key: SymmetricKey) throws
}

/// A type-erased general container for a JSON Web Key (JWK).
///
/// - Note: To create a key able to do operations (sign, verify, encrypt, decrypt) use `specialzed()` method.
public struct AnyJSONWebKey: MutableJSONWebKey {
    public var storage: JSONWebValueStorage
    
    public static func create(storage: JSONWebValueStorage) throws -> AnyJSONWebKey {
        AnyJSONWebKey(storage: storage)
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// A type-erased JWK value.
    ///
    /// - Parameter key: Key to wrap.
    public init(_ key: any JSONWebKey) {
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
    
    /// Initializes JWKSet using given array of key.
    ///
    /// - Parameter keys: An array of JWKs.
    public init(keys: [any JSONWebKey]) {
        self.keys = keys
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let keys = try container.decode([AnyJSONWebKey].self, forKey: .keys)
        self.keys = try keys.map { try $0.specialized() }
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(keys.map(\.storage), forKey: .keys)
    }
    
    public static func == (lhs: JSONWebKeySet, rhs: JSONWebKeySet) -> Bool {
        Set(lhs.keys.map(\.storage)) == Set(rhs.keys.map(\.storage))
    }
    
    public func hash(into hasher: inout Hasher) {
        keys.forEach { hasher.combine($0) }
    }
}
