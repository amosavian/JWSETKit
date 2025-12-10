//
//  SelectiveDisclosure.swift
//
//
//  Created by Claude Code on 9/9/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Collections
import Crypto

/// Represents a single selective disclosure containing a salt, claim name, and claim value.
///
/// Each disclosure is encoded as a Base64URL-encoded JSON array: [salt, claim_name, claim_value]
/// The disclosure can be used to selectively reveal claims in SD-JWT presentations.
///
/// This type stores the original encoded value bytes to ensure consistent hashing across platforms.
/// When processing SD-JWTs from other issuers, the original value encoding is preserved.
public struct JSONWebSelectiveDisclosure: Hashable, ExpressibleByArrayLiteral, Sendable {
    /// Cryptographically random salt used to prevent brute-force attacks on claim values.
    /// Minimum recommended length is 128 bits (16 bytes).
    public let salt: Data
    
    /// Name of the claim being disclosed. If the value is an array element, the key is `nil`.
    public let key: JSONWebValueStorage.Key?
    
    /// The raw encoded JSON bytes of the value (before base64url encoding).
    /// This is stored to ensure consistent hashing regardless of JSON key ordering.
    private let encodedValue: Data
    
    /// Value of the claim being disclosed.
    /// Computed from the stored encoded value bytes.
    public var value: any Sendable {
        // Decode the value from stored bytes
        (try? JSONDecoder().decode(AnyCodable.self, from: encodedValue).value) ?? Data?.none
    }
    
    /// The Base64URL-encoded disclosure in the format: [salt, claim_name, claim_value]
    public var encoded: String {
        let encoder = JSONEncoder()
        encoder.dataEncodingStrategy = .custom { data, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(data.urlBase64EncodedString())
        }
        // Reconstruct the JSON array using the stored value bytes
        var json = Data("[".utf8)
        try? json.append(encoder.encode(salt))
        if let key {
            json.append(Data(",".utf8))
            try? json.append(encoder.encode(key))
        }
        json.append(Data(",".utf8))
        json.append(encodedValue)
        json.append(Data("]".utf8))
        return json.urlBase64EncodedString()
    }
    
    /// Creates a new disclosure with the specified salt, claim name, and value.
    ///
    /// - Parameters:
    ///   - key: Name of the claim (nil for array elements)
    ///   - value: Value of the claim
    ///   - salt: Cryptographically random salt (minimum 16 bytes recommended)
    public init<S>(
        _ key: JSONWebValueStorage.Key? = nil,
        value: String,
        salt: S? = Data?.none
    ) where S: DataProtocol {
        let encodedValue = (try? JSONEncoder.encoder.encode(value)) ?? .init()
        self.init(salt: salt, key: key, encodedValue: encodedValue)
    }
    
    /// Creates a new disclosure with the specified salt, claim name, and value.
    ///
    /// - Parameters:
    ///   - key: Name of the claim (nil for array elements)
    ///   - value: Value of the claim
    ///   - salt: Cryptographically random salt (minimum 16 bytes recommended)
    public init<S>(
        _ key: JSONWebValueStorage.Key? = nil,
        value: Int,
        salt: S? = Data?.none
    ) where S: DataProtocol {
        let encodedValue = (try? JSONEncoder.encoder.encode(value)) ?? .init()
        self.init(salt: salt, key: key, encodedValue: encodedValue)
    }
    
    /// Creates a new disclosure with the specified salt, claim name, and value.
    ///
    /// - Parameters:
    ///   - key: Name of the claim (nil for array elements)
    ///   - value: Value of the claim
    ///   - salt: Cryptographically random salt (minimum 16 bytes recommended)
    public init<S>(
        _ key: JSONWebValueStorage.Key? = nil,
        value: any Sendable,
        salt: S? = Data?.none
    ) throws where S: DataProtocol {
        let encodedValue = try JSONEncoder.encoder.encode(AnyCodable(value))
        self.init(salt: salt, key: key, encodedValue: encodedValue)
    }
    
    /// Creates a new disclosure with the specified salt, claim name, and value.
    ///
    /// - Parameters:
    ///   - key: Name of the claim (nil for array elements)
    ///   - value: Value of the claim
    ///   - salt: Cryptographically random salt (minimum 16 bytes recommended)
    public init<S>(
        _ key: JSONWebValueStorage.Key? = nil,
        value: any JSONWebValueStorage.ValueType,
        salt: S? = Data?.none
    ) throws where S: DataProtocol {
        let encodedValue = try JSONEncoder.encoder.encode(AnyCodable(value))
        self.init(salt: salt, key: key, encodedValue: encodedValue)
    }
    
    /// Internal initializer with pre-encoded value bytes.
    public init<S>(salt: S? = Data?.none, key: JSONWebValueStorage.Key?, encodedValue: Data) where S: DataProtocol {
        self.salt = salt.map { Data($0) } ?? .random(length: 16)
        self.key = key
        self.encodedValue = encodedValue
    }
    
    public init(arrayLiteral elements: (any Sendable)?...) {
        guard elements.count > 1 else {
            self.init(key: nil, encodedValue: Data("null".utf8))
            return
        }
        let salt = JSONWebValueStorage.cast(value: elements[0], as: Data.self) ?? .random(length: 16)
        let key: String?
        let value: any Sendable
        switch elements.count {
        case 2:
            key = nil
            value = elements[1]
        case 3:
            key = JSONWebValueStorage.cast(value: elements[1], as: String.self)
            value = elements[2]
        default:
            key = nil
            value = Data?.none
        }
        // swiftlint:disable:next force_try
        guard let disclosure = try? JSONWebSelectiveDisclosure(key, value: value, salt: salt) else {
            self.init(key: nil, encodedValue: Data("null".utf8))
            assertionFailure("Invalid disclosure")
            return
        }
        self = disclosure
    }
    
    public init(from decoder: any Decoder) throws {
        if let encoded = try? decoder.singleValueContainer().decode(String.self) {
            try self.init(encoded: encoded)
            return
        }
        var container = try decoder.unkeyedContainer()
        guard let salt = try Data(urlBase64Encoded: container.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Salt is not encoded correctly.")
        }
        let key: JSONWebValueStorage.Key?
        let value: any Sendable
        switch container.count {
        case 2:
            key = nil
            value = try container.decode(AnyCodable.self).value
        case 3:
            key = try container.decode(JSONWebValueStorage.Key.self)
            value = try container.decode(AnyCodable.self).value
        default:
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Length of disclosure array is not interpretable.")
        }
        try self.init(key, value: value, salt: salt)
    }
    
    /// Creates a disclosure from its Base64URL-encoded representation.
    ///
    /// This initializer preserves the original encoded value bytes to ensure consistent hashing.
    ///
    /// - Parameter encoded: Base64URL-encoded disclosure string
    /// - Throws: `JSONWebValidationError` if the disclosure cannot be decoded
    public init<S: StringProtocol>(encoded: S) throws {
        guard let data = Data(urlBase64Encoded: encoded) else {
            throw DecodingError.typeMismatch(String.self, .init(codingPath: [], debugDescription: "Disclosure is not encoded as Base64URL."))
        }
        let elements = try Self.extractValueBytes(from: data)
        guard elements.count >= 2, elements.count <= 3 else {
            throw DecodingError.typeMismatch([String].self, .init(codingPath: [], debugDescription: "Disclosure array must have 2 or 3 elements."))
        }
        guard let salt = try Data(urlBase64Encoded: JSONDecoder().decode(String.self, from: elements[0])) else {
            throw DecodingError.typeMismatch(Data.self, .init(codingPath: [], debugDescription: "Salt is not valid base64url."))
        }
        self.salt = salt
        if elements.count == 3 {
            self.key = try JSONDecoder().decode(String.self, from: elements[1])
            self.encodedValue = elements[2]
        } else {
            self.key = nil
            self.encodedValue = elements[1]
        }
    }
    
    /// Extracts the raw JSON bytes of each element from a disclosure JSON array.
    /// Each returned element includes the original bytes (e.g., strings include quotes).
    private static func extractValueBytes(from json: Data) throws -> [Data] {
        var json = json
        guard json.count >= 2, json.removeFirst() == "[", json.removeLast() == "]" else {
            throw DecodingError.typeMismatch([String].self, .init(codingPath: [], debugDescription: "Not a JSON array."))
        }
        var elements: [Data] = [], start = 0, i = 0, inStr = false, depth = 0
        while i < json.count {
            let b = json[json.startIndex.advanced(by: i)]
            if inStr {
                if b == "\\" { i += 1 } else if b == "\"" { inStr = false }
            } else if b == "\"" { inStr = true }
            else if b == "[" || b == "{" { depth += 1 }
            else if b == "]" || b == "}" { depth -= 1 }
            else if b == ",", depth == 0 {
                elements.append(Data(json[json.startIndex.advanced(by: start) ..< json.startIndex.advanced(by: i)]))
                start = i + 1
            }
            i += 1
        }
        elements.append(Data(json[json.startIndex.advanced(by: start)...]))
        return elements
    }
    
    /// The digest of this disclosure with given algorithm.
    ///
    /// This digest is used in the SD-JWT to replace the actual claim value.
    /// Uses the stored encoded bytes for consistent hashing.
    public func digest<H: HashFunction>(using _: H.Type) -> Data {
        H.hash(data: Data(encoded.utf8)).data
    }
    
    /// The digest of this disclosure with given algorithm.
    ///
    /// This digest is used in the SD-JWT to replace the actual claim value.
    /// Uses the stored encoded bytes for consistent hashing.
    public func digest(using hashFunction: any HashFunction.Type) -> Data {
        hashFunction.hash(data: Data(encoded.utf8)).data
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.unkeyedContainer()
        try container.encode(salt.urlBase64EncodedString())
        if let key { try container.encode(key) }
        try container.encode(AnyCodable(value))
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(salt)
        hasher.combine(key)
        hasher.combine(encodedValue)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.salt == rhs.salt && lhs.key == rhs.key && lhs.encodedValue == rhs.encodedValue
    }
}

public struct JSONWebSelectiveDisclosureList: RandomAccessCollection, Hashable, Sendable {
    public let hashFunction: any HashFunction.Type
    private var items: OrderedDictionary<Data, JSONWebSelectiveDisclosure>
    
    public var hashes: [Data] {
        .init(items.keys)
    }
    
    public var disclosures: [JSONWebSelectiveDisclosure] {
        .init(items.values)
    }
    
    public var startIndex: Int {
        items.elements.startIndex
    }
    
    public var endIndex: Int {
        items.elements.endIndex
    }
    
    public var isEmpty: Bool {
        items.isEmpty
    }
    
    public var count: Int {
        items.count
    }
    
    public subscript(position: Int) -> (Data, JSONWebSelectiveDisclosure) {
        items.elements[position]
    }
    
    public subscript(hash: Data) -> JSONWebSelectiveDisclosure? {
        items[hash]
    }
    
    public init(_ items: [JSONWebSelectiveDisclosure], hashFunction: any HashFunction.Type) throws {
        self.hashFunction = hashFunction
        self.items = .init(uniqueKeysWithValues: items.map { ($0.digest(using: hashFunction), $0) })
    }
    
    public static func == (lhs: JSONWebSelectiveDisclosureList, rhs: JSONWebSelectiveDisclosureList) -> Bool {
        lhs.hashFunction == rhs.hashFunction && lhs.disclosures == rhs.disclosures
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine((hashFunction as? any NamedHashFunction.Type)?.identifier)
        hasher.combine(disclosures)
    }
    
    public func index(for hash: Data) -> Int? {
        items.index(forKey: hash)
    }
    
    public mutating func reserveCapacity(_ minimumCapacity: Int) {
        items.reserveCapacity(minimumCapacity)
    }
    
    public mutating func append(_ disclosureList: JSONWebSelectiveDisclosureList) throws {
        guard hashFunction == disclosureList.hashFunction else {
            throw CryptoKitError.incorrectParameterSize
        }
        items.merge(disclosureList.items, uniquingKeysWith: { $1 })
    }
    
    @discardableResult
    public mutating func append(_ disclosure: JSONWebSelectiveDisclosure) -> Data {
        let hash = disclosure.digest(using: hashFunction)
        items.updateValue(disclosure, forKey: hash)
        return hash
    }
    
    @discardableResult
    public mutating func insert(_ disclosure: JSONWebSelectiveDisclosure, at index: Int) -> Data {
        let hash = disclosure.digest(using: hashFunction)
        items.updateValue(disclosure, forKey: hash, insertingAt: index)
        return hash
    }
    
    public mutating func remove(_ disclosure: JSONWebSelectiveDisclosure) {
        let hash = disclosure.digest(using: hashFunction)
        items.removeValue(forKey: hash)
    }
    
    public mutating func remove(digest: Data) {
        items.removeValue(forKey: digest)
    }
    
    public mutating func remove(at index: Int) {
        items.remove(at: index)
    }
}

extension HashFunction {
    /// Generates a random decoy digest for SD-JWT as defined in RFC 9901 Section 4.2.
    ///
    /// Decoy digests are used to obscure the actual number of claims in an SD-JWT.
    /// They are created from cryptographically secure random numbers and have no
    /// corresponding disclosure.
    ///
    /// - Returns: A random digest with the same size as the hash function output.
    static func generateDecoyDigest() -> Data {
        .random(length: Digest.byteCount)
    }
}
