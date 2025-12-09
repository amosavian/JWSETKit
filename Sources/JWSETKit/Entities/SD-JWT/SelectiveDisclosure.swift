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
public struct JSONWebSelectiveDisclosure: Hashable, Codable, ExpressibleByArrayLiteral, Sendable {
    /// Cryptographically random salt used to prevent brute-force attacks on claim values.
    /// Minimum recommended length is 128 bits (16 bytes).
    public let salt: Data
    
    /// Name of the claim being disclosed. If the value is an array element, the key is `nil`.
    public let key: JSONWebValueStorage.Key?
    
    /// Value of the claim being disclosed.
    public let value: any Sendable
    
    /// The Base64URL-encoded disclosure in the format: [salt, claim_name, claim_value]
    public var encoded: String {
        get throws {
            try JSONEncoder.encoder.encode(self).urlBase64EncodedString()
        }
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
    ) where S: DataProtocol {
        self.key = key
        self.value = value
        self.salt = salt.map { Data($0) } ?? .random(length: 16)
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
    ) where S: DataProtocol {
        self.key = key
        self.value = value
        self.salt = salt.map { Data($0) } ?? .random(length: 16)
    }
    
    public init(arrayLiteral elements: (any Sendable)?...) {
        guard elements.count > 1 else {
            self.init(value: Data?.none)
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
        self.init(key, value: value, salt: salt)
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
        self.init(key, value: value, salt: salt)
    }
    
    /// Creates a disclosure from its Base64URL-encoded representation.
    ///
    /// - Parameter encoded: Base64URL-encoded disclosure string
    /// - Throws: `JSONWebValidationError` if the disclosure cannot be decoded
    public init<S: StringProtocol>(encoded: S) throws {
        guard let data = Data(urlBase64Encoded: encoded) else {
            throw DecodingError.typeMismatch(String.self, .init(codingPath: [], debugDescription: "Encoded string can not be decoded."))
        }
        self = try JSONDecoder().decode(Self.self, from: data)
    }
    
    /// The digest of this disclosure with given algorithm.
    ///
    /// This digest is used in the SD-JWT to replace the actual claim value.
    public func digest<H: HashFunction>(using _: H.Type) throws -> Data {
        try H.hash(data: Data(encoded.utf8)).data
    }
    
    /// The digest of this disclosure with given algorithm.
    ///
    /// This digest is used in the SD-JWT to replace the actual claim value.
    public func digest(using hashFunction: any HashFunction.Type) throws -> Data {
        try hashFunction.hash(data: Data(encoded.utf8)).data
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
        if let value = value as? any Hashable {
            hasher.combine(value)
        }
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        let lhsValue: any Equatable
        switch lhs.value {
        case let val as any Equatable:
            lhsValue = val
        default:
            return false
        }
        return lhs.salt == rhs.salt && lhs.key == rhs.key && lhsValue.isEqual(to: rhs.value as? any Equatable)
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
        self.items = try .init(uniqueKeysWithValues: items.map { try ($0.digest(using: hashFunction), $0) })
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
    public mutating func append(_ disclosure: JSONWebSelectiveDisclosure) throws -> Data {
        let hash = try disclosure.digest(using: hashFunction)
        items.updateValue(disclosure, forKey: hash)
        return hash
    }
    
    @discardableResult
    public mutating func insert(_ disclosure: JSONWebSelectiveDisclosure, at index: Int) throws -> Data {
        let hash = try disclosure.digest(using: hashFunction)
        items.updateValue(disclosure, forKey: hash, insertingAt: index)
        return hash
    }
    
    public mutating func remove(_ disclosure: JSONWebSelectiveDisclosure) throws {
        let hash = try disclosure.digest(using: hashFunction)
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
