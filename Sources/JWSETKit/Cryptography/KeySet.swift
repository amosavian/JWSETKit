//
//  KeySet.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2/2/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Collections
import Crypto

/// A JWK Set is a JSON object that represents a set of JWKs.
///
/// The JSON object MUST have a "keys" member, with its value being an array of JWKs.
/// This JSON object MAY contain whitespace and/or line breaks.
public struct JSONWebKeySet: Codable, Hashable, ExpressibleByArrayLiteral {
    enum CodingKeys: CodingKey {
        case keys
    }
    
    fileprivate enum Identification: Hashable, Sendable {
        case thumbprint(Data)
        case id(kid: String, kty: JSONWebKeyType, curve: JSONWebKeyCurve?, use: JSONWebKeyUsage?, thumbprint: Data)
                
        init(_ key: some JSONWebKey) throws {
            let thumbprint = try key.thumbprint(format: .jwk, using: SHA256.self).data
            if let keyId = key.keyId, let kty = key.keyType {
                self = .id(kid: keyId, kty: kty, curve: key.curve, use: key.keyUsage, thumbprint: thumbprint)
            } else {
                self = .thumbprint(thumbprint)
            }
        }
        
        func hash(into hasher: inout Hasher) {
            switch self {
            case .thumbprint(let data):
                hasher.combine(data)
            case .id(let kid, _, _, _, _):
                hasher.combine(kid)
            }
        }
    }
    
    /// The value of the "keys" parameter is an array of JWK values.
    ///
    /// By default, the order of the JWK values within the array does not imply
    /// an order of preference among them, although applications of JWK Sets
    /// can choose to assign a meaning to the order for their purposes, if desired.
    public var keys: [any JSONWebKey] {
        Array(keySet.values)
    }
    
    public var publicKeyset: JSONWebKeySet {
        let publicKeys = keySet.compactMapValues { key in
            key.publicKey()
        }
        return Self(publicKeys)
    }
    
    fileprivate var keySet: OrderedDictionary<Identification, any JSONWebKey>
    
    /// Initializes JWKSet using given array of key.
    ///
    /// - Parameter keys: An array of JWKs.
    public init(keys: [any JSONWebKey]) throws {
        try self.init(keys)
    }
    
    /// Initializes JWKSet using given array of key.
    ///
    /// - Parameter keys: An array of JWKs.
    public init<T>(keys: T) throws where T: Sequence, T.Element == any JSONWebKey {
        try self.init(keys)
    }
    
    public init(arrayLiteral elements: (any JSONWebKey)...) {
        try! self.init(elements)
    }
    
    public init() {
        try! self.init([])
    }
    
    private init<T>(_ keys: T) throws where T: Sequence, T.Element == any JSONWebKey {
        self.keySet = try .init(
            keys.map {
                try (.init($0), $0)
            },
            uniquingKeysWith: { first, second in
                // Prefer private key over public one!
                
                // Both RSA and ECC has `"d"` parameter with different meaning,
                // but checking one of them for the sake of null check is OK.
                second.privateKey != nil ? second : first
            }
        )
    }
    
    private init(_ keySet: OrderedDictionary<Identification, any JSONWebKey>) {
        self.keySet = keySet
    }
    
    /// Initializes JWKSet using given array of key.
    ///
    /// - Parameter keys: An array of JWKs.
    public init<T>(keys: T) throws where T: Sequence, T.Element: JSONWebKey {
        try self.init(keys.map { $0 as any JSONWebKey })
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let keys = try container.decode([AnyJSONWebKey].self, forKey: .keys)
        try self.init(keys.map { $0.specialized() })
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        var nested = container.nestedUnkeyedContainer(forKey: .keys)
        try forEach { try nested.encode($0) }
    }
    
    public func hash(into hasher: inout Hasher) {
        forEach { hasher.combine($0) }
    }
    
    public subscript(thumbprint thumbprint: Data) -> (any JSONWebKey)? {
        if let key = keySet[.thumbprint(thumbprint)] {
            return key
        } else {
            for (id, key) in keySet {
                switch id {
                case .id(_, _, _, _, let thumb):
                    if thumb == thumbprint {
                        return key
                    }
                case .thumbprint:
                    break
                }
            }
        }
        return nil
    }
    
    public subscript(keyId keyId: String) -> (any JSONWebKey)? {
        keySet.values.last(where: { $0.keyId == keyId })
    }
    
    public func filter(_ isIncluded: (any JSONWebKey) -> Bool) -> JSONWebKeySet {
        let dictionary = keySet.filter {
            isIncluded($1)
        }
        return .init(dictionary)
    }
    
    public func filter(algorithm: some JSONWebAlgorithm) -> JSONWebKeySet {
        guard let keyType = algorithm.keyType else { return [] }
        return filter {
            $0.keyType == keyType && $0.curve == algorithm.curve
        }
    }
    
    public func match(for algorithm: some JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        let candidates = filter(algorithm: algorithm)
        if let id {
            return candidates[keyId: id]
        } else {
            return candidates.last
        }
    }
    
    public mutating func merge(_ other: JSONWebKeySet, uniquingKeysWith combine: (any JSONWebKey, any JSONWebKey) throws -> any JSONWebKey) rethrows {
        try keySet.merge(other.keySet) {
            try combine($0, $1)
        }
    }
    
    public func merging(_ other: JSONWebKeySet, uniquingKeysWith combine: (any JSONWebKey, any JSONWebKey) throws -> any JSONWebKey) rethrows -> JSONWebKeySet {
        try .init(keySet.merging(other.keySet) {
            try combine($0, $1)
        })
    }
    
    public mutating func append(_ key: some JSONWebKey) throws {
        try keySet[.init(key)] = key
    }
    
    public func appending(_ key: some JSONWebKey) throws -> Self {
        var result = self
        try result.append(key)
        return result
    }
    
    public mutating func insert(_ key: some JSONWebKey, at index: Int) throws {
        try keySet.updateValue(key, forKey: .init(key), insertingAt: index)
    }
    
    public func inserting(_ key: some JSONWebKey, at index: Int) throws -> Self {
        var result = self
        try result.insert(key, at: index)
        return result
    }
    
    @discardableResult
    public mutating func remove(_ key: some JSONWebKey) throws -> (any JSONWebKey)? {
        try remove(thumbprint: key.thumbprint(format: .jwk, using: SHA256.self).data)
    }
    
    public func removing(_ key: some JSONWebKey) throws -> Self {
        var result = self
        try result.remove(key)
        return result
    }
    
    @discardableResult
    public mutating func remove(thumbprint: Data) throws -> (any JSONWebKey)? {
        if let key = keySet.removeValue(forKey: .thumbprint(thumbprint)) {
            return key
        } else {
            for (id, _) in keySet {
                switch id {
                case .id(_, _, _, _, let thumb):
                    if thumb == thumbprint {
                        return keySet.removeValue(forKey: id)
                    }
                case .thumbprint:
                    break
                }
            }
        }
        return nil
    }
    
    public func removing(thumbprint: Data) throws -> Self {
        var result = self
        try result.remove(thumbprint: thumbprint)
        return result
    }
}

public func == (lhs: some Sequence<JSONWebKey>, rhs: some Sequence<JSONWebKey>) -> Bool {
    Set(lhs.map(\.storage)) == Set(rhs.map(\.storage))
}

extension JSONWebKeySet: MutableCollection, RandomAccessCollection {
    public var indices: Range<Int> {
        keySet.elements.indices
    }
    
    public var startIndex: Int {
        keySet.elements.startIndex
    }
    
    public var endIndex: Int {
        keySet.elements.endIndex
    }
    
    public var isEmpty: Bool {
        keySet.elements.isEmpty
    }
    
    public var count: Int {
        keySet.elements.count
    }
    
    public subscript(position: Int) -> any JSONWebKey {
        get {
            keySet.values[position]
        }
        set {
            keySet.values[position] = newValue
        }
    }
    
    public subscript(bounds: Range<Int>) -> JSONWebKeySet {
        get {
            try! .init(keys: keys[bounds])
        }
        set {
            bounds.forEach { keySet.values[$0] = newValue[$0 - bounds.lowerBound] }
        }
    }
    
    public mutating func partition(by belongsInSecondPartition: (any JSONWebKey) throws -> Bool) rethrows -> Int {
        try keySet.elements.partition {
            try belongsInSecondPartition($0.value)
        }
    }
    
    public mutating func swapAt(_ i: Int, _ j: Int) {
        keySet.elements.swapAt(i, j)
    }
}

extension JSONWebKey {
    fileprivate func publicKey() -> (any JSONWebKey)? {
        switch self {
        case is any JSONWebKeySymmetric:
            nil
        case let key as any JSONWebSigningKey:
            key.publicKey
        case let key as any JSONWebDecryptingKey:
            key.publicKey
        case is any JSONWebSealingKey:
            nil
        default:
            self
        }
    }
}

extension [any JSONWebKey] {
    func match(for algorithm: some JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        try? JSONWebKeySet(keys: self).match(for: algorithm, id: id)
    }
}

extension [any JSONWebSigningKey] {
    func match(for algorithm: some JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        try? JSONWebKeySet(keys: self).match(for: algorithm, id: id) as? Self.Element
    }
}

extension [any JSONWebValidatingKey] {
    func match(for algorithm: some JSONWebAlgorithm, id: String? = nil) -> Self.Element? {
        try? JSONWebKeySet(keys: self).match(for: algorithm, id: id) as? Self.Element
    }
}

#if canImport(Foundation.NSURLSession)
extension JSONWebKeySet {
    public init(url: URL) async throws {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let _ = response as? HTTPURLResponse else {
            throw URLError(.cannotParseResponse)
        }
        self = try JSONDecoder().decode(Self.self, from: data)
    }
}
#endif
