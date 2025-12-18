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
                
        init(_ key: some JSONWebKey) {
            let thumbprint = (try? key.thumbprint(format: .jwk, using: SHA256.self).data) ?? Data(UUID().uuidString.utf8)
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
        keySet.values.elements
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
    public init(keys: [any JSONWebKey]) {
        self.init(keys)
    }
    
    /// Initializes JWKSet using given array of key.
    ///
    /// - Parameter keys: An array of JWKs.
    public init<T>(keys: T) where T: Sequence, T.Element == any JSONWebKey {
        self.init(keys)
    }
    
    public init(arrayLiteral elements: (any JSONWebKey)...) {
        self.init(elements)
    }
    
    /// Initializes an empty JWKSet.
    public init() {
        self.init([])
    }
    
    private init<T>(_ keys: T) where T: Sequence, T.Element == any JSONWebKey {
        self.keySet = .init(
            keys.map {
                (.init($0), $0)
            },
            uniquingKeysWith: { first, second in
                // Prefer private key over public one!
                second.isAsymmetricPrivateKey ? second : first
            }
        )
    }
    
    private init(_ keySet: OrderedDictionary<Identification, any JSONWebKey>) {
        self.keySet = keySet
    }
    
    /// Initializes JWKSet using given array of key.
    ///
    /// - Parameter keys: An array of JWKs.
    public init<T>(keys: T) where T: Sequence, T.Element: JSONWebKey {
        self.init(keys.map { $0 as any JSONWebKey })
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let keyArray = try container.decode([AnyJSONWebKey].self, forKey: .keys)
        self.init(keyArray.map { $0.specialized() })
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        var nested = container.nestedUnkeyedContainer(forKey: .keys)
        try forEach { try nested.encode($0) }
    }
    
    public func hash(into hasher: inout Hasher) {
        forEach { hasher.combine($0) }
    }

    /// Returns the key matches with given thumbprint.
    ///
    /// - Parameter thumbprint: The thumbprint of the key.
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
    
    /// Returns the key matches with given keyId.
    ///
    /// - Note: If the keyID is an URI of JWK thumbprint, it will be matched
    //     with thumbprint even if `kid` field is not set.
    /// - Parameter keyId: The keyId of the key.
    /// - Returns: The key matches with given keyId.
    public subscript(keyId keyId: some StringProtocol) -> (any JSONWebKey)? {
        let jwkThumbprintPrefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
        let thumbprintPrefixLength = jwkThumbprintPrefix.count
        if keyId.hasPrefix(jwkThumbprintPrefix),
           let thumbprint = Data(urlBase64Encoded: keyId.dropFirst(thumbprintPrefixLength)),
           let key = self[thumbprint: thumbprint]
        {
            return key
        }
        return keySet.values.last { key in
            guard let itemKeyId = key.keyId else {
                return false
            }
            return itemKeyId == keyId
        }
    }
    
    /// Returns the key set using the criteria contained by the given closure.
    ///
    /// - Parameter isIncluded:
    /// - Returns:
    public func filter(_ isIncluded: (any JSONWebKey) -> Bool) -> JSONWebKeySet {
        let dictionary = keySet.filter {
            isIncluded($1)
        }
        return .init(dictionary)
    }
    
    /// Returns the key set that contains keys that can be used
    /// for the given algorithm.
    public func filter(algorithm: some JSONWebAlgorithm) -> JSONWebKeySet {
        guard let keyType = algorithm.keyType else { return [] }
        return filter {
            $0.keyType == keyType && (algorithm.curve == nil || $0.curve == algorithm.curve)
        }
    }
    
    /// Returns the key set that contains keys that can be used to verify/decrypt
    /// of JWS/JWE with given header.
    ///
    /// - Parameter header: The JOSE header of JWS or JWE.
    /// - Returns: The key set that contains keys that can be used
    ///     to verify/decrypt.
    public func matches(for header: JOSEHeader) -> JSONWebKeySet {
        var candidates: JSONWebKeySet
        
        if let algorithm = header.algorithm {
            candidates = filter(algorithm: algorithm)
        } else {
            candidates = self
        }
        if let keyId = header.keyId, let key = candidates[keyId: keyId] {
            return [key]
        }
        
        if let key = candidates.first(where: { $0.isMatched(to: header) }) {
            return [key]
        }
        return candidates
    }
    
    /// Merges keyset with another keyset, If the are duplicate keys
    /// by thumbprint or keyId, the `combine` closure will be called.
    ///
    /// - Parameters:
    ///   - other: the other JWK set.
    ///   - combine: The closure that will be called for duplicate keys.
    public mutating func merge(_ other: JSONWebKeySet, uniquingKeysWith combine: (any JSONWebKey, any JSONWebKey) throws -> any JSONWebKey) rethrows {
        try keySet.merge(other.keySet) {
            try combine($0, $1)
        }
    }
    
    /// Returns a new keyset that is the result of merging keyset with another keyset,
    /// If the are duplicate keys by thumbprint or keyId, the `combine` closure will be called.
    ///
    /// - Parameters:
    ///  - other: the other JWK set.
    /// - combine: The closure that will be called for duplicate keys.
    /// - Returns: A new keyset that is the result of merging the keyset with another keyset.
    public func merging(_ other: JSONWebKeySet, uniquingKeysWith combine: (any JSONWebKey, any JSONWebKey) throws -> any JSONWebKey) rethrows -> JSONWebKeySet {
        try .init(keySet.merging(other.keySet) {
            try combine($0, $1)
        })
    }
    
    /// Adds a new key to the keyset.
    ///
    /// If another key with the same thumbprint or keyId exists, it will be removed
    /// and the new key will be appended.
    ///
    /// - Parameter key: The new key to be appended.
    public mutating func append(_ key: some JSONWebKey) {
        keySet[.init(key)] = key
    }
    
    /// Returns a new keyset that is the result of appending a new key to the keyset.
    ///
    /// - Parameter key: The new key to be appended.
    /// - Returns: A new keyset that is the result of appending a new key to the keyset.
    public func appending(_ key: some JSONWebKey) -> Self {
        var result = self
        result.append(key)
        return result
    }
    
    /// Adds a new key to the keyset at the specified position.
    ///
    /// If the key is already exists in the keyset, the current index will be returned.
    ///
    /// - Parameters:
    ///  - key: The new key to be inserted.
    ///  - index: The position to insert the key.
    ///  - Returns: The index of the inserted key.
    @discardableResult
    public mutating func insert(_ key: some JSONWebKey, at index: Int) -> Int {
        keySet.updateValue(key, forKey: .init(key), insertingAt: index).index
    }
    
    /// Returns a new keyset that is the result of inserting a new key to the keyset at the specified position.
    ///
    /// If the key is already exists in keyset, the result will be the same keyset with replacement of new key.
    /// - Parameters:
    ///   - key: The new key to be inserted.
    ///   - index: The position to insert the key.
    /// - Returns: A new keyset that is the result of inserting a new key to the keyset at the specified position.
    public func inserting(_ key: some JSONWebKey, at index: Int) -> Self {
        var result = self
        result.insert(key, at: index)
        return result
    }
    
    /// Removes the key if a key with same thumbprint exists in keyset and retruns it.
    ///
    /// - Parameter key: The key to be removed.
    /// - Throws: `DecodingError` if thumbprint of key can not be calculated
    /// - Returns: The removed key.
    @discardableResult
    public mutating func remove(_ key: some JSONWebKey) throws -> (any JSONWebKey)? {
        try remove(thumbprint: key.thumbprint(format: .jwk, using: SHA256.self).data)
    }
    
    /// Returns a new keyset that is the result of removing the key if a key with same thumbprint exists in keyset.
    ///
    /// - Parameter key: The key to be removed.
    /// - Returns: A new keyset that is the result of removing the key if a key with same thumbprint exists in keyset.
    public func removing(_ key: some JSONWebKey) throws -> Self {
        var result = self
        try result.remove(key)
        return result
    }
    
    /// Removes key with given thumbprint  in keyset and retruns it.
    ///
    /// - Parameter thumbprint: The thumbprint of the key.
    /// - Returns: The removed key.
    @discardableResult
    public mutating func remove(thumbprint: Data) -> (any JSONWebKey)? {
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
    
    /// Returns a new keyset that is the result of removing key with given thumbprint in keyset.
    ///
    /// - Parameter thumbprint: The thumbprint of the key.
    /// - Returns: A new keyset that is the result of removing key with given thumbprint in keyset.
    public func removing(thumbprint: Data) -> Self {
        var result = self
        result.remove(thumbprint: thumbprint)
        return result
    }
}

public func == (lhs: some Sequence<any JSONWebKey>, rhs: some Sequence<any JSONWebKey>) -> Bool {
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
            .init(keys: keys[bounds])
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
        case is any JSONWebSymmetricSealingKey:
            nil
        default:
            self
        }
    }
    
    fileprivate func isMatched(to header: JOSEHeader) -> Bool {
        if let keyId = header.keyId, self.keyId == keyId {
            return true
        }
        if let jwkThumbprint = try? header.key?.thumbprint(format: .jwk, using: SHA256.self), (try? thumbprint(format: .jwk, using: SHA256.self)) == jwkThumbprint {
            return true
        }
        if let x5t = header.certificateThumbprint, x5t == (try? thumbprint(format: .spki, using: hashFunction(of: x5t)).data) {
            return true
        }
#if canImport(X509) || canImport(CommonCrypto)
        if let x5t = try? header.certificateChain.first?.thumbprint(format: .spki, using: SHA256.self), x5t == (try? thumbprint(format: .spki, using: SHA256.self)) {
            return true
        }
#endif
        return false
    }
}

func hashFunction<D: DataProtocol>(of data: D) throws -> any HashFunction.Type {
    return switch data.count {
    case SHA256.byteCount:
        SHA256.self
    case SHA384.byteCount:
        SHA384.self
    case SHA512.byteCount:
        SHA512.self
    case Insecure.SHA1.byteCount:
        Insecure.SHA1.self
    default:
        throw CryptoKitError.incorrectParameterSize
    }
}
