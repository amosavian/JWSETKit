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
        /// A key without a `kid`, identified by its thumbprint.
        case thumbprint(Data)
        
        /// A `kid`-identified key. Identity is `(kid, kty, curve, use)`.
        case id(kid: String, kty: JSONWebKeyType, curve: JSONWebKeyCurve?, use: JSONWebKeyUsage?)
        
        init(_ key: some JSONWebKey) {
            if let keyId = key.keyId, let kty = key.keyType {
                self = .id(kid: keyId, kty: kty, curve: key.curve, use: key.keyUsage)
            } else {
                self = .thumbprint((try? key.thumbprint(format: .jwk, using: SHA256.self).data) ?? Data(UUID().uuidString.utf8))
            }
        }
        
        func hash(into hasher: inout Hasher) {
            switch self {
            case .thumbprint(let data):
                hasher.combine(data)
            case .id(let kid, _, _, _):
                hasher.combine(kid)
            }
        }
    }
    
    /// Backing storage with a small-set fast path, à la `String`'s short-string optimization.
    ///
    /// `empty`/`single` hold no `OrderedDictionary` and never compute a key's SHA-256 thumbprint —
    /// the common sign/verify case (one key in hand) allocates nothing extra. The set promotes to
    /// `multiple` — the fully-indexed, deduplicating `OrderedDictionary` — only on the second
    /// distinct key, where keyed lookup and dedup actually earn their cost (JWKS, key rotation).
    fileprivate enum Storage {
        case empty
        case single(any JSONWebKey)
        case multiple(OrderedDictionary<Identification, any JSONWebKey>)
        
        /// Picks the smallest representation for a deduplicated dictionary, so single/empty sets
        /// shed the `OrderedDictionary` (and its hash-table allocation).
        static func normalized(_ keySet: OrderedDictionary<Identification, any JSONWebKey>) -> Storage {
            switch keySet.count {
            case 0: .empty
            case 1: .single(keySet.values[0])
            default: .multiple(keySet)
            }
        }
    }
    
    fileprivate var storage: Storage
    
    /// The value of the "keys" parameter is an array of JWK values.
    ///
    /// By default, the order of the JWK values within the array does not imply
    /// an order of preference among them, although applications of JWK Sets
    /// can choose to assign a meaning to the order for their purposes, if desired.
    public var keys: [any JSONWebKey] {
        switch storage {
        case .empty:
            []
        case .single(let key):
            [key]
        case .multiple(let keySet):
            keySet.values.elements
        }
    }
    
    public var publicKeyset: JSONWebKeySet {
        Self(keys: keys.compactMap { $0.publicKey() })
    }
    
    /// Builds the deduplicating `OrderedDictionary` for the `multiple` case.
    private static func index<T>(_ keys: T) -> OrderedDictionary<Identification, any JSONWebKey> where T: Sequence, T.Element == any JSONWebKey {
        .init(
            keys.map { (.init($0), $0) },
            uniquingKeysWith: { first, second in
                // Prefer private key over public one!
                second.isAsymmetricPrivateKey ? second : first
            }
        )
    }
    
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
        self.storage = .empty
    }
    
    /// Initializes a JWKSet holding exactly one key.
    public init(key: some JSONWebKey) {
        self.storage = .single(key)
    }
    
    private init<T>(_ keys: T) where T: Sequence, T.Element == any JSONWebKey {
        var iterator = keys.makeIterator()
        guard let first = iterator.next() else {
            self.storage = .empty
            return
        }
        guard iterator.next() != nil else {
            self.storage = .single(first)
            return
        }
        // Two or more inputs: index + deduplicate, then normalize (dedup may collapse to one).
        self.storage = .normalized(Self.index(keys))
    }
    
    private init(_ keySet: OrderedDictionary<Identification, any JSONWebKey>) {
        self.storage = .normalized(keySet)
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
        switch storage {
        case .empty:
            return nil
        case .single(let key):
            return (try? key.thumbprint(format: .jwk, using: SHA256.self).data) == thumbprint ? key : nil
        case .multiple(let keySet):
            if let key = keySet[.thumbprint(thumbprint)] {
                return key
            }
            return keySet.values.first {
                (try? $0.thumbprint(format: .jwk, using: SHA256.self).data) == thumbprint
            }
        }
    }
    
    /// Returns the key matches with given keyId.
    ///
    /// - Note: If the keyID is an URI of JWK thumbprint, it will be matched
    ///     with thumbprint even if `kid` field is not set.
    /// - Parameter keyId: The keyId of the key.
    /// - Returns: The key matches with given keyId.
    private static let jwkThumbprintPrefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
    
    public subscript(keyId keyId: some StringProtocol) -> (any JSONWebKey)? {
        if keyId.hasPrefix(Self.jwkThumbprintPrefix),
           let thumbprint = Data(urlBase64Encoded: keyId.dropFirst(Self.jwkThumbprintPrefix.count)),
           let key = self[thumbprint: thumbprint]
        {
            return key
        }
        // Avoid materializing the `keys` array for the small-set cases.
        switch storage {
        case .empty:
            return nil
        case .single(let key):
            return key.keyId.map { $0 == keyId } == true ? key : nil
        case .multiple(let keySet):
            return keySet.values.last { $0.keyId.map { $0 == keyId } == true }
        }
    }
    
    /// Returns the key set using the criteria contained by the given closure.
    ///
    /// - Parameter isIncluded:
    /// - Returns:
    public func filter(_ isIncluded: (any JSONWebKey) -> Bool) -> JSONWebKeySet {
        .init(keys.filter(isIncluded))
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
        switch storage {
        case .empty:
            return []
        case .single(let key):
            return key.isCompatible(with: header) ? self : []
        case .multiple:
            if let key = first(where: { $0.isMatched(to: header) && $0.isCompatible(with: header) }) {
                return [key]
            }
            return header.algorithm.map { filter(algorithm: $0) } ?? self
        }
    }
    
    /// Resolves the single best-matching key for `header` without building an intermediate
    /// `JSONWebKeySet`. Used by signing, which needs exactly one key; `matches(for:)` is for
    /// verification, which may try several candidates (key rotation, RFC 7515 Appendix D).
    func firstMatch(for header: JOSEHeader) -> (any JSONWebKey)? {
        switch storage {
        case .empty:
            nil
        case .single(let key):
            key.isCompatible(with: header) ? key : nil
        case .multiple:
            matches(for: header).first
        }
    }
    
    /// Merges keyset with another keyset, If the are duplicate keys
    /// by thumbprint or keyId, the `combine` closure will be called.
    ///
    /// - Parameters:
    ///   - other: the other JWK set.
    ///   - combine: The closure that will be called for duplicate keys.
    public mutating func merge(_ other: JSONWebKeySet, uniquingKeysWith combine: (any JSONWebKey, any JSONWebKey) throws -> any JSONWebKey) rethrows {
        try mutateIndexed { keySet in
            try keySet.merge(other.indexed) {
                try combine($0, $1)
            }
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
        var result = self
        try result.merge(other, uniquingKeysWith: combine)
        return result
    }
    
    /// The keys as a deduplicating `OrderedDictionary`, materializing one for the small-set cases.
    fileprivate var indexed: OrderedDictionary<Identification, any JSONWebKey> {
        switch storage {
        case .empty, .single:
            Self.index(keys)
        case .multiple(let keySet):
            keySet
        }
    }
    
    /// Mutates the keys through an `OrderedDictionary` (materialized for small-set cases), then
    /// renormalizes back to the smallest storage case so single/empty sets shed the dictionary.
    private mutating func mutateIndexed(_ body: (inout OrderedDictionary<Identification, any JSONWebKey>) throws -> Void) rethrows {
        var keySet = indexed
        try body(&keySet)
        self = .init(keySet)
    }
    
    /// Adds a new key to the keyset.
    ///
    /// If another key with the same thumbprint or keyId exists, it will be removed
    /// and the new key will be appended.
    ///
    /// - Parameter key: The new key to be appended.
    public mutating func append(_ key: some JSONWebKey) {
        mutateIndexed { $0[.init(key)] = key }
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
        var result = 0
        mutateIndexed { result = $0.updateValue(key, forKey: .init(key), insertingAt: index).index }
        return result
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
        var removed: (any JSONWebKey)?
        mutateIndexed { keySet in
            if let key = keySet.removeValue(forKey: .thumbprint(thumbprint)) {
                removed = key
                return
            }
            for (id, key) in keySet where (try? key.thumbprint(format: .jwk, using: SHA256.self).data) == thumbprint {
                removed = keySet.removeValue(forKey: id)
                return
            }
        }
        return removed
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
        keys.indices
    }
    
    public var startIndex: Int {
        0
    }
    
    public var endIndex: Int {
        count
    }
    
    public var isEmpty: Bool {
        switch storage {
        case .empty: true
        case .single: false
        case .multiple(let keySet): keySet.isEmpty
        }
    }
    
    public var count: Int {
        switch storage {
        case .empty: 0
        case .single: 1
        case .multiple(let keySet): keySet.count
        }
    }
    
    private mutating func withMutableKeys<R>(_ body: (inout [any JSONWebKey]) throws -> R) rethrows -> R {
        var elements = keys
        let result = try body(&elements)
        self = .init(elements)
        return result
    }
    
    public subscript(position: Int) -> any JSONWebKey {
        get {
            switch storage {
            case .empty:
                preconditionFailure("Index out of range")
            case .single(let key):
                precondition(position == 0, "Index out of range")
                return key
            case .multiple(let keySet):
                return keySet.values[position]
            }
        }
        set {
            withMutableKeys { $0[position] = newValue }
        }
    }
    
    public subscript(bounds: Range<Int>) -> JSONWebKeySet {
        get {
            .init(keys: Array(keys[bounds]))
        }
        set {
            withMutableKeys { elements in
                bounds.forEach { elements[$0] = newValue[$0 - bounds.lowerBound] }
            }
        }
    }
    
    public mutating func partition(by belongsInSecondPartition: (any JSONWebKey) throws -> Bool) rethrows -> Int {
        try withMutableKeys { try $0.partition(by: belongsInSecondPartition) }
    }
    
    public mutating func swapAt(_ i: Int, _ j: Int) {
        withMutableKeys { $0.swapAt(i, j) }
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
    
    /// Whether this key can be used with the header's algorithm (matching key type and, when the
    /// algorithm names a curve, curve). A header without an algorithm imposes no constraint.
    fileprivate func isCompatible(with header: JOSEHeader) -> Bool {
        guard let algorithm = header.algorithm, let keyType = algorithm.keyType else { return true }
        // swiftformat:disable:next redundantSelf
        return self.keyType == keyType && (algorithm.curve == nil || self.curve == algorithm.curve)
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
        if let x5t = try? JSONWebCertificateChain(header.certificateChainData).thumbprint(format: .spki, using: SHA256.self), x5t == (try? thumbprint(format: .spki, using: SHA256.self)) {
            return true
        }
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
