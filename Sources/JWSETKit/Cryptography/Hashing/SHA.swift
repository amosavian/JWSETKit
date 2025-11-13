//
//  SHA.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 9/10/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Hash name according to [RFC6920](https://www.rfc-editor.org/rfc/rfc6920 ).
public protocol NamedHashFunction: HashFunction {
    /// [IANA registration name](https://www.iana.org/assignments/named-information/named-information.xhtml) of the digest algorithm.
    static var identifier: JSONWebHashAlgorithm { get }
}

extension SHA256: NamedHashFunction {
    public static let identifier: JSONWebHashAlgorithm = "sha-256"
}

extension SHA384: NamedHashFunction {
    public static let identifier: JSONWebHashAlgorithm = "sha-384"
}

extension SHA512: NamedHashFunction {
    public static let identifier: JSONWebHashAlgorithm = "sha-512"
}

#if compiler(>=6.2) || !canImport(CryptoKit)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension SHA3_256: NamedHashFunction {
    public static let identifier: JSONWebHashAlgorithm = "sha3-256"
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension SHA3_384: NamedHashFunction {
    public static let identifier: JSONWebHashAlgorithm = "sha3-384"
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension SHA3_512: NamedHashFunction {
    public static let identifier: JSONWebHashAlgorithm = "sha3-512"
}
#endif

/// JSON Web Compression Algorithms.
@frozen
public struct JSONWebHashAlgorithm: StringRepresentable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
}

extension JSONWebHashAlgorithm {
    private static let hashFunctions: AtomicValue<[Self: any HashFunction.Type]> = {
        if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) {
#if compiler(>=6.2) || !canImport(CryptoKit)
            [
                SHA256.identifier: SHA256.self,
                SHA384.identifier: SHA384.self,
                SHA512.identifier: SHA512.self,
                SHA3_256.identifier: SHA3_256.self,
                SHA3_384.identifier: SHA3_384.self,
                SHA3_512.identifier: SHA3_512.self,
            ]
#else
            [
                SHA256.identifier: SHA256.self,
                SHA384.identifier: SHA384.self,
                SHA512.identifier: SHA512.self,
            ]
#endif
        } else {
            [
                SHA256.identifier: SHA256.self,
                SHA384.identifier: SHA384.self,
                SHA512.identifier: SHA512.self,
            ]
        }
    }()
    
    private static let fastPathHashFunctions: [Self: any HashFunction.Type] = [
        SHA256.identifier: SHA256.self,
        SHA384.identifier: SHA384.self,
        SHA512.identifier: SHA512.self,
    ]
    
    /// Returns provided hash function  for this algorithm.
    public var hashFunction: (any HashFunction.Type)? {
        Self.fastPathHashFunctions[self] ?? Self.hashFunctions[self]
    }
    
    /// Currently registered algorithms.
    public static var registeredAlgorithms: [Self] {
        .init(hashFunctions.keys)
    }
    
    /// Registers new hash function for given algorithm.
    ///
    /// - Parameters:
    ///   - algorithm: hash function algorithm.
    ///   - hashFunction: hash function type.
    public static func register<C>(_ algorithm: Self, hashFunction: C.Type) where C: HashFunction {
        hashFunctions[algorithm] = hashFunction
    }
}
