//
//  Compression.swift
//
//
//  Created by Amir Abbas Mousavian on 10/13/23.
//

import Foundation

/// A protocol to provide compress/decompress data to support JWE content compression.
public protocol JSONWebCompressor {
    /// Compresses data using defined algorithm.
    ///
    /// - Parameter data: Data to be compressed.
    /// - Returns: Compressed data.
    static func compress<D>(_ data: D) throws -> Data where D: DataProtocol
    
    /// Decompresses data using defined algorithm.
    ///
    /// - Parameter data: Data to be decompressed.
    /// - Returns: Decompressed data.
    static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol
}

/// JSON Web Compression Algorithms.
public struct JSONWebCompressionAlgorithm: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
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

extension JSONWebCompressionAlgorithm {
    private static var compressors: [Self: any JSONWebCompressor.Type] = [:]
    
    /// Returns provided compressor for this algorithm.
    public var compressor: (any JSONWebCompressor.Type)? {
        Self.compressors[self]
    }
    
    /// Registers new compressor for given algorithm.
    ///
    /// - Parameters:
    ///   - algorithm: Compression algorithm.
    ///   - compressor: Compressor instance.
    public static func register<C>(_ algorithm: Self, compressor: C.Type) where C: JSONWebCompressor {
        compressors[algorithm] = compressor
    }
}

extension JSONWebCompressionAlgorithm {
    /// Compression with the DEFLATE [RFC1951](https://www.rfc-editor.org/rfc/rfc1951) algorithm.
    public static let deflate: Self = "DEF"
}
