//
//  Compression.swift
//
//
//  Created by Amir Abbas Mousavian on 10/13/23.
//

import Foundation

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
    /// Compression with the DEFLATE [RFC1951](https://www.rfc-editor.org/rfc/rfc1951) algorithm
    public static let deflate: Self = "DEF"
}
