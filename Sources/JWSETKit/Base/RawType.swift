//
//  RawType.swift
//
//
//  Created by Amir Abbas Mousavian on 11/24/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Represents a type that can be initialized from a string raw value.
public protocol StringRepresentable: RawRepresentable<String>, Hashable, Codable, ExpressibleByStringLiteral, Sendable where StringLiteralType == String {
    init(rawValue: String)
}

extension StringRepresentable {
    public init(stringLiteral value: StringLiteralType) {
        self.init(rawValue: "\(value)")
    }
}
