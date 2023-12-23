//
//  RawType.swift
//
//
//  Created by Amir Abbas Mousavian on 11/24/23.
//

import Foundation

public protocol StringRepresentable: RawRepresentable<String>, Hashable, Codable, ExpressibleByStringLiteral, Sendable where StringLiteralType == String {
    init(rawValue: String)
}

extension StringRepresentable {
    public init(stringLiteral value: StringLiteralType) {
        self.init(rawValue: "\(value)")
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(rawValue: container.decode(String.self))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
