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
public protocol StringRepresentable: RawRepresentable<String>, Hashable, Codable, ExpressibleByStringLiteral, CustomStringConvertible, Sendable where StringLiteralType == String {
    init(rawValue: String)
}

extension StringRepresentable {
    public init(stringLiteral value: StringLiteralType) {
        self.init(rawValue: "\(value)")
    }
    
    public var description: String {
        rawValue
    }
}

public typealias SendableAnyKeyPath = any AnyKeyPath & Sendable
public typealias SendablePartialKeyPath<T> = any PartialKeyPath<T> & Sendable
public typealias SendableKeyPath<T, V> = any KeyPath<T, V> & Sendable
public typealias SendableWritableKeyPath<T, V> = any Sendable & WritableKeyPath<T, V>
public typealias SendableReferenceWritableKeyPath<T, V> = any ReferenceWritableKeyPath<T, V> & Sendable
