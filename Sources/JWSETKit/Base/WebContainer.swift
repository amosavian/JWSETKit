//
//  WebContainer.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

/// JSON container for payloads and sections of JWS and JWE structures.
@dynamicMemberLookup
public protocol JSONWebContainer: Codable, Hashable, Sendable {
    /// Storage of container values.
    var storage: JSONWebValueStorage { get set }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    init(storage: JSONWebValueStorage) throws
    
    /// Validates contents and required fields if applicable.
    func validate() throws
}

@_documentation(visibility: private)
public struct JSONWebContainerCustomParameters {}

extension JSONWebContainer {
    /// Initializes container with filled data.
    ///
    /// - Parameter initializer: Setter of fields.
    public init(_ initializer: (_ container: inout Self) -> Void) throws {
        try self.init(storage: .init())
        initializer(&self)
    }
    
    public init(from decoder: any Decoder) throws {
        self = try Self(storage: .init())
        let container = try decoder.singleValueContainer()
        self.storage = try container.decode(JSONWebValueStorage.self)
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
    
    public func validate() throws {
        // No validation is required by default.
    }
    
    /// Returns value of given key.
    public subscript<T>(_ member: String) -> T? {
        get {
            storage[member]
        }
        set {
            storage[member] = newValue
        }
    }
    
    private func stringKey<T>(_ keyPath: KeyPath<JSONWebContainerCustomParameters, T>) -> String {
        keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    public subscript<T>(dynamicMember member: KeyPath<JSONWebContainerCustomParameters, T?>) -> T? {
        get {
            storage[stringKey(member)]
        }
        set {
            storage[stringKey(member)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @_disfavoredOverload
    public subscript<T>(dynamicMember member: String) -> T? {
        get {
            storage[member.jsonWebKey]
        }
        set {
            storage[member.jsonWebKey] = newValue
        }
    }
}
