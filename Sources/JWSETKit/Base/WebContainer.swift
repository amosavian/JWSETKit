//
//  WebContainer.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// JSON container for payloads and sections of JWS and JWE structures.
@dynamicMemberLookup
public protocol JSONWebContainer: Codable, Hashable {
    /// Storage of container values.
    var storage: JSONWebValueStorage { get }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    init(storage: JSONWebValueStorage) throws
    
    /// Validates contents and required fields if applicable.
    func validate() throws
}

/// JSON container for payloads and sections of JWS and JWE structures.
public protocol MutableJSONWebContainer: JSONWebContainer {
    /// Storage of container values.
    var storage: JSONWebValueStorage { get set }
}

@_documentation(visibility: private)
public struct JSONWebContainerCustomParameters {}

extension JSONWebContainer {
    /// Initializes container with filled data.
    ///
    /// - Parameter initializer: Setter of fields.
    public init(_ initializer: (_ container: inout Self) throws -> Void) throws {
        try self.init(storage: .init())
        try initializer(&self)
    }
    
    public init(from decoder: any Decoder) throws {
        self = try Self(storage: .init())
        let container = try decoder.singleValueContainer()
        try self.init(storage: container.decode(JSONWebValueStorage.self))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
    
    public func validate() throws {
        // No validation is required by default.
    }
    
    /// Returns value of given key.
    public subscript<T: JSONWebValueStorage.ValueType>(_ member: String) -> T? {
        storage[member]
    }
    
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebContainerCustomParameters, T>) -> String {
        keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember member: SendableKeyPath<JSONWebContainerCustomParameters, T?>) -> T? {
        storage[stringKey(member)]
    }
    
    @_documentation(visibility: private)
    @_disfavoredOverload
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember member: String) -> T? {
        storage[member.jsonWebKey]
    }
}

extension JSONWebContainer where Self: CustomReflectable {
    public var customMirror: Mirror {
        storage.customMirror
    }
}

extension MutableJSONWebContainer {
    /// Returns value of given key.
    public subscript<T: JSONWebValueStorage.ValueType>(_ member: String) -> T? {
        get {
            storage[member]
        }
        set {
            storage[member] = newValue
        }
    }
    
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebContainerCustomParameters, T>) -> String {
        keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember member: SendableKeyPath<JSONWebContainerCustomParameters, T?>) -> T? {
        get {
            storage[stringKey(member)]
        }
        set {
            storage[stringKey(member)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @_disfavoredOverload
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember member: String) -> T? {
        get {
            storage[member.jsonWebKey]
        }
        set {
            storage[member.jsonWebKey] = newValue
        }
    }
}
