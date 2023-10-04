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

extension JSONWebContainer {
    public init(from decoder: Decoder) throws {
        self = try Self(storage: .init())
        let container = try decoder.singleValueContainer()
        self.storage = try container.decode(JSONWebValueStorage.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
    
    public func validate() throws {}
    
    /// Returns value of given key.
    public subscript<T>(_ member: String) -> T? {
        get {
            storage[member]
        }
        set {
            storage[member] = newValue
        }
    }
    
    /// Returns value of given key.
    public subscript<T>(dynamicMember member: String) -> T? {
        get {
            storage[member.jsonWebKey]
        }
        set {
            storage[member.jsonWebKey] = newValue
        }
    }
}
