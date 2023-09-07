//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

/// JSON container for payloads and sections of JWS and JWE structures.
@dynamicMemberLookup
public protocol JsonWebContainer: Codable, Hashable {
    /// Storage of container values.
    var storage: JsonWebValueStorage { get set }
    
    /// Creates a container with empty storage.
    init()
}

extension JsonWebContainer {
    public init(from decoder: Decoder) throws {
        self = .init()
        let container = try decoder.singleValueContainer()
        self.storage = try container.decode(JsonWebValueStorage.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
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

