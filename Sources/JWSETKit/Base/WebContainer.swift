//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

@dynamicMemberLookup
public protocol JsonWebContainer: Codable, Hashable {
    var storage: JsonWebValueStorage { get set }
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
    
    public subscript<T>(_ member: String) -> T? {
        get {
            storage[member]
        }
        set {
            storage[member] = newValue
        }
    }
    
    public subscript<T>(dynamicMember member: String) -> T? {
        get {
            storage[member.jsonWebKey]
        }
        set {
            storage[member.jsonWebKey] = newValue
        }
    }
}

