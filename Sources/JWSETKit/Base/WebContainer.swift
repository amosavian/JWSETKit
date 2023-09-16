//
//  WebContainer.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

/// JSON container for payloads and sections of JWS and JWE structures.
@dynamicMemberLookup
public protocol JSONWebContainer: Codable, Hashable {
    /// Storage of container values.
    var storage: JSONWebValueStorage { get set }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    ///
    /// - Returns: A new instance of current class.
    static func create(storage: JSONWebValueStorage) throws -> Self
}

extension JSONWebContainer {
    public init(from decoder: Decoder) throws {
        self = try Self.create(storage: .init())
        let container = try decoder.singleValueContainer()
        self.storage = try container.decode(JSONWebValueStorage.self)
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

/// A JSON Web Signature/Encryption (JWS/JWE) header or payload with can be signed.
///
/// This cotainer preserves original data to keep consistancy of signature as re-encoding payload
/// may change sorting.
public struct ProtectedJSONWebContainer<Container: JSONWebContainer>: Codable, Hashable {
    /// Serialized protected date of JOSE.
    public var protected: Data {
        didSet {
            if protected.isEmpty {
                value.storage = .init()
                return
            }
            do {
                value = try JSONDecoder().decode(Container.self, from: protected)
            } catch {
                protected = .init()
            }
        }
    }
    
    /// Parsed value of data.
    public var value: Container {
        didSet {
            if value.storage == .init() {
                protected = .init()
                return
            }
            do {
                protected = try JSONEncoder().encode(value)
            } catch {
                protected = .init()
            }
        }
    }
    
    /// Initialized protected container from a JOSE data.
    ///
    /// - Parameter protected: Serialzed json object but **not** in `base64url` .
    public init(protected: Data) throws {
        self.protected = protected
        self.value = try JSONDecoder().decode(Container.self, from: protected)
    }
    
    /// Initialized protected container from object.
    ///
    /// - Parameter value: Object that will be presented in `base64url` json.
    public init(value: Container) throws {
        self.value = value
        self.protected = try JSONEncoder().encode(value).urlBase64EncodedData()
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        let encoded = try container.decode(String.self)
        guard let protected = Data(urlBase64Encoded: encoded) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Protected is not a valid bas64url."))
        }
        self.protected = protected
        self.value = try JSONDecoder().decode(Container.self, from: protected)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let encoded = protected.urlBase64EncodedData()
        try container.encode(encoded)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.protected == rhs.protected
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(protected)
    }
}
