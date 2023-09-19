//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/19/23.
//

import Foundation

/// Data value that must be protected by JWS.
public protocol ProtectedWebContainer: Hashable {
    /// Signed data.
    var protected: Data { get set }
    
    init(protected: Data) throws
}

public struct ProtectedDataWebContainer: ProtectedWebContainer, Codable {
    public var protected: Data
    
    public init(protected: Data) throws {
        self.protected = protected
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        let encoded = try container.decode(String.self)
        guard let protected = Data(urlBase64Encoded: encoded) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Protected is not a valid bas64url."))
        }
        self.protected = protected
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let encoded = protected.urlBase64EncodedData()
        try container.encode(encoded)
    }
}

/// A JSON Web Signature/Encryption (JWS/JWE) header or payload with can be signed.
///
/// This cotainer preserves original data to keep consistancy of signature as re-encoding payload
/// may change sorting.
public struct ProtectedJSONWebContainer<Container: JSONWebContainer>: ProtectedWebContainer, Codable {
    private var _protected: Data
    private var _value: Container
    
    /// Serialized protected data of JOSE.
    public var protected: Data {
        get {
            _protected
        }
        set {
            _protected = newValue
            if newValue.isEmpty {
                _value.storage = .init()
                return
            }
            do {
                _value = try JSONDecoder().decode(Container.self, from: newValue)
            } catch {
                _protected = .init()
            }
        }
    }
    
    /// Parsed value of data.
    public var value: Container {
        get {
            _value
        }
        set {
            _value = newValue
            if _value.storage == .init() {
                _protected = .init()
                return
            }
            do {
                _protected = try JSONEncoder().encode(newValue)
            } catch {
                _value = try! .create(storage: .init())
            }
        }
    }
    
    /// Initialized protected container from a JOSE data.
    ///
    /// - Parameter protected: Serialzed json object but **not** in `base64url` .
    public init(protected: Data) throws {
        self._protected = protected
        self._value = try JSONDecoder().decode(Container.self, from: protected)
    }
    
    /// Initialized protected container from object.
    ///
    /// - Parameter value: Object that will be presented in `base64url` json.
    public init(value: Container) throws {
        self._value = value
        self._protected = try JSONEncoder().encode(value).urlBase64EncodedData()
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        let encoded = try container.decode(String.self)
        guard let protected = Data(urlBase64Encoded: encoded) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Protected is not a valid bas64url."))
        }
        self._protected = protected
        self._value = try JSONDecoder().decode(Container.self, from: protected)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let encoded = _protected.urlBase64EncodedData()
        try container.encode(encoded)
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs._protected == rhs._protected
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(_protected)
    }
}
