//
//  ProtectedContainer.swift
//
//
//  Created by Amir Abbas Mousavian on 9/19/23.
//

import Foundation

extension JSONEncoder {
    static var encoder: JSONEncoder {
        let result = JSONEncoder()
        result.outputFormatting = [.withoutEscapingSlashes]
        return result
    }
}

/// Data value that must be protected by JWS.
public protocol ProtectedWebContainer: Hashable, Encodable, Sendable {
    /// Signed data.
    var encoded: Data { get set }
    
    /// Initializes the container using given data.
    ///
    /// - Parameter protected: Data that has been signed.
    init(encoded: Data) throws
    
    /// Validates contents and required fields if applicable.
    func validate() throws
}

extension ProtectedWebContainer {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.encoded == rhs.encoded
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(encoded)
    }
    
    public func validate() throws {
        // No required field by default thus no validation is needed.
    }
    
    /// Decode protected data from Base64URL string contained in decoder..
    ///
    /// - Parameter decoder: Decoder contains Base64URL string.
    /// - Returns: Decoded data.
    public static func decodeProtected(from decoder: any Decoder) throws -> Data {
        let container = try decoder.singleValueContainer()
        
        let encoded = try container.decode(String.self)
        guard let protected = Data(urlBase64Encoded: encoded) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Protected is not a valid bas64url."))
        }
        return protected
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(encoded.urlBase64EncodedString())
    }
}

public protocol TypedProtectedWebContainer<Container>: ProtectedWebContainer {
    associatedtype Container
    /// Parsed value of data.
    var value: Container { get set }
    
    /// Initialized protected container from object.
    ///
    /// - Parameter value: Object that will be presented in `protected`.
    init(value: Container) throws
}

public struct ProtectedDataWebContainer: ProtectedWebContainer, Codable {
    public var encoded: Data
    
    public init(encoded: Data) throws {
        self.encoded = encoded
    }
    
    public init(from decoder: any Decoder) throws {
        self.encoded = try Self.decodeProtected(from: decoder)
    }
}

/// A JSON Web Signature/Encryption (JWS/JWE) header or payload with can be signed.
///
/// This cotainer preserves original data to keep consistancy of signature as re-encoding payload
/// may change sorting.
public struct ProtectedJSONWebContainer<Container: JSONWebContainer>: TypedProtectedWebContainer, Codable {
    private var _protected: Data
    private var _value: Container
    
    /// Serialized protected data of JOSE.
    public var encoded: Data {
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
                _protected = try JSONEncoder.encoder.encode(newValue)
            } catch {
                if let emptyValue = try? Container(storage: .init()) {
                    _value = emptyValue
                } else {
                    assertionFailure("Invalid value provided")
                }
            }
        }
    }
    
    /// Initialized protected container from a JOSE data.
    ///
    /// - Note: If empty encoded data is given, value will be initialzed as empty object.
    ///
    /// - Parameter protected: Serialzed json object but **not** in `base64url` .
    public init(encoded: Data) throws {
        self._protected = encoded
        self._value = try JSONDecoder().decode(Container.self, from: !encoded.isEmpty ? encoded : .init("{}".utf8))
    }
    
    /// Initialized protected container from object.
    ///
    /// - Parameter value: Object that will be presented in `base64url` json.
    public init(value: Container) throws {
        self._value = value
        self._protected = try JSONEncoder.encoder.encode(value)
    }
    
    public init(from decoder: any Decoder) throws {
        let protected = try Self.decodeProtected(from: decoder)
        self._protected = protected
        self._value = try JSONDecoder().decode(Container.self, from: protected)
    }
    
    public func validate() throws {
        try value.validate()
    }
}
