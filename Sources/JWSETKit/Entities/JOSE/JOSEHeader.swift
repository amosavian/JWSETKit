//
//  JOSEHeader.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// For a JWS, the members of the JSON object(s) representing the JOSE Header
/// describe the digital signature or MAC applied to the JWS Protected Header
/// and the JWS Payload and optionally additional properties of the JWS.
public struct JOSEHeader: JSONWebContainer {
    public var storage: JSONWebValueStorage
    
    /// Initializes a new JOSE header with given key/values.
    ///
    /// - Parameter storage: Header key/values.
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// Initializes an empty JOSE header.
    public init() {
        self.storage = .init()
    }
    
    /// Initializes a JOSE header with given algorithm, type and key ID if exists.
    ///
    /// - Parameters:
    ///   - algorithm: Contains JWA to deremine signing/encryption algorithm.
    ///   - type: Payload type, usually `"JWT"` for JSON Web Token.
    ///   - keyId: Key ID that generated signature.
    public init(algorithm: any JSONWebAlgorithm, type: JSONWebContentType, keyId: String? = nil) {
        self.storage = .init()
        self.algorithm = algorithm
        self.type = type
        self.keyId = keyId
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JOSEHeader {
        .init(storage: storage)
    }
    
    public func validate() throws {
        guard storage.contains(key: "alg") else {
            throw JSONWebValidationError.missingRequiredField(key: "alg")
        }
    }
}

/// Content type of payload in JOSE header..
public struct JSONWebContentType: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral, Sendable {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension JSONWebContentType {
    /// Payload contains a JSON with JSON Web Token (JWT) claims.
    public static let jwt: Self = "JWT"
}
