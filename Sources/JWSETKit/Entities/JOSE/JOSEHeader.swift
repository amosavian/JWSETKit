//
//  JOSEHeader.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// For a JWS, the members of the JSON object(s) representing the JOSE Header
/// describe the digital signature or MAC applied to the JWS Protected Header
/// and the JWS Payload and optionally additional properties of the JWS.
@frozen
public struct JOSEHeader: MutableJSONWebContainer, Sendable {
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
    public init(algorithm: some JSONWebAlgorithm, type: JSONWebContentType, keyId: String? = nil) {
        self.storage = .init()
        self.algorithm = algorithm
        self.type = type
        self.keyId = keyId
    }
    
    public func merging(_ other: JOSEHeader, uniquingKeysWith combine: (any Sendable, any Sendable) throws -> any Sendable) rethrows -> JOSEHeader {
        guard !other.storage.isEmpty else { return self }
        let storage = try storage.merging(other.storage, uniquingKeysWith: combine)
        return .init(storage: storage)
    }
    
    private var normalizedStorage: JSONWebValueStorage {
        var result = storage
        result["typ"] = result["typ"].map(JSONWebContentType.init(rawValue:))
        result["cty"] = result["cty"].map(JSONWebContentType.init(rawValue:))
        return result
    }
    
    public static func == (lhs: JOSEHeader, rhs: JOSEHeader) -> Bool {
        lhs.normalizedStorage == rhs.normalizedStorage
    }
}

/// Content type of payload in JOSE header.
///
/// To keep messages compact in common situations, it is RECOMMENDED that
/// producers omit an "application/" prefix of a media type value in a
/// "typ" Header Parameter when no other '/' appears in the media type
/// value.  A recipient using the media type value MUST treat it as if
/// "application/" were prepended to any "typ" value not containing a
/// '/'.  For instance, a "typ" value of "example" SHOULD be used to
/// represent the "application/example" media type, whereas the media
/// type "application/example;part="1/2"" cannot be shortened to
/// "example;part="1/2"".
public struct JSONWebContentType: StringRepresentable {
    public let rawValue: String
    
    /// IANA Media type per RFC-2045.
    ///
    /// As application prefix is optional in JOSE content type, this property returns a valid lowercased MIME type.
    public var mimeType: String {
        var result = rawValue.lowercased()
        if !result.contains("/") {
            result = "application/\(result)"
        }
        return result
    }
    
    public init(rawValue: String) {
        self.rawValue = rawValue
            .trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: "application/", with: "", options: [.anchored])
    }
    
    public static func == (lhs: JSONWebContentType, rhs: JSONWebContentType) -> Bool {
        lhs.mimeType == rhs.mimeType
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(mimeType)
    }
}

extension JSONWebContentType {
    /// Payload contains a JSON with JSON Web Token (JWT) claims.
    ///
    /// JWT values are encoded as a series of`base64url`-encoded values (some of which may be the empty
    /// string) separated by period ('.') characters.
    public static let jwt: Self = "JWT"
    
    /// Payload contains encrypted data with JSON Web Encryption (JWE) serialization.
    public static let jwe: Self = "JWE"
    
    /// JOSE values are encoded as a series of `base64url`-encoded values (some of which may be the empty
    ///  string), each separated from the next by a single period ('.') character.
    ///
    /// This value indicates that the content is a JWS or JWE using the JWS Compact Serialization
    /// or the JWE Compact Serialization.
    public static let jose: Self = "JOSE"
    
    /// JOSE values are represented as a JSON Object; UTF-8 encoding SHOULD be employed for the JSON object.
    ///
    /// This value indicates that the content is a JWS or JWE using the JWS JSON Serialization
    /// or the JWE JSON Serialization.
    public static let joseJSON: Self = "JOSE+JSON"
    
    /// Payload contains a JSON with JSON Web Key (JWK) parameters.
    public static let jwk: Self = "jwk+json"
    
    /// Payload contains a JSON with JSON Web Key Set (JWKS) items.
    public static let jwks: Self = "jwk-set+json"
    
    /// Payload contains a Selective Disclosure JWT (SD-JWT) as defined in RFC 9901.
    ///
    /// SD-JWT enables selective disclosure of individual claims within a JWT.
    /// This type is used with compact serialization format.
    public static let sdJWT: Self = "sd-jwt"
    
    /// Payload contains a Selective Disclosure JWT (SD-JWT) in JSON serialization as defined in RFC 9901.
    ///
    /// SD-JWT enables selective disclosure of individual claims within a JWT.
    /// This type is used with JSON serialization format.
    public static let sdJWTJSON: Self = "sd-jwt+json"
    
    /// Key Binding JWT type as defined in RFC 9901.
    ///
    /// KB-JWT is used to bind an SD-JWT presentation to a holder's key.
    public static let keyBindingJWT: Self = "kb+jwt"
}

#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers

extension JSONWebContentType {
    /// Initializes content type from Uniform Type Identifier.
    ///
    /// - Parameter utType: A structure that represents a type of data to load, send, or receive.
    public init?(_ utType: UTType) {
        guard let mimeType = utType.preferredMIMEType else {
            return nil
        }
        
        self.init(rawValue: mimeType)
    }
 
    /// Returns a Uniform Type Identifier corresponding to MIME type.
    public var utType: UTType? {
        let mimeType = mimeType
        let conformingType: UTType = mimeType.hasSuffix("+json") ? .json : .data
        return .init(mimeType: mimeType, conformingTo: conformingType)
    }
}
#endif
