//
//  JWSCodable.swift
//
//
//  Created by Amir Abbas Mousavian on 10/1/23.
//

import Foundation

/// JWSs use one of two serializations: the JWS Compact Serialization or the JWS JSON Serialization.
///
/// Applications using this specification need to specify what serialization and serialization features are
/// used for that application.
///
/// To change the representation  of JWS during encoding to flattened JSON:
/// ```swift
/// do {
///     var encoder = JSONEncoder()
///     encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.jsonFlattened
///     try encoder.encode(jws)
/// } catch {
///     print(error)
/// }
/// ```
public enum JSONWebSignatureRepresentation: Sendable {
    /// Use compact or detached serialization if only one signature and
    /// no unprotected header is present, regarding `b64` header value.
    ///
    /// - Important: This is default encoding format when using `JSONWebSignature.encode(to:)`.
    ///              To use other encodings, change `.jwsEncodedRepresentation`
    ///              parameter in `userInfo`.
    case automatic
    
    /// The JWS Compact Serialization represents digitally signed or MACed content as a compact, URL-safe string.
    ///
    /// This string is:
    /// ```
    /// BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    /// BASE64URL(JWS Payload) || '.' ||
    /// BASE64URL(JWS Signature)
    /// ```
    ///
    /// Only one signature/MAC is supported by the JWS Compact Serialization
    /// and it provides no syntax to represent a JWS Unprotected Header value.
    case compact
    
    /// The JWS Compact Serialization without payload re. [RFC7797](https://www.rfc-editor.org/rfc/rfc7797).
    ///
    /// The primary set of use cases where this enhancement may be helpful are those in
    /// which the payload may be very large and where means are already in
    /// place to enable the payload to be communicated between the parties
    /// without modifications.
    ///
    /// This string is:
    /// ```
    /// BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    /// '.' || BASE64URL(JWS Signature)
    /// ```
    case compactDetached
    
    /// The JWS JSON Serialization represents digitally signed or MACed
    /// content as a JSON object.  This representation is neither optimized
    /// for compactness nor URL-safe.
    ///
    /// The value can be a flattened representation if only one signature is present,
    /// or a fully general syntax if more than one signature is present.
    case json
    
    /// The flattened JWS JSON Serialization syntax is based upon the general
    /// syntax but flattens it, optimizing it for the single digital signature/MAC case
    case jsonFlattened
    
    /// A JSON Serialization fully general syntax, with which content can be secured
    /// with more than one digital signature and/or MAC operation
    case jsonGeneral
}

extension CodingUserInfoKey {
    /// Changes serialzation of JWS.
    ///
    /// Default value is `.compact` if not set.
    public static var jwsEncodedRepresentation: Self {
        .init(rawValue: #function).unsafelyUnwrapped
    }
}

extension JSONWebSignature: Codable {
    public init(from decoder: Decoder) throws {
        if let stringContainer = try? decoder.singleValueContainer(), let value = try? stringContainer.decode(String.self) {
            let sections = value
                .components(separatedBy: ".")
                .map { Data(urlBase64Encoded: $0) ?? .init() }
            guard sections.count == 3 else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "JWS String is not a three part data."))
            }
            self.payload = try Payload(encoded: sections[1])
            self.signatures = try [
                .init(
                    protected: sections[0],
                    unprotected: nil,
                    signature: sections[2]
                ),
            ]
            return
        }
        
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let signatures = try container.decodeIfPresent([JSONWebSignatureHeader].self, forKey: .signatures) {
            let payload = try container.decode(String.self, forKey: .payload)
            guard let payloadData = Data(urlBase64Encoded: payload) else {
                throw DecodingError.dataCorrupted(.init(codingPath: [CodingKeys.payload], debugDescription: "Payload is not Base64URL"))
            }
            self.payload = try .init(encoded: payloadData)
            self.signatures = signatures
        } else {
            let payload = try container.decode(String.self, forKey: .payload)
            guard let payloadData = Data(urlBase64Encoded: payload) else {
                throw DecodingError.dataCorrupted(.init(codingPath: [CodingKeys.payload], debugDescription: "Payload is not Base64URL"))
            }
            self.payload = try .init(encoded: payloadData)
            let header = try JSONWebSignatureHeader(from: decoder)
            self.signatures = [header]
        }
    }
    
    fileprivate func encodeAsString(_ encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        guard let signature = signatures.first else {
            try container.encode("..")
            return
        }
        let plainPayload = signatures[0].protected.value.base64 == false
        let value = [
            signature.protected.encoded.urlBase64EncodedData(),
            plainPayload ? payload.encoded : payload.encoded.urlBase64EncodedData(),
            signature.signature.urlBase64EncodedData(),
        ]
        .map { String(decoding: $0, as: UTF8.self) }
        .joined(separator: ".")
        try container.encode(value)
    }
    
    fileprivate func encodeAsDetachedString(_ encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        guard let signature = signatures.first else {
            try container.encode("..")
            return
        }
        let value = [
            signature.protected.encoded.urlBase64EncodedData(),
            signature.signature.urlBase64EncodedData(),
        ]
        .map { String(decoding: $0, as: UTF8.self) }
        .joined(separator: "..")
        try container.encode(value)
    }
    
    fileprivate func encodeAsCompleteJSON(_ encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.encoded.urlBase64EncodedData(), forKey: .payload)
        try container.encode(signatures, forKey: .signatures)
    }
    
    fileprivate func encodeAsFlattenedJSON(_ encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.encoded.urlBase64EncodedData(), forKey: .payload)
        var headerContainer = encoder.container(keyedBy: JSONWebSignatureHeader.CodingKeys.self)
        try headerContainer.encodeIfPresent(signatures.first?.protected, forKey: .protected)
        try headerContainer.encodeIfPresent(signatures.first?.unprotected, forKey: .header)
        try headerContainer.encodeIfPresent(signatures.first?.signature, forKey: .signature)
    }
    
    fileprivate func bestRepresentation() -> JSONWebSignatureRepresentation {
        switch signatures.count {
        case 0:
            return .compact
        case 1 where signatures[0].unprotected == nil:
            if signatures[0].protected.value.base64 == false {
                return .compactDetached
            }
            return .compact
        default:
            return .json
        }
    }
    
    fileprivate func encodeFunction(for representation: JSONWebSignatureRepresentation) -> (_ encoder: Encoder) throws -> Void {
        var representation = representation
        if representation == .automatic {
            representation = bestRepresentation()
        }
        switch representation {
        case .automatic:
            fallthrough
        case .compact:
            return encodeAsString
        case .compactDetached:
            return encodeAsDetachedString
        case .json:
            switch signatures.count {
            case 0, 1:
                return encodeAsFlattenedJSON
            default:
                return encodeAsCompleteJSON
            }
        case .jsonFlattened:
            return encodeAsFlattenedJSON
        case .jsonGeneral:
            return encodeAsCompleteJSON
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        try validate()
        let representation = encoder.userInfo[.jwsEncodedRepresentation] as? JSONWebSignatureRepresentation ?? .automatic
        try encodeFunction(for: representation)(encoder)
    }
}

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
public struct JSONWebSignatureCodableConfiguration: Sendable {
    public let representation: JSONWebSignatureRepresentation
    
    public init(representation: JSONWebSignatureRepresentation) {
        self.representation = representation
    }
}

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
extension JSONWebSignature: EncodableWithConfiguration {
    public typealias EncodingConfiguration = JSONWebSignatureCodableConfiguration
    
    public func encode(to encoder: Encoder, configuration: JSONWebSignatureCodableConfiguration) throws {
        try validate()
        try encodeFunction(for: configuration.representation)(encoder)
    }
}
