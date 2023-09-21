//
//  JWS.swift
//
//
//  Created by Amir Abbas Mousavian on 9/8/23.
//

import Foundation

/// Represents a signature or MAC over the JWS Payload and the JWS Protected Header.
public struct JSONWebSignatureHeader: Hashable, Codable {
    enum CodingKeys: CodingKey {
        case protected
        case header
        case signature
    }
    
    /// For a JWS, the members of the JSON object(s) representing the JOSE Header
    /// describe the digital signature or MAC applied to the JWS Protected Header
    /// and the JWS Payload and optionally additional properties of the JWS.
    public var header: ProtectedJSONWebContainer<JOSEHeader>
    
    /// The value JWS Unprotected Header.
    public var unprotectedHeader: JOSEHeader?
    
    /// Signature of protected header concatenated with payload.
    public var signature: Data
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - header: JWS Protected Header.
    ///   - unprotectedHeader: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(header: JOSEHeader, unprotectedHeader: JOSEHeader? = nil, signature: Data) throws {
        self.header = try .init(value: header)
        self.unprotectedHeader = unprotectedHeader
        self.signature = signature
    }
    
    /// /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - header: JWS Protected Header in byte array representation.
    ///   - unprotectedHeader: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(header: Data, unprotectedHeader: JOSEHeader? = nil, signature: Data) throws {
        self.header = try ProtectedJSONWebContainer<JOSEHeader>(protected: header)
        self.unprotectedHeader = unprotectedHeader
        self.signature = signature
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.header = try container.decode(ProtectedJSONWebContainer<JOSEHeader>.self, forKey: .protected)
        self.unprotectedHeader = try container.decodeIfPresent(JOSEHeader.self, forKey: .header)
        
        let signatureString = try container.decodeIfPresent(String.self, forKey: .signature) ?? .init()
        self.signature = Data(urlBase64Encoded: signatureString) ?? .init()
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .protected)
        try container.encodeIfPresent(unprotectedHeader, forKey: .header)
        try container.encode(signature.urlBase64EncodedData(), forKey: .signature)
    }
}

/// JWS represents digitally signed or MACed content using JSON data structures and `base64url` encoding.
public struct JSONWebSignature<Payload: ProtectedWebContainer>: Codable, Hashable {
    
    /// The "signatures" member value MUST be an array of JSON objects.
    ///
    /// Each object represents a signature or MAC over the JWS Payload and the JWS Protected Header.
    public var signatures: [JSONWebSignatureHeader]
    
    /// The "`payload`" member MUST be present and contain the value of JWS Payload.
    public var payload: Payload
    
    enum CodingKeys: String, CodingKey {
        case payload
        case signatures
    }
    
    /// Decodes a data that may contain either Base64URL encoded string of JWS or a Complete/Flattened JWS representation.
    ///
    /// - Parameter data: Either Base64URL encoded string of JWS or a JSON with Complete/Flattened JWS representation.
    public init<D: DataProtocol>(from data: D) throws {
        if data.starts(with: Data("ey".utf8)) {
            let container = Data("\"".utf8) + Data(data) + Data("\"".utf8)
            self = try JSONDecoder().decode(JSONWebSignature<Payload>.self, from: container)
        } else if data.starts(with: Data("{".utf8)) {
            self = try JSONDecoder().decode(JSONWebSignature<Payload>.self, from: Data(data))
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid JWS."))
        }
    }
    
    /// Initialzes JWS using Base64URL encoded String.
    ///
    /// - Parameter string: Base64URL encoded String.
    public init<S: StringProtocol>(from string: S) throws {
        try self.init(from: Data(string.utf8))
    }
    
    public init(from decoder: Decoder) throws {
        if let stringContainer = try? decoder.singleValueContainer(), let value = try? stringContainer.decode(String.self) {
            let sections = value
                .components(separatedBy: ".")
                .map { Data(urlBase64Encoded: $0) ?? .init() }
            guard sections.count == 3 else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "JWS String is not a three part data."))
            }
            self.payload = try Payload.init(protected: sections[1])
            self.signatures = try [
                .init(
                    header: sections[0],
                    unprotectedHeader: nil,
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
            self.payload = try .init(protected: payloadData)
            self.signatures = signatures
        } else {
            let payload = try container.decode(String.self, forKey: .payload)
            guard let payloadData = Data(urlBase64Encoded: payload) else {
                throw DecodingError.dataCorrupted(.init(codingPath: [CodingKeys.payload], debugDescription: "Payload is not Base64URL"))
            }
            self.payload = try .init(protected: payloadData)
            let header = try JSONWebSignatureHeader(from: decoder)
            self.signatures = [header]
        }
    }
    
    /// Initializes a new JWS with given payload and signature(s).
    ///
    /// - Parameters:
    ///   - signatures: An array of signatures and JOSE headers.
    ///   - payload: Protected payload data/object.
    public init(signatures: [JSONWebSignatureHeader], payload: Payload) {
        self.signatures = signatures
        self.payload = payload
    }
    
    fileprivate func encodeAsString(_ encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let value = [
            signatures.first?.header.protected.urlBase64EncodedData() ?? .init(),
            payload.protected.urlBase64EncodedData(),
            signatures.first?.signature.urlBase64EncodedData() ?? .init(),
        ]
        .map { String(decoding: $0, as: UTF8.self) }
        .joined(separator: ".")
        try container.encode(value)
    }
    
    fileprivate func encodeAsCompleteJSON(_ encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.protected.urlBase64EncodedData(), forKey: .payload)
        try container.encode(signatures, forKey: .signatures)
    }
    
    fileprivate func encodeAsFlattenedJSON(_ encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.protected.urlBase64EncodedData(), forKey: .payload)
        var headerContainer = encoder.container(keyedBy: JSONWebSignatureHeader.CodingKeys.self)
        try headerContainer.encodeIfPresent(signatures.first?.header, forKey: .protected)
        try headerContainer.encodeIfPresent(signatures.first?.unprotectedHeader, forKey: .header)
        try headerContainer.encodeIfPresent(signatures.first?.signature, forKey: .signature)
    }
    
    public func encode(to encoder: Encoder) throws {
        let representation = encoder.userInfo[.jwsEncodedRepresentation] as? JSONWebSignatureRepresentation ?? .compact
        switch representation {
        case .compact:
            try encodeAsString(encoder)
        case .json:
            switch signatures.count {
            case 0, 1:
                try encodeAsFlattenedJSON(encoder)
            default:
                try encodeAsCompleteJSON(encoder)
            }
        case .jsonGeneral:
            try encodeAsCompleteJSON(encoder)
        case .jsonFlattened:
            try encodeAsFlattenedJSON(encoder)
        }
    }
    
    /// Renews all signatures for protected header(s) using given keys.
    ///
    /// This methos finds appropriate key for the header using `kid` value in protected or unprotected header.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebSigningKey` that would be used for signing.
    public mutating func updateSignature(using keys: [any JSONWebSigningKey]) throws {
        guard let firstKey = keys.first else {
            throw JSONWebKeyError.keyNotFound
        }
        signatures = try signatures.map { header in
            let header = header
            let key = keys.first {
                header.unprotectedHeader?.keyId == $0.keyId || header.header.value.keyId == $0.keyId
            } ?? firstKey
            
            let message = header.header.protected.urlBase64EncodedData() + Data(".".utf8) + payload.protected.urlBase64EncodedData()
            let signature = try key.signature(message, using: header.header.value.algorithm)
            return try .init(
                header: header.header.protected,
                unprotectedHeader: header.unprotectedHeader,
                signature: signature
            )
        }
    }
    
    /// Renews all signatures for protected header(s) using given key.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebSigningKey` object that would be used for signing.
    public mutating func updateSignature(using key: any JSONWebSigningKey) throws {
        try updateSignature(using: [key])
    }
    
    /// Verifies all signatures for protected header(s) using given keys.
    ///
    /// This methos finds appropriate key for the header using `kid` value in protected or unprotected header.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    public func verifySignature(using keys: [any JSONWebValidatingKey]) throws {
        try keys.forEach { key in
            let header = signatures.first {
                $0.unprotectedHeader?.keyId == key.keyId || $0.header.value.keyId == key.keyId
            } ?? signatures.first
            guard let protectedHeadeer = header?.header, let signature = header?.signature else { return }
            let message = protectedHeadeer.protected.urlBase64EncodedData() + Data(".".utf8) + payload.protected.urlBase64EncodedData()
            try key.verifySignature(signature, for: message, using: protectedHeadeer.value.algorithm)
        }
    }
    
    /// Verifies all signatures in protected header(s) using given key.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    public func verifySignature(using key: any JSONWebValidatingKey) throws {
        try verifySignature(using: [key])
    }
}

/// JWSs use one of two serializations: the JWS Compact Serialization or the JWS JSON Serialization.
///
/// Applications using this specification need to specify what serialization and serialization features are
/// used for that application.
public enum JSONWebSignatureRepresentation {
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
    ///
    /// - Important: This is default encoding format when using `JSONWebSignature.encode(to:)`.
    ///              To use other encodings, change `.jwsEncodedRepresentation`
    ///              parameter in `userInfo`.
    case compact
    
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

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
public struct JSONWebSignatureCodableConfiguration {
    public let representation: JSONWebSignatureRepresentation
    
    public init(representation: JSONWebSignatureRepresentation) {
        self.representation = representation
    }
}

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
extension JSONWebSignature: EncodableWithConfiguration {
    public typealias EncodingConfiguration = JSONWebSignatureCodableConfiguration
    
    public func encode(to encoder: Encoder, configuration: JSONWebSignatureCodableConfiguration) throws {
        switch configuration.representation {
        case .compact:
            try encodeAsString(encoder)
        case .json:
            switch signatures.count {
            case 0, 1:
                try encodeAsFlattenedJSON(encoder)
            default:
                try encodeAsCompleteJSON(encoder)
            }
        case .jsonGeneral:
            try encodeAsCompleteJSON(encoder)
        case .jsonFlattened:
            try encodeAsFlattenedJSON(encoder)
        }
    }
}

extension String {
    public init<Payload: ProtectedWebContainer>(jws: JSONWebSignature<Payload>) throws {
        self = String(String(decoding: try JSONEncoder().encode(jws), as: UTF8.self).dropFirst().dropLast())
    }
}

extension JSONWebSignature: LosslessStringConvertible, CustomDebugStringConvertible {
    public init?(_ description: String) {
        guard let jws = try? JSONWebSignature<Payload>(from: description) else {
            return nil
        }
        self = jws
    }
    
    public var description: String {
        (try? String(jws: self)) ?? ""
    }
    
    public var debugDescription: String {
        "Signatures: \(signatures.debugDescription)\nPayload: \(String(decoding: payload.protected.urlBase64EncodedData(), as: UTF8.self))"
    }
}
