//
//  File.swift
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
    public var unprotectedHeader: JOSEHeader
    
    /// Signature of protected header concatenated with payload.
    public var signature: Data
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - header: JWS Protected Header.
    ///   - unprotectedHeader: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(header: JOSEHeader, unprotectedHeader: JOSEHeader, signature: Data) throws {
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
    public init(header: Data, unprotectedHeader: JOSEHeader, signature: Data) throws {
        self.header = try ProtectedJSONWebContainer<JOSEHeader>(protected: header)
        self.unprotectedHeader = unprotectedHeader
        self.signature = signature
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.header = try container.decode(ProtectedJSONWebContainer<JOSEHeader>.self, forKey: .protected)
        self.unprotectedHeader = try container.decode(JOSEHeader.self, forKey: .header)
        
        let signatureString = try container.decodeIfPresent(String.self, forKey: .signature) ?? .init()
        self.signature = Data(urlBase64Encoded: signatureString) ?? .init()
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .protected)
        try container.encode(unprotectedHeader, forKey: .header)
        try container.encode(signature.urlBase64EncodedData(), forKey: .signature)
    }
}

/// JWS represents digitally signed or MACed content using JSON data structures and `base64url` encoding.
public struct JSONWebSignature<Payload: JSONWebContainer>: Codable, Hashable {
    /// The "signatures" member value MUST be an array of JSON objects.
    ///
    /// Each object represents a signature or MAC over the JWS Payload and the JWS Protected Header.

    public var signatures: [JSONWebSignatureHeader]
    
    /// The "`payload`" member MUST be present and contain the value of JWS Payload.
    public var payload: ProtectedJSONWebContainer<Payload>
    
    enum CodingKeys: String, CodingKey {
        case payload
        case signatures
    }
    
    public init(from decoder: Decoder) throws {
        let stringContainer = try decoder.singleValueContainer()
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        if let value = try? stringContainer.decode(String.self) {
            let sections = value
                .components(separatedBy: ".")
                .map { Data(urlBase64Encoded: $0) ?? .init() }
            guard sections.count == 3 else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "JWS String is not a three part data."))
            }
            self.payload = try ProtectedJSONWebContainer<Payload>.init(protected: sections[1])
            self.signatures = try [
                .init(
                header: sections[0],
                unprotectedHeader: .init(storage: .init()),
                signature: sections[2])
            ]
        } else if let signatures = try container.decodeIfPresent([JSONWebSignatureHeader].self, forKey: .signatures) {
            self.payload = try container.decode(ProtectedJSONWebContainer<Payload>.self, forKey: .payload)
            self.signatures = signatures
        } else {
            self.payload = try container.decode(ProtectedJSONWebContainer<Payload>.self, forKey: .payload)
            let header = try JSONWebSignatureHeader(from: decoder)
            self.signatures = [header]
        }
    }
    
    fileprivate func encodeAsString(_ encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let value = [
            signatures.first?.header.protected.urlBase64EncodedData() ?? .init(),
            payload.protected.urlBase64EncodedData(),
            signatures.first?.signature.urlBase64EncodedData() ?? .init()]
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
        let representation = encoder.userInfo[.jwsEncodedRepresentation] as? JSONWebSignatureRepresentation ?? .string
        switch representation {
        case .string:
            try encodeAsString(encoder)
        case .automaticJSON:
            switch signatures.count {
            case 0, 1:
                try encodeAsFlattenedJSON(encoder)
            default:
                try encodeAsCompleteJSON(encoder)
            }
        case .completeJSON:
            try encodeAsCompleteJSON(encoder)
        case .flattenedJSON:
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
        signatures = try signatures.map({ header in
            let header = header
            let key = keys.first {
                header.unprotectedHeader.keyId == $0.keyId || header.header.value.keyId == $0.keyId
            } ?? firstKey
            
            let message = header.header.protected.urlBase64EncodedData() + Data(".".utf8) + payload.protected.urlBase64EncodedData()
            let signature = try key.sign(message, using: header.header.value.algorithm)
            return try.init(
                header: header.header.protected,
                unprotectedHeader: header.unprotectedHeader,
                signature: signature)
        })
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
                $0.unprotectedHeader.keyId == key.keyId || $0.header.value.keyId == key.keyId
            } ?? signatures.first
            guard let protectedHeadeer = header?.header, let signature = header?.signature else { return }
            let message = protectedHeadeer.protected.urlBase64EncodedData() + Data(".".utf8) + payload.protected.urlBase64EncodedData()
            try key.validate(signature, for: message, using: protectedHeadeer.value.algorithm)
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

public enum JSONWebSignatureRepresentation {
    case string
    case automaticJSON
    case flattenedJSON
    case completeJSON
}

extension CodingUserInfoKey {
    public static var jwsEncodedRepresentation: Self {
        .init(rawValue: #function).unsafelyUnwrapped
    }
}
