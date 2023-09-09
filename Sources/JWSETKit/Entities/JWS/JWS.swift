//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/8/23.
//

import Foundation

public struct JSONWebSignatureHeader: Hashable, Codable {
    enum CodingKeys: CodingKey {
        case protected
        case header
        case signature
    }
    
    public var header: ProtectedJSONWebContainer<JOSEHeader>
    public var unprotectedHeader: JOSEHeader
    public var signature: Data
    
    public init(header: JOSEHeader, unprotectedHeader: JOSEHeader, signature: Data) throws {
        self.header = try .init(value: header)
        self.unprotectedHeader = unprotectedHeader
        self.signature = signature
    }
    
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
        self.signature = Data(urlBase64Encoded: Data(signatureString.utf8)) ?? .init()
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .protected)
        try container.encode(unprotectedHeader, forKey: .header)
        try container.encode(signature.urlBase64EncodedData(), forKey: .signature)
    }
}

public struct JSONWebSignature<Payload: JSONWebContainer>: Codable, Hashable {
    public var headers: [JSONWebSignatureHeader]
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
                .map { Data(urlBase64Encoded: Data($0.utf8)) ?? .init() }
            guard sections.count == 3 else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "JWS String is not a three part data."))
            }
            self.payload = try ProtectedJSONWebContainer<Payload>.init(protected: sections[1])
            self.headers = try [
                .init(
                header: sections[0],
                unprotectedHeader: .init(storage: .init()),
                signature: sections[2])
            ]
        } else if let signatures = try container.decodeIfPresent([JSONWebSignatureHeader].self, forKey: .signatures) {
            self.payload = try container.decode(ProtectedJSONWebContainer<Payload>.self, forKey: .payload)
            self.headers = signatures
        } else {
            self.payload = try container.decode(ProtectedJSONWebContainer<Payload>.self, forKey: .payload)
            let header = try JSONWebSignatureHeader(from: decoder)
            self.headers = [header]
        }
    }
    
    fileprivate func encodeAsString(_ encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let value = [
            headers.first?.header.protected.urlBase64EncodedData() ?? .init(),
            payload.protected.urlBase64EncodedData(),
            headers.first?.signature.urlBase64EncodedData() ?? .init()]
            .map { String(decoding: $0, as: UTF8.self) }
            .joined(separator: ".")
        try container.encode(value)
    }
    
    fileprivate func encodeAsCompleteJSON(_ encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.protected.urlBase64EncodedData(), forKey: .payload)
        try container.encode(headers, forKey: .signatures)
    }
    
    fileprivate func encodeAsFlattenedJSON(_ encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.protected.urlBase64EncodedData(), forKey: .payload)
        var headerContainer = encoder.container(keyedBy: JSONWebSignatureHeader.CodingKeys.self)
        try headerContainer.encodeIfPresent(headers.first?.header, forKey: .protected)
        try headerContainer.encodeIfPresent(headers.first?.unprotectedHeader, forKey: .header)
        try headerContainer.encodeIfPresent(headers.first?.signature, forKey: .signature)
    }
    
    public func encode(to encoder: Encoder) throws {
        let representation = encoder.userInfo[.jwsEncodedRepresentation] as? JSONWebSignatureRepresentation ?? .string
        switch representation {
        case .string:
            try encodeAsString(encoder)
        case .automaticJSON:
            switch headers.count {
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
    
    public mutating func updateSignature(using keys: [any JSONWebSigningKey]) throws {
        guard let firstKey = keys.first else {
            throw JSONWebKeyError.noKeyProvided
        }
        headers = try headers.map({ header in
            let header = header
            let key = keys.first {
                header.unprotectedHeader.keyId == $0.keyId || header.header.value.keyId == $0.keyId
            } ?? firstKey
            let message = header.header.protected.urlBase64EncodedData() + Data(".".utf8) + payload.protected.urlBase64EncodedData()
            let signature = try key.sign(message)
            return try.init(
                header: header.header.protected,
                unprotectedHeader: header.unprotectedHeader,
                signature: signature)
        })
    }
    
    public mutating func updateSignature(using key: any JSONWebSigningKey) throws {
        try updateSignature(using: [key])
    }
    
    public func verify(using keys: [any JSONWebValidatingKey]) throws {
        try keys.forEach { key in
            let header = headers.first {
                $0.unprotectedHeader.keyId == key.keyId || $0.header.value.keyId == key.keyId
            } ?? headers.first
            guard let protectedHeadeer = header?.header, let signature = header?.signature else { return }
            let message = protectedHeadeer.protected.urlBase64EncodedData() + Data(".".utf8) + payload.protected.urlBase64EncodedData()
            try key.validate(signature, for: message)
        }
    }
    
    public func verify(using key: any JSONWebValidatingKey) throws {
        try verify(using: [key])
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
