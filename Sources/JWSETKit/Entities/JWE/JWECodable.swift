//
//  JWECodable.swift
//
//
//  Created by Amir Abbas Mousavian on 10/5/23.
//

import Foundation

/// JWSs use one of two serializations: the JWE Compact Serialization or the JWEJSON Serialization.
///  
/// Applications using this specification need to specify what serialization and serialization features are
/// used for that application.
///  
/// To change the representation  of JWE during encoding to flattened JSON:
/// ```swift
/// do {
///     var encoder = JSONEncoder()
///     encoder.userInfo[.jweEncodedRepresentation] = JSONWebEncryptionRepresentation.jsonFlattened
///     try encoder.encode(jwe)
/// } catch {
///     print(error)
/// }
/// ```
public enum JSONWebEncryptionRepresentation: Sendable {
    /// /// The JWE Compact Serialization represents encrypted content as a
    /// compact, URL-safe string.
    ///
    /// This string is:
    /// ```
    /// BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    /// BASE64URL(JWE Encrypted Key) || '.' ||
    /// BASE64URL(JWE Initialization Vector) || '.' ||
    /// BASE64URL(JWE Ciphertext) || '.' ||
    /// BASE64URL(JWE Authentication Tag)
    ///
    /// Only one recipient is supported by the JWE Compact Serialization and
    /// it provides no syntax to represent JWE Shared Unprotected Header, JWE
    /// Per-Recipient Unprotected Header, or JWE AAD values.
    case compact
    
    /// The JWE JSON Serialization represents encrypted content as a JSON
    /// object.  This representation is neither optimized for compactness nor
    /// URL safe.
    case json
    
    /// The JWE JSON Serialization represents encrypted content as a JSON
    /// object.  This representation is neither optimized for compactness nor
    /// URL safe.
    ///
    /// This form supports only one recipient.
    case jsonFlattened
    
    /// The JWE JSON Serialization represents encrypted content as a JSON
    /// object.  This representation is neither optimized for compactness nor
    /// URL safe.
    ///
    /// This form supports multiple recipients.
    case jsonGeneral
}

extension CodingUserInfoKey {
    /// Changes serialzation of JWE.
    ///
    /// Default value is `.compact` if not set.
    public static var jweEncodedRepresentation: Self {
        .init(rawValue: #function).unsafelyUnwrapped
    }
}

extension JSONWebEncryption: Codable {
    enum CodingKeys: String, CodingKey {
        case recipients
        case aad
        case iv
        case ciphertext
        case tag
    }
    
    public init(from decoder: Decoder) throws {
        let header: JSONWebEncryptionHeader
        let recipients: [JSONWebEncryptionRecipient]
        let aad: Data?
        let iv: Data?
        let ciphertext: Data?
        let tag: Data?
        if let stringContainer = try? decoder.singleValueContainer(), let value = try? stringContainer.decode(String.self) {
            let sections = value
                .components(separatedBy: ".")
                .map { Data(urlBase64Encoded: $0) }
            guard sections.count == 5 else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "JWE String is not a five part data."))
            }
            header = try .init(protected: .init(encoded: sections[0] ?? .init()))
            recipients = sections[1].map { [.init(encrypedKey: $0)] } ?? []
            aad = nil
            iv = sections[2]
            ciphertext = sections[3]
            tag = sections[4]
        } else {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            header = try JSONWebEncryptionHeader(from: decoder)
            if let recipientsValue = try? container.decode([JSONWebEncryptionRecipient].self, forKey: .recipients) {
                recipients = recipientsValue
            } else {
                let recipient = try JSONWebEncryptionRecipient(from: decoder)
                recipients = [recipient]
            }
            aad = try container.decodeIfPresent(String.self, forKey: .aad)
                .flatMap(Data.init(urlBase64Encoded:))
            iv = try Data(urlBase64Encoded: container.decode(String.self, forKey: .iv))
            ciphertext = try Data(urlBase64Encoded: container.decode(String.self, forKey: .ciphertext))
            tag = try Data(urlBase64Encoded: container.decode(String.self, forKey: .tag))
        }
        
        try self.init(
            header: header,
            recipients: recipients,
            sealed: .init(iv: iv ?? .init(), ciphertext: ciphertext ?? .init(), tag: tag ?? .init()),
            additionalAuthenticatedData: aad
        )
    }
    
    fileprivate func encodeAsString(_ encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let value = [
            header.protected.encoded,
            encryptedKey ?? .init(),
            sealed.iv,
            sealed.ciphertext,
            sealed.tag,
        ]
        .map { String(decoding: $0.urlBase64EncodedData(), as: UTF8.self) }
        .joined(separator: ".")
        try container.encode(value)
    }
    
    fileprivate func encodeAsCompleteJSON(_ encoder: Encoder) throws {
        try header.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(recipients, forKey: .recipients)
        try container.encodeIfPresent(additionalAuthenticatedData, forKey: .aad)
        try container.encode(sealed.iv, forKey: .iv)
        try container.encode(sealed.ciphertext, forKey: .ciphertext)
        try container.encode(sealed.tag, forKey: .tag)
    }
    
    fileprivate func encodeAsFlattenedJSON(_ encoder: Encoder) throws {
        try header.encode(to: encoder)
        try recipients.first?.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(additionalAuthenticatedData, forKey: .aad)
        try container.encode(sealed.iv, forKey: .iv)
        try container.encode(sealed.ciphertext, forKey: .ciphertext)
        try container.encode(sealed.tag, forKey: .tag)
    }
    
    fileprivate func bestRepresentation() -> JSONWebSignatureRepresentation {
        switch recipients.count {
        case 0, 1:
            return .compact
        default:
            return .json
        }
    }
    
    fileprivate func encodeFunction(for representation: JSONWebEncryptionRepresentation) -> (_ encoder: Encoder) throws -> Void {
        switch representation {
        case .compact:
            return encodeAsString
        case .json:
            switch recipients.count {
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
        let representation = encoder.userInfo[.jweEncodedRepresentation] as? JSONWebEncryptionRepresentation ?? .compact
        try encodeFunction(for: representation)(encoder)
    }
}

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
public struct JSONWebEncryptionCodableConfiguration: Sendable {
    public let representation: JSONWebEncryptionRepresentation
    
    public init(representation: JSONWebEncryptionRepresentation) {
        self.representation = representation
    }
}

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
extension JSONWebEncryption: EncodableWithConfiguration {
    public typealias EncodingConfiguration = JSONWebEncryptionCodableConfiguration
    
    public func encode(to encoder: Encoder, configuration: JSONWebEncryptionCodableConfiguration) throws {
        try encodeFunction(for: configuration.representation)(encoder)
    }
}
