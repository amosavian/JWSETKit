//
//  JWECodable.swift
//
//
//  Created by Amir Abbas Mousavian on 10/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

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
    /// Changes serialization of JWE.
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
    
    private init(string: String, codingPath: [any CodingKey]) throws {
        let sections = try string
            .components(separatedBy: ".")
            .map {
                guard let data = Data(urlBase64Encoded: $0) else {
                    throw DecodingError.dataCorrupted(.init(codingPath: codingPath, debugDescription: "JWE String is not base64-encoded data."))
                }
                return data
            }
        guard sections.count == 5 else {
            throw DecodingError.dataCorrupted(.init(codingPath: codingPath, debugDescription: "JWE String is not a five part data."))
        }
        self.header = try JSONWebEncryptionHeader(protected: .init(encoded: sections[0]))
        self.recipients = [JSONWebEncryptionRecipient(encryptedKey: sections[1])]
        let iv = sections[2]
        let ciphertext = sections[3]
        let tag = sections[4]
        self.sealed = .init(nonce: iv, ciphertext: ciphertext, tag: tag)
    }
    
    private init(object decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.header = try JSONWebEncryptionHeader(from: decoder)
        if let recipientsValue = try? container.decode([JSONWebEncryptionRecipient].self, forKey: .recipients) {
            self.recipients = recipientsValue
        } else {
            let recipient = try JSONWebEncryptionRecipient(from: decoder)
            self.recipients = [recipient]
        }
        self.additionalAuthenticatedData = try container.decodeIfPresent(String.self, forKey: .aad)
            .flatMap(Data.init(urlBase64Encoded:))
        let iv = try Data(urlBase64Encoded: container.decode(String.self, forKey: .iv))
        let ciphertext = try Data(urlBase64Encoded: container.decode(String.self, forKey: .ciphertext))
        let tag = try Data(urlBase64Encoded: container.decode(String.self, forKey: .tag))
        self.sealed = .init(nonce: iv ?? .init(), ciphertext: ciphertext ?? .init(), tag: tag ?? .init())
    }
    
    public init(from decoder: any Decoder) throws {
        if let stringContainer = try? decoder.singleValueContainer(), let value = try? stringContainer.decode(String.self) {
            try self.init(string: value, codingPath: decoder.codingPath)
        } else {
            try self.init(object: decoder)
        }
    }
    
    fileprivate func encodeAsString(_ encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        let value = [
            header.protected.encoded,
            encryptedKey ?? .init(),
            sealed.nonce,
            sealed.ciphertext,
            sealed.tag,
        ]
        .map { $0.urlBase64EncodedData() }
        .joinedString(separator: .init(".".utf8))
        try container.encode(value)
    }
    
    fileprivate func encodeAsCompleteJSON(_ encoder: any Encoder) throws {
        try header.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(recipients, forKey: .recipients)
        try container.encodeIfPresent(additionalAuthenticatedData, forKey: .aad)
        try container.encode(sealed.nonce, forKey: .iv)
        try container.encode(sealed.ciphertext, forKey: .ciphertext)
        try container.encode(sealed.tag, forKey: .tag)
    }
    
    fileprivate func encodeAsFlattenedJSON(_ encoder: any Encoder) throws {
        try header.encode(to: encoder)
        try recipients.first?.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(additionalAuthenticatedData, forKey: .aad)
        try container.encode(sealed.nonce, forKey: .iv)
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
    
    fileprivate func encodeFunction(for representation: JSONWebEncryptionRepresentation) -> (_ encoder: any Encoder) throws -> Void {
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
    
    public func encode(to encoder: any Encoder) throws {
        let representation = encoder.userInfo[.jweEncodedRepresentation] as? JSONWebEncryptionRepresentation ?? .compact
        try encodeFunction(for: representation)(encoder)
    }
}

/// Allows encoding JWE with configuration for representation style of JWE such as compact, flattened JSON or JSON.
public struct JSONWebEncryptionCodableConfiguration: Sendable {
    /// Changes serialization of JWE.
    ///
    /// Applications using this specification need to specify what serialization and serialization features are
    /// used for that application.
    ///
    /// Default value is `.compact` if not set.
    public let representation: JSONWebEncryptionRepresentation
    
    public init(representation: JSONWebEncryptionRepresentation) {
        self.representation = representation
    }
}

extension JSONWebEncryption: EncodableWithConfiguration {
    public typealias EncodingConfiguration = JSONWebEncryptionCodableConfiguration
    
    public func encode(to encoder: any Encoder, configuration: JSONWebEncryptionCodableConfiguration) throws {
        try encodeFunction(for: configuration.representation)(encoder)
    }
}
