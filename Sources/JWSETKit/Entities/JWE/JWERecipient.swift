//
//  JWERecipient.swift
//
//
//  Created by Amir Abbas Mousavian on 10/3/23.
//

import Foundation

/// Contains JWE Per-Recipient Unprotected Header and
/// content encryption key encrypted using recipient's public key.
public struct JSONWebEncryptionRecipient: Hashable, Sendable, Codable {
    enum CodingKeys: String, CodingKey {
        case header
        case encrypedKey = "encrypted_key"
    }
    
    /// JWE Per-Recipient Unprotected Header.
    ///
    /// JSON object that contains Header Parameters that apply to a single
    /// recipient of the JWE.  These Header Parameter values are not
    /// integrity protected.  This can only be present when using the JWE JSON Serialization.
    public var header: JOSEHeader?
    
    /// Content Encryption Key (CEK).
    ///
    /// A symmetric key for the AEAD algorithm used to encrypt the
    /// plaintext to produce the ciphertext and the Authentication Tag.
    public var encrypedKey: Data
    
    /// Initializes a new recipient with given header and encrypted key.
    ///
    /// - Parameters:
    ///   - header: JWE Per-Recipient Unprotected Header.
    ///   - encrypedKey: Content Encryption Key (CEK).
    public init(header: JOSEHeader? = nil, encrypedKey: Data) {
        self.header = header
        self.encrypedKey = encrypedKey
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.header = try container.decodeIfPresent(JOSEHeader.self, forKey: JSONWebEncryptionRecipient.CodingKeys.header)
        let b64Key = try container.decode(String.self, forKey: JSONWebEncryptionRecipient.CodingKeys.encrypedKey)
        guard let key = Data(urlBase64Encoded: b64Key) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath + [CodingKeys.encrypedKey], debugDescription: "Encrypted key is not a valid Base64URL"))
        }
        self.encrypedKey = key
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encodeIfPresent(header, forKey: .header)
        try container.encode(encrypedKey.urlBase64EncodedString(), forKey: .encrypedKey)
    }
}

extension [JSONWebEncryptionRecipient] {
    func match(for key: any JSONWebKey, keyId: String? = nil) throws -> Self.Element {
        if let keyId, let recipient = first(where: {
            $0.header?.keyId == keyId
        }) {
            return recipient
        } else if let recipient = first(where: {
            $0.header?.algorithm.keyType == key.keyType && $0.header?.algorithm.curve == key.curve
        }) {
            return recipient
        } else if let recipient = first {
            return recipient
        } else {
            throw JSONWebKeyError.keyNotFound
        }
    }
}
