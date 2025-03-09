//
//  JWERecipient.swift
//
//
//  Created by Amir Abbas Mousavian on 10/3/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Contains JWE Per-Recipient Unprotected Header and
/// content encryption key encrypted using recipient's public key.
public struct JSONWebEncryptionRecipient: Hashable, Sendable, Codable {
    enum CodingKeys: String, CodingKey {
        case header
        case encryptedKey = "encrypted_key"
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
    public var encryptedKey: Data
    
    /// Initializes a new recipient with given header and encrypted key.
    ///
    /// - Parameters:
    ///   - header: JWE Per-Recipient Unprotected Header.
    ///   - encryptedKey: Content Encryption Key (CEK).
    public init(header: JOSEHeader? = nil, encryptedKey: Data) {
        self.header = header
        self.encryptedKey = encryptedKey
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.header = try container.decodeIfPresent(JOSEHeader.self, forKey: JSONWebEncryptionRecipient.CodingKeys.header)
        let b64Key = try container.decode(String.self, forKey: JSONWebEncryptionRecipient.CodingKeys.encryptedKey)
        guard let key = Data(urlBase64Encoded: b64Key) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath + [CodingKeys.encryptedKey], debugDescription: "Encrypted key is not a valid Base64URL"))
        }
        self.encryptedKey = key
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        if let header, !header.storage.storageKeys.isEmpty {
            try container.encode(header, forKey: .header)
        }
        try container.encode(encryptedKey.urlBase64EncodedString(), forKey: .encryptedKey)
    }
}

extension [JSONWebEncryptionRecipient] {
    func match(for key: any JSONWebKey, keyId: String? = nil) throws -> Self.Element {
        if let keyId, let recipient = first(where: {
            $0.header?.keyId == keyId
        }) {
            return recipient
        } else if let recipient = first(where: {
            guard let algorithm = $0.header?.algorithm else { return false }
            return (algorithm.keyType == key.keyType && algorithm.curve == key.curve) ||
                ($0.header?.ephemeralPublicKey?.keyType == key.keyType && $0.header?.ephemeralPublicKey?.curve == key.curve)
        }) {
            return recipient
        } else if let recipient = first {
            return recipient
        } else {
            throw JSONWebKeyError.keyNotFound
        }
    }
}
