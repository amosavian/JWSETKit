//
//  JWTPopClaims.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 1/15/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
#if canImport(CommonCrypto)
import CommonCrypto
#endif
#if canImport(X509)
import X509
#endif

/// Presenter possesses a particular key and that the recipient can cryptographically
/// confirm that the presenter has possession of that key as described in
/// [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800.html ).
public enum JSONWebTokenConfirmation: Codable, Hashable, Sendable {
    /// A JWK representing the confirmation key.
    case key(_ key: AnyJSONWebKey)
    
    /// A JWE object in compact form that contains a JWK as its payload.
    case encryptedKey(_ encryptedKey: JSONWebEncryption)
    
    /// A JWK Set URL that refers to a resource for a set of JWKs, from which the recipient
    /// can identify the key being used.
    ///
    /// `keyId` may be `nil` if only one matching key is provided in JWKS.
    case url(_ setURL: URL, keyId: String? = nil)
    
    /// Key ID value that matches a key identifier of the referenced key.
    case keyId(_ keyId: String)
    
    /// SHA-256 hash of the key's JWK representation.
    case keyThumbprint(_ thumbprint: Data)
    
    /// SHA-256 hash of the Certificate public key.
    case certificateThumbprint(_ thumbprint: Data)
    
    enum CodingKeys: String, CodingKey {
        case jwk
        case jwe
        case kid
        case jku
        case x5tS256 = "x5t#S256"
        case jkt
    }
    
    /// A unique identifier for the signing key.
    ///
    /// This claim is used to identify the key that was used to sign the JWT.
    /// The value should match the `kid` parameter in the confirmation(`cnf`) payload.
    public var keyId: String? {
        switch self {
        case .keyId(let keyId):
            keyId
        case .url(_, keyId: let keyId):
            keyId
        default:
            nil
        }
    }
    
    /// JWKS url when the key is provided by `jku`.
    ///
    /// - Note: This URL can be used to download keys and initialize ``JSONWebKeySet`` which should be passed
    ///     to ``matchKey(from:decryptingKeyset:)`` function.
    public var jwkSetUrl: URL? {
        switch self {
        case .url(let url, _):
            url
        default:
            nil
        }
    }
    
    /// A key that can be used to verify the authenticity of the token.
    /// This property represents a cryptographic key used for validation purposes in the JWT POP claims.
    ///
    /// The key conforms to the `JSONWebValidatingKey` protocol, allowing various key types to be used.
    /// It's optional, indicating that a POP claim might not always include a key.
    public var key: (any JSONWebValidatingKey)? {
        switch self {
        case .key(let key):
            key.specialized() as? (any JSONWebValidatingKey)
        default:
            nil
        }
    }
    
    /// Creates a claim with a public key value.
    ///
    /// - Parameter value: The keyinstance to be used as the `jwk` claim. If key is a private
    ///     private key, Public key value will be used.
    /// - Returns: A new `JSONWebTokenConfirmation` instance with the specified JWK value.
    @_disfavoredOverload
    public static func key(_ value: any JSONWebKey) -> Self {
        switch value {
        case let value as any JSONWebSigningKey:
            .key(AnyJSONWebKey(value.publicKey))
        case let value as any JSONWebDecryptingKey:
            .key(AnyJSONWebKey(value.publicKey))
        default:
            .key(AnyJSONWebKey(value))
        }
    }
    
    /// SHA-256 hash of the key's JWK representation.
    public static func keyThumbprint(_ key: any JSONWebKey) throws -> Self {
        try .keyThumbprint(key.thumbprint(format: .jwk, using: SHA256.self).data)
    }
    
    /// SHA-256 hash of the Certificate public key.
    public static func certificateThumbprint(_ key: any JSONWebKey) throws -> Self {
        try .certificateThumbprint(key.thumbprint(format: .spki, using: SHA256.self).data)
    }

#if canImport(X509)
    /// SHA-256 hash of the Certificate public key.
    public static func certificateThumbprint(_ key: Certificate) throws -> Self {
        try .certificateThumbprint(key.thumbprint(format: .spki, using: SHA256.self).data)
    }
#endif
    
#if canImport(CommonCrypto)
    /// SHA-256 hash of the Certificate public key.
    public static func certificateThumbprint(_ key: SecCertificate) throws -> Self {
        try .certificateThumbprint(key.thumbprint(format: .spki, using: SHA256.self).data)
    }
#endif
    
    /// Creates a POP claim that encrypts a given key using a key encryption key (KEK).
    ///
    /// This function encrypts the provided key using the specified key encryption key,
    /// creating a protected POP claim that can be included in a JWT.
    ///
    /// - Parameters:
    ///   - value: The key to be encrypted, conforming to `JSONWebKeyExportable`
    ///   - keyEncryptionKey: The key used to encrypt the provided key, conforming to `JSONWebEncryptingKey`
    ///
    /// - Returns: A new `cnf`` claim instance containing the encrypted key.
    ///
    /// - Throws: An error if the encryption process fails.
    public static func encryptedKey(
        _ value: any JSONWebKeyExportable,
        keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        keyEncryptionKey: (any JSONWebKey)?,
        contentEncryptionAlgorithm: JSONWebContentEncryptionAlgorithm = .aesEncryptionGCM128
    ) throws -> Self {
        let jwe = try JSONWebEncryption(
            protected: .init(),
            content: value.exportKey(format: .jwk),
            keyEncryptingAlgorithm: keyEncryptingAlgorithm,
            keyEncryptionKey: keyEncryptionKey,
            contentEncryptionAlgorithm: contentEncryptionAlgorithm
        )
        return .encryptedKey(jwe)
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let jwk = try container.decodeIfPresent(AnyJSONWebKey.self, forKey: .jwk) {
            self = .key(jwk)
            return
        } else if let jwe = try container.decodeIfPresent(JSONWebEncryption.self, forKey: .jwe) {
            self = .encryptedKey(jwe)
            return
        } else if let jku = try container.decodeIfPresent(URL.self, forKey: .jku) {
            let kid = try container.decodeIfPresent(String.self, forKey: .kid)
            self = .url(jku, keyId: kid)
        } else if let x5t = try container.decodeIfPresent(String.self, forKey: .x5tS256) {
            guard let x5tData = Data(urlBase64Encoded: x5t) else {
                throw DecodingError.dataCorruptedError(forKey: .x5tS256, in: container, debugDescription: "Base64 is invalid.")
            }
            self = .certificateThumbprint(x5tData)
        } else if let jkt = try container.decodeIfPresent(String.self, forKey: .jkt) {
            guard let jktData = Data(urlBase64Encoded: jkt) else {
                throw DecodingError.dataCorruptedError(forKey: .jkt, in: container, debugDescription: "Base64 is invalid.")
            }
            self = .certificateThumbprint(jktData)
        } else {
            self = try .keyId(container.decode(String.self, forKey: .kid))
        }
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .key(let jwk):
            try container.encode(jwk, forKey: .jwk)
        case .encryptedKey(let jwe):
            try container.encode(jwe, forKey: .jwe)
        case .keyId(let kid):
            try container.encode(kid, forKey: .kid)
        case .url(let setURL, let kid):
            try container.encode(setURL, forKey: .jku)
            try container.encodeIfPresent(kid, forKey: .kid)
        case .certificateThumbprint(let x5t):
            try container.encode(x5t, forKey: .x5tS256)
        case .keyThumbprint(let jkt):
            try container.encode(jkt, forKey: .jkt)
        }
    }
    
    /// Decrypts the key using the provided decrypting key.
    ///
    /// - Parameter key: The key used for decryption.
    /// - Returns: A key if decryption is successful, nil otherwise.
    /// - Throws: An error if the decryption process fails.
    public func decryptedKey(using key: any JSONWebKey) throws -> (any JSONWebValidatingKey)? {
        try decryptedKey(using: [key])
    }
    
    /// Decrypts and retrieves a validating key from a set of keys.
    ///
    /// - Parameter keySet: An array of `JSONWebKey` objects to use for decryption
    /// - Returns: An optional `JSONWebValidatingKey` if decryption is successful
    /// - Throws: Errors that may occur during the decryption process
    public func decryptedKey(using keySet: [any JSONWebKey]) throws -> (any JSONWebValidatingKey)? {
        switch self {
        case .key(let jwk):
            jwk.specialized() as? (any JSONWebValidatingKey)
        case .encryptedKey(let jwe):
            try JSONDecoder().decode(AnyJSONWebKey.self, from: jwe.decrypt(using: keySet)).specialized() as? (any JSONWebValidatingKey)
        default:
            nil
        }
    }
    
    /// Decrypts and retrieves a validating key from a set of keys.
    ///
    /// - Parameter keys: A JWK set contains private keys for decryption.
    /// - Returns: An optional `JSONWebValidatingKey` if decryption is successful
    /// - Throws: Errors that may occur during the decryption process
    public func decryptedKey(using keys: JSONWebKeySet) throws -> (any JSONWebValidatingKey)? {
        try decryptedKey(using: keys.keys)
    }
    
    /// Validates whether the given key matches the thumbprint stored in the proof of possession claims.
    ///
    /// - Parameter key: A key to validate against the stored thumbprint.
    /// - Throws: An error if the validation fails or if the thumbprint calculation encounters an error.
    public func validateThumbprint(_ key: any JSONWebKey) throws {
        switch self {
        case .certificateThumbprint(let thumbprint):
            guard try key.thumbprint(format: .spki, using: SHA256.self).data == thumbprint else {
                throw JSONWebKeyError.operationNotAllowed
            }
        case .keyThumbprint(let thumbprint):
            guard try key.thumbprint(format: .jwk, using: SHA256.self).data == thumbprint else {
                throw JSONWebKeyError.operationNotAllowed
            }
        default:
            break
        }
    }
    
    /// Attempts to resolve and return a validating key based on the proof-of-possession claim.
    ///
    /// This method inspects the current confirmation (`cnf`) claim and tries to find a matching
    /// validating key from the provided key sets. It supports all confirmation types, including
    /// direct key, encrypted key, key set URL, key ID, and thumbprints.
    ///
    /// - Parameters:
    ///   - keySet: An optional `JSONWebKeySet` containing candidate keys for matching by key ID, URL, or thumbprint.
    ///   - decryptingKeyset: An optional `JSONWebKeySet` containing private keys for decrypting an encrypted key.
    /// - Returns: A matching key conforming to `JSONWebValidatingKey` if found.
    /// - Throws: `JSONWebKeyError.keyNotFound` if no matching key is found, or errors from decryption or decoding.
    public func matchKey(from keySet: JSONWebKeySet = .init(), decryptingKeyset: JSONWebKeySet? = nil) throws -> any JSONWebValidatingKey {
        let key: (any JSONWebKey)?
        switchcase: switch self {
        case .key(let value):
            key = value.specialized()
        case .encryptedKey(let jwe):
            guard let decryptingKeyset else {
                throw JSONWebKeyError.keyNotFound
            }
            key = try JSONDecoder().decode(AnyJSONWebKey.self, from: jwe.decrypt(using: decryptingKeyset))
        case .url(_, let keyId):
            if let keyId {
                key = keySet[keyId: keyId]
            } else if keySet.count == 1 {
                key = keySet.first
            } else {
                key = nil
            }
        case .keyId(let keyId):
            key = keySet[keyId: keyId]
        case .keyThumbprint(let thumbprint):
            key = keySet[thumbprint: thumbprint]
        case .certificateThumbprint(let thumbprint):
            for item in keySet {
                if try item.thumbprint(format: .spki, using: SHA256.self) == thumbprint {
                    key = item
                    break switchcase
                }
            }
            key = nil
        }
        if let key = key as? (any JSONWebValidatingKey) {
            return key
        } else if let key, let result = AnyJSONWebKey(key).specialized() as? (any JSONWebValidatingKey) {
            return result
        } else {
            throw JSONWebKeyError.keyNotFound
        }
    }
}

/// Claims registered in [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800.html)
public struct JSONWebTokenClaimsPopParameters: JSONWebContainerParameters {
    /// The "cnf" claim is used in the JWT to contain members used to
    /// identify the proof-of-possession key.  Other members of the "cnf"
    /// object may be defined because a proof-of-possession key may not be
    /// the only means of confirming the authenticity of the token.
    ///
    /// The "cnf" claim value MUST represent only a single proof-of-
    /// possession key; thus, at most one of the "jwk", "jwe", and "jku" (JWK
    /// Set URL) confirmation values defined below may be present.  Note that
    /// if an application needs to represent multiple proof-of-possession
    /// keys in the same JWT, one way for it to achieve this is to use other
    /// claim names, in addition to "cnf", to hold the additional proof-of-possession
    /// key information.
    public var confirmation: JSONWebTokenConfirmation?
    
    @_documentation(visibility: private)
    public static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.confirmation: "cnf",
    ]
}

extension JSONWebTokenClaims {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPopParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
