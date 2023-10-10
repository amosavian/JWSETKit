//
//  JWE.swift
//
//
//  Created by Amir Abbas Mousavian on 10/3/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The JWE cryptographic mechanisms encrypt and provide integrity protection
/// for an arbitrary sequence of octets.
public struct JSONWebEncryption: Hashable {
    /// Contains JWE Protected Header and JWE Shared Unprotected Header.
    public var header: JSONWebEncryptionHeader
    
    /// Contains JWE Per-Recipient Unprotected Header and
    /// content encryption key encrypted using recipient's public key.
    public var recipients: [JSONWebEncryptionRecipient]
    
    /// Contains JWE Initialization Vector, JWE Ciphertext and JWE Authentication Tag.
    public var sealed: SealedData
    
    /// An input to an AEAD operation that is integrity protected but not encrypted.
    public var additionalAuthenticatedData: Data?
    
    /// A symmetric key for the AEAD algorithm used to encrypt the plaintext
    /// to produce the ciphertext and the Authentication Tag.
    public var encryptedKey: Data? {
        get {
            recipients.first?.encrypedKey
        }
        set {
            guard let newValue else {
                recipients = []
                return
            }
            if !recipients.isEmpty {
                recipients[0].encrypedKey = newValue
            } else {
                recipients = [.init(encrypedKey: newValue)]
            }
        }
    }
    
    /// Creates new JWE container.
    ///
    /// - Parameters:
    ///   - header: Contains JWE Protected Header and JWE Shared Unprotected Header.
    ///   - recipients: Contains JWE Per-Recipient Unprotected Header and
    ///         content encryption key encrypted using recipient's public key.
    ///   - sealed: Contains JWE Initialization Vector, JWE Ciphertext and JWE Authentication Tag.
    ///   - additionalAuthenticatedData: An input to an AEAD operation that is integrity protected but not encrypted.
    public init(header: JSONWebEncryptionHeader, recipients: [JSONWebEncryptionRecipient], sealed: SealedData, additionalAuthenticatedData: Data? = nil) throws {
        self.header = header
        self.recipients = recipients
        self.sealed = sealed
        self.additionalAuthenticatedData = additionalAuthenticatedData
    }
    
    /// Creates new JWE container.
    ///
    /// - Parameters:
    ///   - protected: JWE Protected Header.
    ///   - encryptedKey: A symmetric key for the AEAD algorithm used to encrypt the plaintext
    ///         to produce the ciphertext and the Authentication Tag.
    ///   - sealed: Contains JWE Initialization Vector, JWE Ciphertext and JWE Authentication Tag.
    public init(protected: ProtectedJSONWebContainer<JOSEHeader>, encryptedKey: Data, sealed: SealedData) throws {
        self.header = try .init(protected: protected)
        self.recipients = [.init(encrypedKey: encryptedKey)]
        self.sealed = sealed
        self.additionalAuthenticatedData = nil
    }
    
    /// Creates new JWE container with encrypted data using given recipients public key.
    ///
    /// - Parameters:
    ///   - plainData: Data to be encrypted.
    ///   - compressionAlgorithm: Compression algorithm of plain-text, if applicable.
    ///   - additionalAuthenticatedData: An input to an AEAD operation that is integrity protected but not encrypted.
    ///   - keyEncryptingAlgorithm: Encryption algorithm applied to `contentEncryptionKey`
    ///         using `keyEncryptionKey`.
    ///   - keyEncryptionKey: The public key that `contentEncryptionKey` will be encrypted with.
    ///   - contentEncryptionAlgorithm: Algorithm of content encryption.
    ///   - contentEncryptionKey: AEAD key, generates a new key compatible
    ///         with `contentEncryptionAlgorithm` if `nil` is passed.
    public init<D: DataProtocol>(
        plainData: D,
        compressionAlgorithm: JSONWebCompressionAlgorithm? = nil,
        additionalAuthenticatedData: Data? = nil,
        keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        keyEncryptionKey: (any JSONWebEncryptingKey)?,
        contentEncryptionAlgorithm: JSONWebContentEncryptionAlgorithm,
        contentEncryptionKey: (any JSONWebSealingKey)? = nil
    ) throws {
        var header = JOSEHeader(algorithm: keyEncryptingAlgorithm, type: "JWE")
        header.encryptionAlgorithm = contentEncryptionAlgorithm
        header.compressionAlgorithm = compressionAlgorithm
        
        let cek = try contentEncryptionKey ?? contentEncryptionAlgorithm.generateRandomKey()
        let cekData = try JSONEncoder().encode(cek)
        switch keyEncryptingAlgorithm {
        case .direct:
            self.recipients = []
        case .aesGCM128KeyWrap, .aesGCM192KeyWrap, .aesGCM256KeyWrap:
            guard let kek = keyEncryptionKey?.keyValue else {
                throw JSONWebKeyError.keyNotFound
            }
            let sealed = try kek.seal(cekData, using: JSONWebContentEncryptionAlgorithm(keyEncryptingAlgorithm.rawValue.dropLast(2)))
            header.initialVector = sealed.iv
            header.authenticationTag = sealed.tag
            self.recipients = [.init(encrypedKey: sealed.ciphertext)]
        case .pbes2hmac256, .pbes2hmac384, .pbes2hmac512:
            fatalError()
        default:
            guard let keyEncryptionKey else {
                throw JSONWebKeyError.keyNotFound
            }
            self.recipients = try [
                .init(encrypedKey: keyEncryptionKey.encrypt(cekData, using: keyEncryptingAlgorithm)),
            ]
        }
        self.header = try .init(protected: ProtectedJSONWebContainer(value: header))
        let authenticating = self.header.protected.encoded.urlBase64EncodedData() + (additionalAuthenticatedData ?? .init())
        self.sealed = try cek.seal(
            plainData,
            authenticating: authenticating,
            using: contentEncryptionAlgorithm
        )
        self.additionalAuthenticatedData = additionalAuthenticatedData
    }
    
    /// Decodes a data that may contain either Base64URL encoded string of JWE or a Complete/Flattened JWE representation.
    ///
    /// - Parameter data: Either Base64URL encoded string of JWE or a JSON with Complete/Flattened JWE representation.
    public init<D: DataProtocol>(from data: D) throws {
        if data.starts(with: Data("ey".utf8)) {
            let container = Data("\"".utf8) + Data(data) + Data("\"".utf8)
            self = try JSONDecoder().decode(JSONWebEncryption.self, from: container)
        } else if data.starts(with: Data("{".utf8)) {
            self = try JSONDecoder().decode(JSONWebEncryption.self, from: Data(data))
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid JWS."))
        }
    }
    
    /// Initialzes JWE using Base64URL encoded String.
    ///
    /// - Parameter string: Base64URL encoded String.
    public init<S: StringProtocol>(from string: S) throws {
        try self.init(from: Data(string.utf8))
    }
    
    /// Decrypts encrypted data, using given private key.
    public func decrypt(using key: any JSONWebKey) throws -> Data {
        guard let algorithm = AnyJSONWebAlgorithm.specialized(header.protected.value.algorithm.rawValue) as? JSONWebKeyEncryptionAlgorithm else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let contentEncAlgorithm = header.protected.value.encryptionAlgorithm else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        let cek: any JSONWebSealingKey
        switch algorithm {
        case .direct:
            guard let cekCandidate = key as? (any JSONWebSealingKey) else {
                throw JSONWebKeyError.keyNotFound
            }
            cek = cekCandidate
        case .aesGCM128KeyWrap, .aesGCM192KeyWrap, .aesGCM256KeyWrap:
            guard let key = key as? (any JSONWebSealingKey) else {
                throw JSONWebKeyError.keyNotFound
            }
            guard let iv = header.protected.value.initialVector, let tag = header.protected.value.authenticationTag else {
                throw CryptoKitError.authenticationFailure
            }
            let algorithm = JSONWebContentEncryptionAlgorithm(algorithm.rawValue.dropLast(2))
            guard let cekData = recipients.compactMap({
                try? key.open(.init(iv: iv, ciphertext: $0.encrypedKey, tag: tag), using: algorithm)
            }).first else {
                throw JSONWebKeyError.keyNotFound
            }
            cek = SymmetricKey(data: cekData)
        case .pbes2hmac256, .pbes2hmac384, .pbes2hmac512:
            fatalError()
        default:
            guard let key = key as? (any JSONWebDecryptingKey) else {
                throw JSONWebKeyError.keyNotFound
            }
            guard let cekData = recipients.compactMap({
                try? key.decrypt($0.encrypedKey, using: algorithm)
            }).first else {
                throw JSONWebKeyError.keyNotFound
            }
            cek = SymmetricKey(data: cekData)
        }
        let authenticating = header.protected.encoded.urlBase64EncodedData() + (additionalAuthenticatedData ?? .init())
        return try cek.open(sealed, authenticating: authenticating, using: contentEncAlgorithm)
    }
}
