//
//  JWE.swift
//
//
//  Created by Amir Abbas Mousavian on 10/3/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// The JWE cryptographic mechanisms encrypt and provide integrity protection
/// for an arbitrary sequence of octets.
public struct JSONWebEncryption: Hashable, Sendable {
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
            recipients.first?.encryptedKey
        }
        set {
            guard let newValue else {
                recipients = []
                return
            }
            if !recipients.isEmpty {
                recipients[0].encryptedKey = newValue
            } else {
                recipients = [.init(encryptedKey: newValue)]
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
        self.recipients = [.init(encryptedKey: encryptedKey)]
        self.sealed = sealed
        self.additionalAuthenticatedData = nil
    }
    
    /// Creates new JWE container with encrypted data using given recipients public key.
    ///
    /// - Note: `algorithm` and `encryptionAlgorithm` parameters in `protected` shall
    ///         be overrided by `keyEncryptingAlgorithm` and `contentEncryptionAlgorithm`.
    ///
    /// - Important: For `PBES2` algorithms, provide password using
    ///         `SymmetricKey(data: Data(password.utf8))` to`keyEncryptionKey`.\
    ///         `pbes2Count` and `pbes2Salt` must be provided in `protected` fields.
    ///
    /// - Parameters:
    ///   - protected: Protected header of JWE.
    ///   - unprotected: Unprotected header of JWE.
    ///   - nonce: Initialization Vector for content encryption.
    ///   - content: Data to be encrypted.
    ///   - additionalAuthenticatedData: An input to an AEAD operation that is integrity protected but not encrypted.
    ///   - keyEncryptingAlgorithm: Encryption algorithm applied to `contentEncryptionKey`
    ///         using `keyEncryptionKey`.
    ///   - keyEncryptionKey: The public key that `contentEncryptionKey` will be encrypted with.
    ///   - contentEncryptionAlgorithm: Algorithm of content encryption.
    ///   - contentEncryptionKey: AEAD key, generates a new key compatible
    ///         with `contentEncryptionAlgorithm` if `nil` is passed.
    public init<ND: DataProtocol, PD: DataProtocol, AD: DataProtocol>(
        protected: JOSEHeader? = nil,
        unprotected: JOSEHeader? = nil,
        nonce _: ND? = Data?.none,
        content: PD,
        additionalAuthenticated _: AD? = Data?.none,
        keyEncryptingAlgorithm: JSONWebKeyEncryptionAlgorithm,
        keyEncryptionKey: (any JSONWebKey)?,
        contentEncryptionAlgorithm: JSONWebContentEncryptionAlgorithm,
        contentEncryptionKey: (any JSONWebSealingKey)? = nil
    ) throws {
        var header = protected ?? JOSEHeader(algorithm: keyEncryptingAlgorithm, type: .jwe)
        header.algorithm = keyEncryptingAlgorithm
        header.encryptionAlgorithm = contentEncryptionAlgorithm
        
        let plainData: any DataProtocol
        if let compressor = header.compressionAlgorithm?.compressor {
            plainData = try compressor.compress(content)
        } else {
            plainData = content
            header.compressionAlgorithm = nil
        }
        
        let handler = keyEncryptingAlgorithm.encryptedKeyHandler ?? JSONWebKeyEncryptionAlgorithm.standardEncryptdKey
        
        let cek: any JSONWebSealingKey
        switch keyEncryptingAlgorithm {
        case .direct:
            // As we don't return content encryption key and content encryption key
            // must be accessible, no autogenerated key is allowed.
            guard let inputCek = contentEncryptionKey else {
                throw JSONWebKeyError.keyNotFound
            }
            cek = inputCek
            self.recipients = []
        case .ecdhEphemeralStatic:
            // Content encryption key is exactly the result of ECDH, thus
            // `contentEncryptionKey` is ignored.
            let cekData = try handler(&header, keyEncryptingAlgorithm, keyEncryptionKey, contentEncryptionAlgorithm, Data())
            cek = SymmetricKey(data: cekData)
            self.recipients = []
        default:
            cek = try contentEncryptionKey ?? contentEncryptionAlgorithm.generateRandomKey()
            guard let cekData = cek.keyValue?.data else {
                throw JSONWebKeyError.keyNotFound
            }
            let mutatedEncryptedKey = try handler(&header, keyEncryptingAlgorithm, keyEncryptionKey, contentEncryptionAlgorithm, cekData)
            self.recipients = [.init(encryptedKey: mutatedEncryptedKey)]
        }
        self.header = try .init(
            protected: ProtectedJSONWebContainer(value: header),
            unprotected: unprotected
        )
        let authenticating = self.header.protected.authenticating(additionalAuthenticatedData: additionalAuthenticatedData)
        self.sealed = try cek.seal(
            plainData,
            authenticating: authenticating,
            using: contentEncryptionAlgorithm
        )
        self.additionalAuthenticatedData = additionalAuthenticatedData.map { Data($0) }
    }
    
    /// Creates new JWE container with encrypted data using given recipients public key.
    ///
    /// - Note: `algorithm` and `encryptionAlgorithm` parameters in `protected` shall
    ///         be overrided by `keyEncryptingAlgorithm` and `contentEncryptionAlgorithm`.
    ///
    /// - Important: For `PBES2` algorithms, provide password using
    ///         `SymmetricKey(data: Data(password.utf8))` to`keyEncryptionKey`.\
    ///         `pbes2Count` and `pbes2Salt` must be provided in `protected` fields.
    ///
    /// - Parameters:
    ///   - protected: Protected header of JWE.
    ///   - unprotected: Unprotected header of JWE.
    ///   - nonce: Initialization Vector for AEAD.
    ///   - content: Data to be encrypted.
    ///   - additionalAuthenticatedData: An input to an AEAD operation that is integrity protected but not encrypted.
    ///   - keyEncryptionKey: The public key that `contentEncryptionKey` will be encrypted with.
    ///   - contentEncryptionAlgorithm: Algorithm of content encryption.
    ///   - contentEncryptionKey: AEAD key, generates a new key compatible
    ///         with `contentEncryptionAlgorithm` if `nil` is passed.
    public init<ND: DataProtocol, PD: DataProtocol>(
        protected: ProtectedJSONWebContainer<JOSEHeader>,
        unprotected: JOSEHeader? = nil,
        nonce: ND? = Data?.none,
        content: PD,
        additionalAuthenticatedData: Data? = nil,
        keyEncryptionKey: (any JSONWebKey)?,
        contentEncryptionKey: (any JSONWebSealingKey)? = nil
    ) throws {
        let mergedHeader = protected.value.merging(unprotected ?? .init(), uniquingKeysWith: { p, _ in p })
        
        let plainData: any DataProtocol
        if let compressor = mergedHeader.compressionAlgorithm?.compressor {
            plainData = try compressor.compress(content)
        } else {
            plainData = content
        }
        
        let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(mergedHeader.algorithm) ?? .direct
        let contentEncryptionAlgorithm = JSONWebContentEncryptionAlgorithm(mergedHeader.encryptionAlgorithm?.rawValue ?? "")
        let handler = keyEncryptingAlgorithm.encryptedKeyHandler ?? JSONWebKeyEncryptionAlgorithm.standardEncryptdKey
        
        let cek: any JSONWebSealingKey
        switch keyEncryptingAlgorithm {
        case .direct:
            // As we don't return content encryption key and content encryption key
            // must be accessible, no autogenerated key is allowed.
            guard let inputCek = contentEncryptionKey else {
                throw JSONWebKeyError.keyNotFound
            }
            cek = inputCek
            self.recipients = []
        case .ecdhEphemeralStatic:
            // Content encryption key is exactly the result of ECDH, thus
            // `contentEncryptionKey` is ignored.
            var modifiedHeader = mergedHeader
            let cekData = try handler(&modifiedHeader, keyEncryptingAlgorithm, keyEncryptionKey, contentEncryptionAlgorithm, Data())
            guard modifiedHeader == mergedHeader else {
                throw JSONWebKeyError.operationNotAllowed
            }
            cek = SymmetricKey(data: cekData)
            self.recipients = []
        default:
            cek = try contentEncryptionKey ?? contentEncryptionAlgorithm.generateRandomKey()
            guard let cekData = cek.keyValue?.data else {
                throw JSONWebKeyError.keyNotFound
            }
            var modifiedHeader = mergedHeader
            let mutatedEncryptedKey = try handler(&modifiedHeader, keyEncryptingAlgorithm, keyEncryptionKey, contentEncryptionAlgorithm, cekData)
            guard modifiedHeader == mergedHeader else {
                throw JSONWebKeyError.operationNotAllowed
            }
            self.recipients = [.init(encryptedKey: mutatedEncryptedKey)]
        }
        self.header = try .init(protected: protected, unprotected: unprotected)
        let authenticating = protected.authenticating(additionalAuthenticatedData: additionalAuthenticatedData)
        self.sealed = try cek.seal(
            plainData,
            iv: nonce,
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
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid JWE."))
        }
    }
    
    /// Initializes JWE using Base64URL encoded String.
    ///
    /// - Parameter string: Base64URL encoded String.
    public init<S: StringProtocol>(from string: S) throws {
        try self.init(from: Data(string.utf8))
    }
    
    /// Decrypts encrypted data, using given private key.
    ///
    /// - Important: For `PBES2` algorithms, provide password using
    ///         `SymmetricKey(data: Data(password.utf8))` to`key`.
    ///
    /// - Parameter key: Key that used to encrypt the content encryption key.
    /// - Returns: Decrypted payload.
    public func decrypt(using key: any JSONWebKey, keyId: String? = nil) throws -> Data {
        let recipient = try? recipients.match(for: key, keyId: keyId)
        let combinedHeader = header.protected.value
            .merging(header.unprotected ?? .init(), uniquingKeysWith: { p, _ in p })
            .merging(recipient?.header ?? .init(), uniquingKeysWith: { p, _ in p })
        guard let contentEncAlgorithm = combinedHeader.encryptionAlgorithm else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        
        var targetEncryptedKey = recipient?.encryptedKey ?? .init()
        guard let algorithm = combinedHeader.algorithm?.specialized() as? JSONWebKeyEncryptionAlgorithm else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        
        var decryptingKey = key
        try algorithm.decryptionMutator?(combinedHeader, &decryptingKey, &targetEncryptedKey)
        guard let decryptingKey = decryptingKey as? (any JSONWebDecryptingKey) else {
            throw JSONWebKeyError.keyNotFound
        }
        let cek = try SymmetricKey(data: decryptingKey.decrypt(targetEncryptedKey, using: algorithm))
        let authenticatingData = header.protected.authenticating(additionalAuthenticatedData: additionalAuthenticatedData)
        let content = try cek.open(sealed, authenticating: authenticatingData, using: contentEncAlgorithm)
        
        if let compressor = combinedHeader.compressionAlgorithm?.compressor {
            return try compressor.decompress(content)
        } else {
            return content
        }
    }
    
    /// Decrypts encrypted data, using given private key.
    ///
    /// - Important: For `PBES2` algorithms, provide password using
    ///         `SymmetricKey(data: Data(password.utf8))` to`key`.
    ///
    /// - Parameter keys: An array of keys that used to encrypt the content encryption key.
    /// - Returns: Decrypted payload.
    public func decrypt(using keys: [any JSONWebKey]) throws -> Data {
        try decrypt(using: JSONWebKeySet(keys: keys))
    }
    
    /// Decrypts encrypted data, using given private key.
    ///
    /// - Important: For `PBES2` algorithms, provide password using
    ///         `SymmetricKey(data: Data(password.utf8))` to`key`.
    ///
    /// - Parameter keySet: An array of keys that used to encrypt the content encryption key.
    /// - Returns: Decrypted payload.
    public func decrypt(using keySet: JSONWebKeySet) throws -> Data {
        let mergedHeader = header.protected.value
            .merging(header.unprotected ?? .init(), uniquingKeysWith: { p, _ in p })
        for recipient in recipients {
            let recipientMergedHeader = recipient.header
                .map { mergedHeader.merging($0, uniquingKeysWith: { p, _ in p }) } ?? mergedHeader
            for key in keySet.matches(for: recipientMergedHeader) {
                if let plain = try? decrypt(using: key) {
                    return plain
                }
            }
        }
        
        throw JSONWebKeyError.keyNotFound
    }
}

extension String {
    /// Encodes JWE to compact representation.
    /// - Parameter jwe: JWE to be encoded.
    /// - Throws: Encoding error.
    public init(_ jwe: JSONWebEncryption) throws {
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.jwsEncodedRepresentation] = JSONWebEncryptionRepresentation.compact
        self = try String(String(decoding: encoder.encode(jwe), as: UTF8.self).dropFirst().dropLast())
    }
}

extension ProtectedWebContainer {
    fileprivate func authenticating(additionalAuthenticatedData: Data?) -> Data {
        let suffix: Data
        if let additionalAuthenticatedData, !additionalAuthenticatedData.isEmpty {
            suffix = Data(".".utf8) + additionalAuthenticatedData.urlBase64EncodedData()
        } else {
            suffix = .init()
        }
        return encoded.urlBase64EncodedData() + suffix
    }
}

extension JSONWebEncryption: LosslessStringConvertible, CustomDebugStringConvertible {
    public init?(_ description: String) {
        guard let jwe = try? JSONWebEncryption(from: description) else {
            return nil
        }
        self = jwe
    }
    
    public var description: String {
        (try? String(self)) ?? ""
    }
    
    public var debugDescription: String {
        """
        Protected Header: \(header.protected.value)
        Unprotected Header: \(String(describing: header.unprotected))
        Recipients: \(recipients)
        IV: \(sealed.nonce.urlBase64EncodedString())
        CipherText: \(sealed.ciphertext.urlBase64EncodedString())
        Tag: \(sealed.tag.urlBase64EncodedString())
        """
    }
}
