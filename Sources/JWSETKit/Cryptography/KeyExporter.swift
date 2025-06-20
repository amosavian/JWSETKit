//
//  KeyExporter.swift
//
//
//  Created by Amir Abbas Mousavian on 2/10/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// A string describing the data format of the key to import/export.
public enum JSONWebKeyFormat: String, Codable, Hashable {
    /// You can use this format to import or export AES or HMAC secret keys, or Elliptic Curve public keys.
    ///
    /// In this format the key is supplied as an `Data` containing the raw bytes for the key.
    case raw
    
    /// You can use this format to import or export RSA or Elliptic Curve private keys.
    ///
    /// The PKCS #8 format is defined in [RFC 5208](https://www.rfc-editor.org/rfc/rfc5208),
    /// using the ASN.1 notation:
    ///
    /// ```
    /// PrivateKeyInfo ::= SEQUENCE {
    /// version                   Version,
    /// privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    /// privateKey                PrivateKey,
    /// attributes           [0]  IMPLICIT Attributes OPTIONAL }
    /// ```
    case pkcs8
    
    /// You can use this format to import or export RSA or Elliptic Curve public keys.
    ///
    /// SubjectPublicKey is defined in RFC 5280, Section 4.1 using the ASN.1 notation:
    ///
    /// ```
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    /// algorithm            AlgorithmIdentifier,
    /// subjectPublicKey     BIT STRING  }
    /// ```
    ///
    /// Just like PKCS #8, the importKey() method expects to receive this object as an `Data`
    /// containing the DER-encoded form of the SubjectPublicKeyInfo.
    case spki
    
    /// JSON Web Key format is defined in RFC 7517.
    ///
    /// It describes a way to represent public, private, and secret keys as JSON objects.
    case jwk
}

public protocol JSONWebKeyImportable: JSONWebKey {
    /// Imports the key from the specified format.
    ///
    /// - Parameters:
    ///   - key: The key in the specified format.
    ///   - format: The format in which the key is supplied.
    /// - Throws: If the key cannot be imported in the specified format.
    init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol
}

public protocol JSONWebKeyExportable: JSONWebKey {
    /// Exports the key in the specified format.
    ///
    /// - Parameters:
    ///   - format: The format in which to export the key.
    /// - Returns: The key in the specified format.
    /// - Throws: If the key cannot be exported in the specified format.
    func exportKey(format: JSONWebKeyFormat) throws -> Data
}

extension JSONWebKeyExportable {
    var jwkRepresentation: Data {
        get throws {
            try JSONEncoder.encoder.encode(self)
        }
    }
}

public protocol JSONWebKeySymmetric: JSONWebKeyImportable, JSONWebKeyExportable, Hashable {
    /// Initializes key from the given symmetric key.
    init(_ key: SymmetricKey) throws
}

extension SymmetricKey {
    /// Initializes a symmetric key from the given JSON Web Key.
    ///
    /// - Parameter key: The JSON Web Key to initialize the symmetric key from.
    /// - Throws: If the key cannot be initialized from the JSON Web Key.
    public init(_ key: some JSONWebKeySymmetric) throws {
        guard let keyValue = key.keyValue else {
            throw CryptoKitError.incorrectKeySize
        }
        self = keyValue
    }
}

extension JSONWebKeySymmetric {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(.init(data: key.asContiguousBytes))
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
            try validate()
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .raw:
            // swiftformat:disable:next redundantSelf
            guard let data = self.keyValue?.data else {
                throw JSONWebKeyError.keyNotFound
            }
            return data
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.keyValue == rhs.keyValue
    }
    
    public func hash(into hasher: inout Hasher) {
        // swiftformat:disable:next redundantSelf
        hasher.combine(self.keyValue)
    }
}
