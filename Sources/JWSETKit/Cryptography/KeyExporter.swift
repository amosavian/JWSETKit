//
//  KeyExporter.swift
//
//
//  Created by Amir Abbas Mousavian on 2/10/24.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

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
    init(importing key: Data, format: JSONWebKeyFormat) throws
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

public protocol JSONWebKeySymmetricPortable: JSONWebKeyImportable, JSONWebKeyExportable {
    init(_ key: SymmetricKey) throws
}

extension JSONWebKeySymmetricPortable {
    public init(importing key: Data, format: JSONWebKeyFormat) throws {
        switch format {
        case .raw:
            try self.init(.init(data: key))
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: key)
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
            return try JSONEncoder().encode(self)
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

protocol DERKeyContainer {
    var algorithmIdentifier: RFC5480AlgorithmIdentifier { get }
}

extension SubjectPublicKeyInfo: DERKeyContainer {
    init(pkcs1: Data) {
        self.init(
            algorithmIdentifier: .init(algorithm: .AlgorithmIdentifier.rsaEncryption, parameters: nil),
            key: [UInt8](pkcs1)
        )
    }
}

extension SEC1PrivateKey: DERKeyContainer {
    var algorithmIdentifier: RFC5480AlgorithmIdentifier {
        algorithm ?? .init(algorithm: [], parameters: nil)
    }
}

extension PKCS8PrivateKey: DERKeyContainer {
    var algorithmIdentifier: RFC5480AlgorithmIdentifier {
        algorithm
    }
    
    init(pkcs1: Data) {
        self.init(
            algorithm: .init(algorithm: .AlgorithmIdentifier.rsaEncryption, parameters: nil),
            privateKey: [UInt8](pkcs1),
            publicKey: []
        )
        privateKey.publicKey = nil
    }
}

extension DERKeyContainer {
    var keyType: JSONWebKeyType {
        get throws {
            switch algorithmIdentifier.algorithm {
            case .AlgorithmIdentifier.idEcPublicKey:
                return .ellipticCurve
            case .AlgorithmIdentifier.rsaEncryption:
                return .rsa
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    
    var keyCurve: JSONWebKeyCurve? {
        switch algorithmIdentifier.parameters {
        case try? .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp256r1):
            return .p256
        case try? .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp384r1):
            return .p384
        case try? .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp521r1):
            return .p521
        default:
            return nil
        }
    }
}

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import SwiftASN1

struct SubjectPublicKeyInfo: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var algorithmIdentifier: RFC5480AlgorithmIdentifier

    var key: ASN1BitString

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        // The SPKI block looks like this:
        //
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //   algorithm         AlgorithmIdentifier,
        //   subjectPublicKey  BIT STRING
        // }
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let key = try ASN1BitString(derEncoded: &nodes)

            return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }

    private init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: ASN1BitString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }

    init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = ASN1BitString(bytes: key[...])
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.key)
        }
    }
}

struct RFC5480AlgorithmIdentifier: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var algorithm: ASN1ObjectIdentifier

    var parameters: ASN1Any?

    init(algorithm: ASN1ObjectIdentifier, parameters: ASN1Any?) {
        self.algorithm = algorithm
        self.parameters = parameters
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        // The AlgorithmIdentifier block looks like this.
        //
        // AlgorithmIdentifier  ::=  SEQUENCE  {
        //   algorithm   OBJECT IDENTIFIER,
        //   parameters  ANY DEFINED BY algorithm OPTIONAL
        // }
        //
        // ECParameters ::= CHOICE {
        //   namedCurve         OBJECT IDENTIFIER
        //   -- implicitCurve   NULL
        //   -- specifiedCurve  SpecifiedECDomain
        // }
        //
        // We don't bother with helpers: we just try to decode it directly.
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmOID = try ASN1ObjectIdentifier(derEncoded: &nodes)

            let parameters = nodes.next().map { ASN1Any(derEncoded: $0) }

            return .init(algorithm: algorithmOID, parameters: parameters)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            if let parameters = self.parameters {
                try coder.serialize(parameters)
            }
        }
    }
}

// MARK: Algorithm Identifier Statics

extension RFC5480AlgorithmIdentifier {
    static let ecdsaP256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp256r1)
    )

    static let ecdsaP384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp384r1)
    )

    static let ecdsaP521 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp521r1)
    )
}

struct SEC1PrivateKey: DERImplicitlyTaggable, PEMRepresentable {
    static let defaultPEMDiscriminator: String = "EC PRIVATE KEY"

    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var algorithm: RFC5480AlgorithmIdentifier?

    var privateKey: ASN1OctetString

    var publicKey: ASN1BitString?

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == 1 else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid version")
            }

            let privateKey = try ASN1OctetString(derEncoded: &nodes)
            let parameters = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try ASN1ObjectIdentifier(derEncoded: node)
            }
            let publicKey = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                try ASN1BitString(derEncoded: node)
            }

            return try .init(privateKey: privateKey, algorithm: parameters, publicKey: publicKey)
        }
    }

    private init(privateKey: ASN1OctetString, algorithm: ASN1ObjectIdentifier?, publicKey: ASN1BitString?) throws {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.algorithm = try algorithm.map { algorithmOID in
            switch algorithmOID {
            case ASN1ObjectIdentifier.NamedCurves.secp256r1:
                return .ecdsaP256
            case ASN1ObjectIdentifier.NamedCurves.secp384r1:
                return .ecdsaP384
            case ASN1ObjectIdentifier.NamedCurves.secp521r1:
                return .ecdsaP521
            default:
                throw ASN1Error.invalidASN1Object(reason: "Invalid algorithm ID")
            }
        }
    }

    init(privateKey: [UInt8], algorithm: RFC5480AlgorithmIdentifier?, publicKey: [UInt8]) {
        self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        self.algorithm = algorithm
        self.publicKey = ASN1BitString(bytes: publicKey[...])
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(1) // version
            try coder.serialize(self.privateKey)

            if let algorithm = self.algorithm {
                let oid: ASN1ObjectIdentifier
                switch algorithm {
                case .ecdsaP256:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp256r1
                case .ecdsaP384:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp384r1
                case .ecdsaP521:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp521r1
                default:
                    throw ASN1Error.invalidASN1Object(reason: "Unsupported algorithm")
                }

                try coder.serialize(oid, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }

            if let publicKey = self.publicKey {
                try coder.serialize(publicKey, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
        }
    }
}

struct PKCS8PrivateKey: DERImplicitlyTaggable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var algorithm: RFC5480AlgorithmIdentifier

    var privateKey: SEC1PrivateKey

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == 0 else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid version")
            }

            let algorithm = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let privateKeyBytes = try ASN1OctetString(derEncoded: &nodes)

            // We ignore the attributes
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }

            let sec1PrivateKeyNode = try DER.parse(privateKeyBytes.bytes)
            let sec1PrivateKey = try SEC1PrivateKey(derEncoded: sec1PrivateKeyNode)
            if let innerAlgorithm = sec1PrivateKey.algorithm, innerAlgorithm != algorithm {
                throw ASN1Error.invalidASN1Object(reason: "Mismatched algorithms")
            }

            return try .init(algorithm: algorithm, privateKey: sec1PrivateKey)
        }
    }

    private init(algorithm: RFC5480AlgorithmIdentifier, privateKey: SEC1PrivateKey) throws {
        self.privateKey = privateKey
        self.algorithm = algorithm
    }

    init(algorithm: RFC5480AlgorithmIdentifier, privateKey: [UInt8], publicKey: [UInt8]) {
        self.algorithm = algorithm

        // We nil out the private key here. I don't really know why we do this, but OpenSSL does, and it seems
        // safe enough to do: it certainly avoids the possibility of disagreeing on what it is!
        self.privateKey = SEC1PrivateKey(privateKey: privateKey, algorithm: nil, publicKey: publicKey)
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(0) // version
            try coder.serialize(self.algorithm)

            // Here's a weird one: we recursively serialize the private key, and then turn the bytes into an octet string.
            var subCoder = DER.Serializer()
            try subCoder.serialize(self.privateKey)
            let serializedKey = ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

            try coder.serialize(serializedKey)
        }
    }
}
