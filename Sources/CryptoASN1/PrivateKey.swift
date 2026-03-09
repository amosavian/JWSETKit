//
//  PrivateKey.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 6/19/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1

extension SEC1PrivateKey: DERKeyContainer {
    package var algorithmIdentifier: RFC5480AlgorithmIdentifier {
        algorithm ?? .init(algorithm: [], parameters: nil)
    }
}

extension PKCS8PrivateKey: DERKeyContainer {
    package var algorithmIdentifier: RFC5480AlgorithmIdentifier {
        algorithm
    }
}

package struct RSAOAEPParams: DERImplicitlyTaggable, Hashable, Sendable {
    package static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    package var hashAlgorithm: RFC5480AlgorithmIdentifier?
    package var maskGenAlgorithm: RFC5480AlgorithmIdentifier?
    package var pSourceAlgorithm: RFC5480AlgorithmIdentifier?
    
    private init(hashAlgorithm: RFC5480AlgorithmIdentifier? = nil, maskGenAlgorithm: RFC5480AlgorithmIdentifier? = nil, pSourceAlgorithm: RFC5480AlgorithmIdentifier? = nil) {
        self.hashAlgorithm = hashAlgorithm
        self.maskGenAlgorithm = maskGenAlgorithm
        self.pSourceAlgorithm = pSourceAlgorithm
    }
    
    package init<H: HashFunction>(hashFunction: H.Type) throws {
        self.hashAlgorithm = try .digestIdentifier(hashFunction)
        self.maskGenAlgorithm = try .maskGenFunction1(hashFunction)
        self.pSourceAlgorithm = .init(algorithm: .AlgorithmIdentifier.pSpecified, parameters: ASN1OctetString(contentBytes: []))
    }
    
    package init(derEncoded rootNode: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let hashAlgorithm = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try RFC5480AlgorithmIdentifier(derEncoded: node)
            }
            let maskGenAlgorithm = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                node in
                try RFC5480AlgorithmIdentifier(derEncoded: node)
            }
            let pSourceAlgorithm = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                node in
                try RFC5480AlgorithmIdentifier(derEncoded: node)
            }
            
            return .init(hashAlgorithm: hashAlgorithm, maskGenAlgorithm: maskGenAlgorithm, pSourceAlgorithm: pSourceAlgorithm)
        }
    }
    
    package func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if let hash = hashAlgorithm {
                try coder.serialize(hash, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let mgf = maskGenAlgorithm {
                try coder.serialize(mgf, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
            if let pSourceAlgorithm {
                try coder.serialize(pSourceAlgorithm, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
            }
        }
    }
    
    package static func == (lhs: Self, rhs: Self) -> Bool {
        (lhs.hashAlgorithm ?? .sha1Identifier) == (rhs.hashAlgorithm ?? .sha1Identifier) &&
            (lhs.maskGenAlgorithm ?? .mgf1SHA1Identifier) == (rhs.maskGenAlgorithm ?? .mgf1SHA1Identifier)
    }
}

package struct RSASSAPSSParams: DERImplicitlyTaggable, Hashable, Sendable {
    package static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    package var hashAlgorithm: RFC5480AlgorithmIdentifier?
    package var maskGenAlgorithm: RFC5480AlgorithmIdentifier?
    package var saltLength: Int?
    package var trailerField: Int?
    
    private init(hashAlgorithm: RFC5480AlgorithmIdentifier? = nil, maskGenAlgorithm: RFC5480AlgorithmIdentifier? = nil, saltLength: Int? = nil, trailerField: Int? = nil) {
        self.hashAlgorithm = hashAlgorithm
        self.maskGenAlgorithm = maskGenAlgorithm
        self.saltLength = saltLength
        self.trailerField = trailerField
    }
    
    package init<H: HashFunction>(hashFunction: H.Type, trailerField: Int? = 1) throws {
        self.hashAlgorithm = try .digestIdentifier(hashFunction)
        self.maskGenAlgorithm = try .maskGenFunction1(hashFunction)
        self.saltLength = hashFunction.Digest.byteCount
        self.trailerField = trailerField
    }
    
    package init(derEncoded rootNode: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let hashAlgorithm = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try RFC5480AlgorithmIdentifier(derEncoded: node)
            }
            let maskGenAlgorithm = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                node in
                try RFC5480AlgorithmIdentifier(derEncoded: node)
            }
            let saltLength = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                node in
                try Int(derEncoded: node)
            }
            
            let trailerField = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) {
                node in
                try Int(derEncoded: node)
            }
            return .init(hashAlgorithm: hashAlgorithm, maskGenAlgorithm: maskGenAlgorithm, saltLength: saltLength, trailerField: trailerField)
        }
    }
    
    package func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if let hash = hashAlgorithm {
                try coder.serialize(hash, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let mgf = maskGenAlgorithm {
                try coder.serialize(mgf, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
            if let salt = saltLength {
                try coder.serialize(salt, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
            }
            if let trailer = trailerField {
                try coder.serialize(trailer, explicitlyTaggedWithTagNumber: 3, tagClass: .contextSpecific)
            }
        }
    }
    
    package static func == (lhs: Self, rhs: Self) -> Bool {
        (lhs.hashAlgorithm ?? .sha1Identifier) == (rhs.hashAlgorithm ?? .sha1Identifier) &&
            (lhs.maskGenAlgorithm ?? .mgf1SHA1Identifier) == (rhs.maskGenAlgorithm ?? .mgf1SHA1Identifier) &&
            (lhs.saltLength ?? 20) == (rhs.saltLength ?? 20) &&
            (lhs.trailerField ?? 1) == (rhs.trailerField ?? 1)
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

// MARK: Algorithm Identifier Statics

package struct SEC1PrivateKey: DERImplicitlyTaggable, PEMRepresentable {
    package static let defaultPEMDiscriminator: String = "EC PRIVATE KEY"

    package static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    package var algorithm: RFC5480AlgorithmIdentifier?

    package var privateKey: ASN1OctetString

    package var publicKey: ASN1BitString?

    package init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == 1 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            let encodedPrivateKey = try ASN1OctetString(derEncoded: &nodes)
            let parameters = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try ASN1ObjectIdentifier(derEncoded: node)
            }
            let encodedPublicKey = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                try ASN1BitString(derEncoded: node)
            }

            return try .init(privateKey: encodedPrivateKey, algorithm: parameters, publicKey: encodedPublicKey)
        }
    }

    private init(privateKey: ASN1OctetString, algorithm: ASN1ObjectIdentifier?, publicKey: ASN1BitString?) throws {
        self.privateKey = privateKey
        self.algorithm = .init(algorithm: .AlgorithmIdentifier.idEcPublicKey, parameters: algorithm)
        self.publicKey = publicKey
    }

    package init(privateKey: [UInt8], algorithm: RFC5480AlgorithmIdentifier?, publicKey: [UInt8]) {
        self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        self.algorithm = algorithm
        self.publicKey = !publicKey.isEmpty ? ASN1BitString(bytes: publicKey[...]) : nil
    }

    package func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(1) // version
            try coder.serialize(privateKey)
            
            if let algorithm, let curveOID = algorithm.parameters as? ASN1ObjectIdentifier {
                try coder.serialize(curveOID, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let publicKey {
                try coder.serialize(publicKey, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
        }
    }
}

package struct ModuleLatticePrivateKey: DERParseable, DERSerializable, Hashable, Sendable {
    package var seed: ASN1OctetString
    package var expandedKey: ASN1OctetString?
    
    package init(seed: [UInt8], expandedKey: [UInt8]? = nil) throws {
        guard seed.count == 32 else {
            throw CryptoKitASN1Error.unsupportedFieldLength
        }
        self.seed = .init(contentBytes: seed[...])
        self.expandedKey = expandedKey.map { .init(contentBytes: $0[...]) }
    }
    
    package init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case .init(tagWithNumber: 0, tagClass: .contextSpecific):
            // seed [0] case
            guard let seed = node.content.primitive else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }
            guard seed.count == 32 || seed.count == 64 else {
                throw CryptoKitASN1Error.unsupportedFieldLength
            }
            try self.init(seed: .init(seed))
            
        case .octetString:
            // expandedKey case - this still breaks the design
            throw CryptoKitASN1Error.unexpectedFieldType
            
        case .sequence:
            // both case
            guard case .constructed(let elementsSequence) = node.content else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }
            let elements = Array(elementsSequence)
            guard elements.count == 2 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }
            
            let parsedSeed = try ASN1OctetString(derEncoded: elements[0]).bytes
            let parsedExpandedKey = try ASN1OctetString(derEncoded: elements[1]).bytes
            
            try self.init(seed: .init(parsedSeed), expandedKey: .init(parsedExpandedKey))
            
        default:
            throw CryptoKitASN1Error.unexpectedFieldType
        }
    }
    
    package func serialize(into coder: inout DER.Serializer) throws {
        if let expandedKey {
            // Serialize as "both" sequence
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try seed.serialize(into: &coder)
                try expandedKey.serialize(into: &coder)
            }
        } else {
            // Serialize as seed [0] - context-specific tag 0
            coder.appendPrimitiveNode(identifier: ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) { bytes in
                bytes.append(contentsOf: seed.bytes)
            }
        }
    }
}

package struct PKCS8PrivateKey: DERImplicitlyTaggable {
    package static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    package var algorithm: RFC5480AlgorithmIdentifier

    package var privateKey: any (DERSerializable & DERParseable)

    package init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == 0 || version == 1 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            let encodedAlgorithm = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            guard let privateKey = nodes.next()?.content.primitive else {
                throw CryptoKitASN1Error.invalidASN1Object
            }
            
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in
                // We ignore the attributes
            }
            
            if version == 1 {
                // We ignore the public key
                while nodes.next() != nil {
                    // We don't care about the public key in this context
                }
            }
            
            if encodedAlgorithm.algorithm == .AlgorithmIdentifier.idEcPublicKey {
                let privateKey = try SEC1PrivateKey(derEncoded: privateKey)
                if let innerAlgorithm = privateKey.algorithm, innerAlgorithm != encodedAlgorithm {
                    throw CryptoKitASN1Error.invalidObjectIdentifier
                }
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            } else if [ASN1ObjectIdentifier].AlgorithmIdentifier.moduleLatticeAlgs.contains(encodedAlgorithm.algorithm) {
                let privateKey = try ModuleLatticePrivateKey(derEncoded: privateKey)
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            } else {
                // RSA and Edwards curve
                return try .init(algorithm: encodedAlgorithm, privateKey: ASN1OctetString(derEncoded: privateKey))
            }
        }
    }

    package init(algorithm: RFC5480AlgorithmIdentifier, privateKey: any(DERSerializable & DERParseable)) throws {
        self.privateKey = privateKey
        self.algorithm = algorithm
    }

    package init(algorithm: RFC5480AlgorithmIdentifier, privateKey: [UInt8], publicKey: [UInt8] = []) {
        self.algorithm = algorithm
        if algorithm.algorithm == .AlgorithmIdentifier.idEcPublicKey {
            self.privateKey = SEC1PrivateKey(privateKey: privateKey, algorithm: algorithm, publicKey: publicKey)
        } else if [ASN1ObjectIdentifier].AlgorithmIdentifier.moduleLatticeAlgs.contains(algorithm.algorithm) {
            self.privateKey = (try? ModuleLatticePrivateKey(seed: privateKey, expandedKey: nil)) ?? ASN1OctetString(contentBytes: privateKey[...])
        } else {
            // RSA and Edwards curve
            self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        }
    }
    
    package init(pkcs1: [UInt8]) throws {
        self.algorithm = .rsaEncryption
        self.privateKey = try ASN1Any(derEncoded: pkcs1[...])
    }

    package func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(0) // version
            try coder.serialize(algorithm)

            // Here's a weird one: we recursively serialize the private key, and then turn the bytes into an octet string.
            var subCoder = DER.Serializer()
            try subCoder.serialize(privateKey)
            let serializedKey = ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

            try coder.serialize(serializedKey)
        }
    }
}
