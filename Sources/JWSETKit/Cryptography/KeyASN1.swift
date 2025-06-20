//
//  KeyASN1.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 6/19/25.
//

import SwiftASN1

protocol DERKeyContainer {
    var algorithmIdentifier: RFC5480AlgorithmIdentifier { get }
}

extension DERKeyContainer {
    @inlinable
    func isSameAlgorithmGroup(_ other: RFC5480AlgorithmIdentifier) -> Bool {
        algorithmIdentifier.isSameGroup(other)
    }
}

extension SubjectPublicKeyInfo: DERKeyContainer {
    init(pkcs1: some RandomAccessCollection<UInt8>) {
        self.init(
            algorithmIdentifier: .rsaEncryption,
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
}

extension ASN1ObjectIdentifier {
    func isSameGroup(_ other: Self) -> Bool {
        oidComponents.starts(with: other.oidComponents.dropLast())
    }
}

extension RFC5480AlgorithmIdentifier {
    var keyType: JSONWebKeyType {
        get throws {
            if isSameGroup(.rsaEncryption) {
                return .rsa
            } else if isSameGroup(.ecdsaP256) {
                return .ellipticCurve
            } else if isSameGroup(.ed25519) {
                return .octetKeyPair
            } else if isSameGroup(.mldsa44) || isSameGroup(.mlkem512) {
                return .algorithmKeyPair
            } else {
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    var keyCurve: JSONWebKeyCurve? {
        switch (algorithm, parameters) {
        case (_, ASN1ObjectIdentifier.NamedCurves.secp256r1):
            return .p256
        case (_, ASN1ObjectIdentifier.NamedCurves.secp384r1):
            return .p384
        case (_, ASN1ObjectIdentifier.NamedCurves.secp521r1):
            return .p521
        case (.AlgorithmIdentifier.idEd25519, _):
            return .ed25519
        case (.AlgorithmIdentifier.idX25519, _):
            return .x25519
        default:
            return nil
        }
    }
    
    @inlinable
    func isSameGroup(_ other: Self) -> Bool {
        algorithm.oidComponents.starts(with: other.algorithm.oidComponents.dropLast())
    }
}

extension DERKeyContainer {
    var keyType: JSONWebKeyType {
        get throws {
            try algorithmIdentifier.keyType
        }
    }
    
    var keyCurve: JSONWebKeyCurve? {
        algorithmIdentifier.keyCurve
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

    var parameters: ASN1ObjectIdentifier?

    init(algorithm: ASN1ObjectIdentifier, parameters: ASN1ObjectIdentifier?) {
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

            let nodeParameters = try nodes.next().map { try ASN1ObjectIdentifier(derEncoded: $0) }

            return .init(algorithm: algorithmOID, parameters: nodeParameters)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            if let parameters = self.parameters {
                try coder.serialize(parameters)
            } else {
                try coder.serialize(ASN1Null())
            }
        }
    }
}

// MARK: Algorithm Identifier Statics

extension ASN1ObjectIdentifier.AlgorithmIdentifier {
    static let idX25519: ASN1ObjectIdentifier = [1, 3, 101, 110]
    static let idX448: ASN1ObjectIdentifier = [1, 3, 101, 111]
    static let idEd25519: ASN1ObjectIdentifier = [1, 3, 101, 112]
    static let idEd448: ASN1ObjectIdentifier = [1, 3, 101, 113]
    static let idMLDSA44: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 17]
    static let idMLDSA65: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 18]
    static let idMLDSA87: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 19]
    static let idMLKEM512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 1]
    static let idMLKEM768: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 2]
    static let idMLKEM1024: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 3]
}

extension RFC5480AlgorithmIdentifier {
    static let ecdsaP256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: ASN1ObjectIdentifier.NamedCurves.secp256r1
    )

    static let ecdsaP384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: ASN1ObjectIdentifier.NamedCurves.secp384r1
    )

    static let ecdsaP521 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: ASN1ObjectIdentifier.NamedCurves.secp521r1
    )
    
    static let ed25519 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEd25519,
        parameters: nil
    )
    
    static let rsaEncryption = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaEncryption,
        parameters: nil
    )
    
    static let mldsa44 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idMLDSA44,
        parameters: nil
    )
    
    static let mldsa65 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idMLDSA65,
        parameters: nil
    )
    
    static let mldsa87 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idMLDSA87,
        parameters: nil
    )
    
    static let mlkem512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idMLKEM512,
        parameters: nil
    )
    
    static let mlkem768 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idMLKEM768,
        parameters: nil
    )
    
    static let mlkem1024 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idMLKEM1024,
        parameters: nil
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

struct ModuleLatticePrivateKey: DERParseable, DERSerializable, Hashable, Sendable {
    var seed: ASN1OctetString
    var expandedKey: ASN1OctetString?
    
    init(seed: [UInt8], expandedKey: [UInt8]? = nil) throws {
        guard seed.count == 32 else {
            throw ASN1Error.invalidASN1Object(reason: "Seed must be exactly 32 bytes")
        }
        self.seed = .init(contentBytes: seed[...])
        self.expandedKey = expandedKey.map { .init(contentBytes: $0[...]) }
    }
    
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific):
            // seed [0] case
            let seed = try ASN1OctetString(derEncoded: node).bytes
            guard seed.count == 32 else {
                throw ASN1Error.invalidASN1Object(reason: "Seed must be exactly 32 bytes")
            }
            try self.init(seed: .init(seed))
            
        case ASN1Identifier.octetString:
            // expandedKey case - this still breaks the design
            throw ASN1Error.invalidASN1Object(reason: "Cannot represent expandedKey-only choice in this struct design")
            
        case ASN1Identifier.sequence:
            // both case
            guard case .constructed(let elementsSequence) = node.content else {
                throw ASN1Error.unexpectedFieldType(.sequence)
            }
            let elements = Array(elementsSequence)
            guard elements.count == 2 else {
                throw ASN1Error.invalidASN1Object(reason: "Both sequence must have exactly 2 elements")
            }
            
            let parsedSeed = try ASN1OctetString(derEncoded: elements[0]).bytes
            let parsedExpandedKey = try ASN1OctetString(derEncoded: elements[1]).bytes
            
            try self.init(seed: .init(parsedSeed), expandedKey: .init(parsedExpandedKey))
            
        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }
    
    func serialize(into coder: inout DER.Serializer) throws {
        if let expandedKey = expandedKey {
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

struct PKCS8PrivateKey: DERImplicitlyTaggable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var algorithm: RFC5480AlgorithmIdentifier

    var privateKey: any (DERSerializable & DERParseable)

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == 0 else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid version")
            }

            let encodedAlgorithm = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let privateKeyBytes = try ASN1OctetString(derEncoded: &nodes)

            // We ignore the attributes
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }
            
            switch try encodedAlgorithm.keyType {
            case .rsa:
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKeyBytes.bytes)
            case .ellipticCurve, .algorithmKeyPair:
                let privateKeyNode = try DER.parse(privateKeyBytes.bytes)
                let privateKey = try SEC1PrivateKey(derEncoded: privateKeyNode)
                if let innerAlgorithm = privateKey.algorithm, innerAlgorithm != encodedAlgorithm {
                    throw ASN1Error.invalidASN1Object(reason: "Mismatched algorithms")
                }
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            case .algorithmKeyPair:
                let privateKeyNode = try DER.parse(privateKeyBytes.bytes)
                let privateKey = try ModuleLatticePrivateKey(derEncoded: privateKeyNode)
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            default:
                throw ASN1Error.invalidASN1Object(reason: "Unsupported algorithm for PKCS#8 private key")
            }
        }
    }

    init(algorithm: RFC5480AlgorithmIdentifier, privateKey: any(DERSerializable & DERParseable)) throws {
        self.privateKey = privateKey
        self.algorithm = algorithm
    }

    init(algorithm: RFC5480AlgorithmIdentifier, privateKey: [UInt8], publicKey: [UInt8]) {
        self.algorithm = algorithm
        switch try? algorithm.keyType {
        case .ellipticCurve, .octetKeyPair:
            self.privateKey = SEC1PrivateKey(privateKey: privateKey, algorithm: algorithm, publicKey: publicKey)
        case .algorithmKeyPair:
            self.privateKey = (try? ModuleLatticePrivateKey(seed: privateKey, expandedKey: nil)) ?? ASN1OctetString(contentBytes: privateKey[...])
        default:
            self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        }
    }
    
    init(pkcs1: [UInt8]) throws {
        self.algorithm = .rsaEncryption
        self.privateKey = try ASN1Any(derEncoded: pkcs1[...])
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
