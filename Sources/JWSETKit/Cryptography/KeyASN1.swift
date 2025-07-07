//
//  KeyASN1.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 6/19/25.
//

import Crypto
import SwiftASN1

protocol DERKeyContainer {
    var algorithmIdentifier: RFC5480AlgorithmIdentifier { get }
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

extension RFC5480AlgorithmIdentifier {
    var keyType: JSONWebKeyType {
        get throws {
            if [ASN1ObjectIdentifier].AlgorithmIdentifier.rsa.contains(algorithm) {
                return .rsa
            } else if algorithm == .AlgorithmIdentifier.idEcPublicKey {
                return .ellipticCurve
            } else if [ASN1ObjectIdentifier].AlgorithmIdentifier.edwardsCurveAlgs.contains(algorithm) {
                return .octetKeyPair
            } else if [ASN1ObjectIdentifier].AlgorithmIdentifier.moduleLatticeAlgs.contains(algorithm) {
                return .algorithmKeyPair
            } else {
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    var keyCurve: JSONWebKeyCurve? {
        switch (algorithm, parameters as? ASN1ObjectIdentifier) {
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
    
    private static let algorithms: [Self: any JSONWebAlgorithm] = [
        .rsaEncryption: .unsafeRSAEncryptionPKCS1,
        .rsaEncryptionSHA256: .rsaSignaturePKCS1v15SHA256,
        .rsaEncryptionSHA384: .rsaSignaturePKCS1v15SHA384,
        .rsaEncryptionSHA512: .rsaSignaturePKCS1v15SHA512,
        .rsaPSSSHA256: .rsaSignaturePSSSHA256,
        .rsaPSSSHA384: .rsaSignaturePSSSHA384,
        .rsaPSSSHA512: .rsaSignaturePSSSHA512,
        .rsaOAEP: .rsaEncryptionOAEP,
        .rsaOAEPSHA256: .rsaEncryptionOAEPSHA256,
        .rsaOAEPSHA384: .rsaEncryptionOAEPSHA384,
        .rsaOAEPSHA512: .rsaEncryptionOAEPSHA512,
        .ecdsaP256: .ecdsaSignatureP256SHA256,
        .ecdsaP384: .ecdsaSignatureP384SHA384,
        .ecdsaP521: .ecdsaSignatureP521SHA512,
        .ed25519: .eddsaSignature,
        .mldsa65: .mldsa65Signature,
        .mldsa87: .mldsa87Signature,
    ]
    
    var jsonWebAlgorithm: (any JSONWebAlgorithm)? {
        Self.algorithms[self]
    }
    
    init?(_ jsonWebAlgorithm: any JSONWebAlgorithm) {
        if let value = Self.algorithms.first(where: { $1 == jsonWebAlgorithm }) {
            self = value.key
        }
        return nil
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
            try coder.serialize(algorithmIdentifier)
            try coder.serialize(key)
        }
    }
}

extension Equatable {
    /// Compare this value to another existential Equatable.
    func isEqual(to other: (any Equatable)?) -> Bool {
        guard let other = other as? Self else { return false }
        return self == other
    }
}

struct RFC5480AlgorithmIdentifier: DERImplicitlyTaggable, Hashable, Sendable {
    typealias ParameterType = DERParseable & DERSerializable & Hashable & Sendable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var algorithm: ASN1ObjectIdentifier

    var parameters: (any ParameterType)?

    init(algorithm: ASN1ObjectIdentifier, parameters: (any ParameterType)? = nil) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    init(algorithm: ASN1ObjectIdentifier, parameters: ASN1ObjectIdentifier) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    init(algorithm: ASN1ObjectIdentifier, parameters: RFC5480AlgorithmIdentifier) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    init(algorithm: ASN1ObjectIdentifier, parameters: RSAOAEPParams) {
        self.algorithm = algorithm
        self.parameters = parameters
    }

    init(algorithm: ASN1ObjectIdentifier, parameters: RSASSAPSSParams) {
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

            let nodeParameters: (any ParameterType)? = try nodes.next().flatMap {
                switch algorithmOID {
                case .AlgorithmIdentifier.idEcPublicKey:
                    try ASN1ObjectIdentifier(derEncoded: $0)
                case .AlgorithmIdentifier.rsaPSS:
                    try RSASSAPSSParams(derEncoded: $0)
                case .AlgorithmIdentifier.rsaOAEP:
                    try RSAOAEPParams(derEncoded: $0)
                default:
                    ASN1ObjectIdentifier?.none
                }
            }

            return .init(algorithm: algorithmOID, parameters: nodeParameters)
        }
    }

    private var shouldEncodeNullParameters: Bool {
        // For RSA algorithms the parameters MUST be present and MUST be NULL.
        // cited in PKCS #1 Appendix (as cited in RFC 5280).
        //
        // For Ed25519 - regarding RFC 8410 - the parameters field is forbidden
        // and it MUST be absent.
        //
        // For MLDSA, in the example keys in X509 format the parameters field
        // is absent.
        [ASN1ObjectIdentifier].AlgorithmIdentifier.rsa.contains(algorithm)
    }
    
    static func == (lhs: RFC5480AlgorithmIdentifier, rhs: RFC5480AlgorithmIdentifier) -> Bool {
        lhs.algorithm == rhs.algorithm && ((lhs.parameters?.isEqual(to: rhs.parameters)) ?? true)
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(algorithm)
        if let parameters = parameters as (any Hashable)? {
            hasher.combine(parameters)
        }
    }
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(algorithm)
            if let parameters = parameters {
                try coder.serialize(parameters)
            } else if shouldEncodeNullParameters {
                try coder.serialize(ASN1Null())
            }
        }
    }
}

// MARK: Algorithm Identifier Statics

extension [ASN1ObjectIdentifier] {
    enum AlgorithmIdentifier {
        static let rsa: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.rsaEncryption,
            .AlgorithmIdentifier.rsaPSS,
            .AlgorithmIdentifier.sha256WithRSAEncryption,
            .AlgorithmIdentifier.sha384WithRSAEncryption,
            .AlgorithmIdentifier.sha512WithRSAEncryption,
        ]
        
        static let edwardsCurveAlgs: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.idX25519,
            .AlgorithmIdentifier.idX448,
            .AlgorithmIdentifier.idEd25519,
            .AlgorithmIdentifier.idEd448,
        ]
        
        static let moduleLatticeAlgs: [ASN1ObjectIdentifier] = moduleLatticeDSAs + moduleLatticeKEMs
        
        static let moduleLatticeDSAs: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.mldsa44,
            .AlgorithmIdentifier.mldsa65,
            .AlgorithmIdentifier.mldsa87,
        ]
        
        static let moduleLatticeKEMs: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.mlkem512,
            .AlgorithmIdentifier.mlkem768,
            .AlgorithmIdentifier.mlkem1024,
        ]
    }
}

extension ASN1ObjectIdentifier.AlgorithmIdentifier {
    static let rsaOAEP: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 7]
    static let mgf1: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 8]
    static let pSpecified: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 9]
    static let md5: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 2, 5]
    static let idX25519: ASN1ObjectIdentifier = [1, 3, 101, 110]
    static let idX448: ASN1ObjectIdentifier = [1, 3, 101, 111]
    static let idEd25519: ASN1ObjectIdentifier = [1, 3, 101, 112]
    static let idEd448: ASN1ObjectIdentifier = [1, 3, 101, 113]
    static let sha1: ASN1ObjectIdentifier = [1, 3, 14, 3, 2, 26]
    static let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let sha384: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]
    static let sha512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]
    static let mldsa44: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 17]
    static let mldsa65: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 18]
    static let mldsa87: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 19]
    static let mlkem512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 1]
    static let mlkem768: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 2]
    static let mlkem1024: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 3]
}

extension RFC5480AlgorithmIdentifier {
    static let sha1Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1,
        parameters: nil
    )
    
    static let sha256Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256,
        parameters: nil
    )
    
    static let sha384Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384,
        parameters: nil
    )
    
    static let sha512Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512,
        parameters: nil
    )
    
    static let mgf1SHA1Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: .sha1Identifier
    )
    
    static let mgf1SHA256Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: sha256Identifier
    )
    
    static let mgf1SHA384Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: .sha384Identifier
    )
    
    static let mgf1SHA512Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: .sha512Identifier
    )
    
    static func digestIdentifier<H: HashFunction>(_ hashFunction: H.Type) throws -> Self {
        switch hashFunction {
        case is Insecure.SHA1.Type:
            .sha1Identifier
        case is SHA256.Type:
            sha256Identifier
        case is SHA384.Type:
            .sha384Identifier
        case is SHA512.Type:
            .sha512Identifier
        default:
            throw CryptoKitASN1Error.invalidObjectIdentifier
        }
    }
    
    static func maskGenFunction1<H: HashFunction>(_ hashFunction: H.Type) throws -> Self {
        try .init(algorithm: .AlgorithmIdentifier.mgf1, parameters: .digestIdentifier(hashFunction))
    }
}

extension RFC5480AlgorithmIdentifier {
    static let ecdsaP256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp256r1
    )

    static let ecdsaP384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp384r1
    )

    static let ecdsaP521 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp521r1
    )
    
    static let ed25519 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEd25519,
        parameters: nil
    )
    
    static let x25519 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idX25519,
        parameters: nil
    )
    
    static let rsaEncryption = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaEncryption,
        parameters: nil
    )
    
    static let rsaEncryptionSHA256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256WithRSAEncryption,
        parameters: nil
    )
    
    static let rsaEncryptionSHA384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384WithRSAEncryption,
        parameters: nil
    )
    
    static let rsaEncryptionSHA512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512WithRSAEncryption,
        parameters: nil
    )
    
    static let rsaOAEP = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaOAEP,
        parameters: RFC5480AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.pSpecified,
            parameters: (try? RSAOAEPParams(hashFunction: Insecure.SHA1.self)).unsafelyUnwrapped
        )
    )
    
    static let rsaOAEPSHA256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaOAEP,
        parameters: RFC5480AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.pSpecified,
            parameters: (try? RSAOAEPParams(hashFunction: SHA256.self)).unsafelyUnwrapped
        )
    )
    
    static let rsaOAEPSHA384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaOAEP,
        parameters: RFC5480AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.pSpecified,
            parameters: (try? RSAOAEPParams(hashFunction: SHA384.self)).unsafelyUnwrapped
        )
    )
    
    static let rsaOAEPSHA512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaOAEP,
        parameters: RFC5480AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.pSpecified,
            parameters: (try? RSAOAEPParams(hashFunction: SHA512.self)).unsafelyUnwrapped
        )
    )
    static let rsaPSSSHA1 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaPSS,
        parameters: (try? RSASSAPSSParams(hashFunction: Insecure.SHA1.self)).unsafelyUnwrapped
    )
    
    static let rsaPSSSHA256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaPSS,
        parameters: (try? RSASSAPSSParams(hashFunction: SHA256.self)).unsafelyUnwrapped
    )
    
    static let rsaPSSSHA384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaPSS,
        parameters: (try? RSASSAPSSParams(hashFunction: SHA384.self)).unsafelyUnwrapped
    )
    
    static let rsaPSSSHA512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaPSS,
        parameters: (try? RSASSAPSSParams(hashFunction: SHA512.self)).unsafelyUnwrapped
    )
    
    static let mldsa44 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mldsa44,
        parameters: nil
    )
    
    static let mldsa65 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mldsa65,
        parameters: nil
    )
    
    static let mldsa87 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mldsa87,
        parameters: nil
    )
    
    static let mlkem512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mlkem512,
        parameters: nil
    )
    
    static let mlkem768 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mlkem768,
        parameters: nil
    )
    
    static let mlkem1024 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mlkem1024,
        parameters: nil
    )
}

struct RSAOAEPParams: DERImplicitlyTaggable, Hashable, Sendable {
    static var defaultIdentifier: ASN1Identifier { .sequence }
    
    var hashAlgorithm: RFC5480AlgorithmIdentifier?
    var maskGenAlgorithm: RFC5480AlgorithmIdentifier?
    var pSourceAlgorithm: RFC5480AlgorithmIdentifier?
    
    private init(hashAlgorithm: RFC5480AlgorithmIdentifier? = nil, maskGenAlgorithm: RFC5480AlgorithmIdentifier? = nil, pSourceAlgorithm: RFC5480AlgorithmIdentifier? = nil) {
        self.hashAlgorithm = hashAlgorithm
        self.maskGenAlgorithm = maskGenAlgorithm
        self.pSourceAlgorithm = pSourceAlgorithm
    }
    
    init<H: HashFunction>(hashFunction: H.Type) throws {
        self.hashAlgorithm = try .digestIdentifier(hashFunction)
        self.maskGenAlgorithm = try .maskGenFunction1(hashFunction)
        self.pSourceAlgorithm = .init(algorithm: .AlgorithmIdentifier.pSpecified, parameters: ASN1OctetString(contentBytes: []))
    }
    
    init(derEncoded rootNode: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
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
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if let hash = hashAlgorithm {
                try coder.serialize(hash, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let mgf = maskGenAlgorithm {
                try coder.serialize(mgf, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
            if let pSourceAlgorithm = pSourceAlgorithm {
                try coder.serialize(pSourceAlgorithm, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
            }
        }
    }
    
    static func == (lhs: Self, rhs: Self) -> Bool {
        (lhs.hashAlgorithm ?? .sha1Identifier) == (rhs.hashAlgorithm ?? .sha1Identifier) &&
            (lhs.maskGenAlgorithm ?? .mgf1SHA1Identifier) == (rhs.maskGenAlgorithm ?? .mgf1SHA1Identifier)
    }
}

struct RSASSAPSSParams: DERImplicitlyTaggable, Hashable, Sendable {
    static var defaultIdentifier: ASN1Identifier { .sequence }
    
    var hashAlgorithm: RFC5480AlgorithmIdentifier?
    var maskGenAlgorithm: RFC5480AlgorithmIdentifier?
    var saltLength: Int?
    var trailerField: Int?
    
    private init(hashAlgorithm: RFC5480AlgorithmIdentifier? = nil, maskGenAlgorithm: RFC5480AlgorithmIdentifier? = nil, saltLength: Int? = nil, trailerField: Int? = nil) {
        self.hashAlgorithm = hashAlgorithm
        self.maskGenAlgorithm = maskGenAlgorithm
        self.saltLength = saltLength
        self.trailerField = trailerField
    }
    
    init<H: HashFunction>(hashFunction: H.Type, trailerField: Int? = 1) throws {
        self.hashAlgorithm = try .digestIdentifier(hashFunction)
        self.maskGenAlgorithm = try .maskGenFunction1(hashFunction)
        self.saltLength = hashFunction.Digest.byteCount
        self.trailerField = trailerField
    }
    
    init(derEncoded rootNode: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
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
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
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
    
    static func == (lhs: Self, rhs: Self) -> Bool {
        (lhs.hashAlgorithm ?? .sha1Identifier) == (rhs.hashAlgorithm ?? .sha1Identifier) &&
            (lhs.maskGenAlgorithm ?? .mgf1SHA1Identifier) == (rhs.maskGenAlgorithm ?? .mgf1SHA1Identifier) &&
            (lhs.saltLength ?? 20) == (rhs.saltLength ?? 20) &&
            (lhs.trailerField ?? 1) == (rhs.trailerField ?? 1)
    }
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
                throw CryptoKitASN1Error.invalidObjectIdentifier
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
            try coder.serialize(privateKey)

            if let algorithm = algorithm {
                let oid: ASN1ObjectIdentifier
                switch algorithm {
                case .ecdsaP256:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp256r1
                case .ecdsaP384:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp384r1
                case .ecdsaP521:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp521r1
                default:
                    throw CryptoKitASN1Error.invalidASN1Object
                }

                try coder.serialize(oid, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }

            if let publicKey = publicKey {
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
            throw CryptoKitASN1Error.unsupportedFieldLength
        }
        self.seed = .init(contentBytes: seed[...])
        self.expandedKey = expandedKey.map { .init(contentBytes: $0[...]) }
    }
    
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific):
            // seed [0] case
            guard let seed = node.content.primitive else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }
            guard seed.count == 32 || seed.count == 64 else {
                throw CryptoKitASN1Error.unsupportedFieldLength
            }
            try self.init(seed: .init(seed))
            
        case ASN1Identifier.octetString:
            // expandedKey case - this still breaks the design
            throw CryptoKitASN1Error.unexpectedFieldType
            
        case ASN1Identifier.sequence:
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
            guard version == 0 || version == 1 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            let encodedAlgorithm = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let privateKeyBytes = try ASN1OctetString(derEncoded: &nodes)
            
            // We ignore the attributes
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }
            
            if version == 1 {
                // We ignore the public key
                while nodes.next() != nil {
                    // We don't care about the public key in this context
                }
            }
            
            switch try encodedAlgorithm.keyType {
            case .rsa:
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKeyBytes.bytes)
            case .ellipticCurve:
                let privateKeyNode = try DER.parse(privateKeyBytes.bytes)
                let privateKey = try SEC1PrivateKey(derEncoded: privateKeyNode)
                if let innerAlgorithm = privateKey.algorithm, innerAlgorithm != encodedAlgorithm {
                    throw CryptoKitASN1Error.invalidObjectIdentifier
                }
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            case .octetKeyPair:
                let privateKeyNode = try DER.parse(privateKeyBytes.bytes)
                let privateKey = try ASN1OctetString(derEncoded: privateKeyNode.encodedBytes)
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            case .algorithmKeyPair:
                let privateKeyNode = try DER.parse(privateKeyBytes.bytes)
                let privateKey = try ModuleLatticePrivateKey(derEncoded: privateKeyNode)
                return try .init(algorithm: encodedAlgorithm, privateKey: privateKey)
            default:
                throw CryptoKitASN1Error.invalidASN1Object
            }
        }
    }

    init(algorithm: RFC5480AlgorithmIdentifier, privateKey: any(DERSerializable & DERParseable)) throws {
        self.privateKey = privateKey
        self.algorithm = algorithm
    }

    init(algorithm: RFC5480AlgorithmIdentifier, privateKey: [UInt8], publicKey: [UInt8] = []) {
        self.algorithm = algorithm
        switch try? algorithm.keyType {
        case .ellipticCurve:
            self.privateKey = SEC1PrivateKey(privateKey: privateKey, algorithm: algorithm, publicKey: publicKey)
        case .octetKeyPair:
            self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
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
            try coder.serialize(algorithm)

            // Here's a weird one: we recursively serialize the private key, and then turn the bytes into an octet string.
            var subCoder = DER.Serializer()
            try subCoder.serialize(privateKey)
            let serializedKey = ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

            try coder.serialize(serializedKey)
        }
    }
}
