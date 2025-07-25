//
//  RFC5480Algorithms.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 7/22/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1

public struct RFC5480AlgorithmIdentifier: DERImplicitlyTaggable, Hashable, Sendable {
    public typealias ParameterType = DERParseable & DERSerializable & Hashable & Sendable
    
    public static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    public let algorithm: ASN1ObjectIdentifier

    public let parameters: (any ParameterType)?

    public init(algorithm: ASN1ObjectIdentifier, parameters: (any ParameterType)? = nil) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    public init(algorithm: ASN1ObjectIdentifier, parameters: ASN1ObjectIdentifier) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    public init(algorithm: ASN1ObjectIdentifier, parameters: RFC5480AlgorithmIdentifier) {
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

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
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
    
    public static func == (lhs: RFC5480AlgorithmIdentifier, rhs: RFC5480AlgorithmIdentifier) -> Bool {
        (try? lhs.derRepresentation) == (try? rhs.derRepresentation)
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(algorithm)
        if let parameters = parameters as (any Hashable)? {
            hasher.combine(parameters)
        }
    }
    
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
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

extension RFC5480AlgorithmIdentifier {
    public var keyType: JSONWebKeyType {
        get throws {
            guard let result = AnyJSONWebAlgorithm(jsonWebAlgorithm)?.keyType else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            return result
        }
    }
    
    public var keyCurve: JSONWebKeyCurve? {
        jsonWebAlgorithm?.curve
    }
    
    private static let algorithms: PthreadReadWriteLockedValue<[Self: any JSONWebAlgorithm]> = [
        .rsaEncryption: .unsafeRSAEncryptionPKCS1,
        .rsaEncryptionSHA256: .rsaSignaturePKCS1v15SHA256,
        .rsaEncryptionSHA384: .rsaSignaturePKCS1v15SHA384,
        .rsaEncryptionSHA512: .rsaSignaturePKCS1v15SHA512,
        .rsaPSS(SHA256.self): .rsaSignaturePSSSHA256,
        .rsaPSS(SHA384.self): .rsaSignaturePSSSHA384,
        .rsaPSS(SHA512.self): .rsaSignaturePSSSHA512,
        .rsaOAEP(Insecure.SHA1.self): .rsaEncryptionOAEP,
        .rsaOAEP(SHA256.self): .rsaEncryptionOAEPSHA256,
        .rsaOAEP(SHA384.self): .rsaEncryptionOAEPSHA384,
        .rsaOAEP(SHA512.self): .rsaEncryptionOAEPSHA512,
        .ecdsaP256: .ecdsaSignatureP256SHA256,
        .ecdsaP384: .ecdsaSignatureP384SHA384,
        .ecdsaP521: .ecdsaSignatureP521SHA512,
        .ed25519: .eddsaSignature,
        .ed448: .eddsaSignature,
        .mldsa44: .mldsa44Signature,
        .mldsa65: .mldsa65Signature,
        .mldsa87: .mldsa87Signature,
    ]
    
    public var jsonWebAlgorithm: (any JSONWebAlgorithm)? {
        Self.algorithms[self]
    }
    
    /// Registers a new symmetric key for JWE content encryption.
    ///
    /// - Parameters:
    ///   - algorithm: New algorithm name.
    ///   - keyClass: Key class of symmetric key.
    ///   - keyLength: The sizes that a symmetric cryptographic key can take.
    public static func register(
        _ algorithm: Self,
        jsonWebAlgorithm: some JSONWebAlgorithm
    ) {
        Self.algorithms[algorithm] = jsonWebAlgorithm
    }
    
    init?(_ jsonWebAlgorithm: any JSONWebAlgorithm) {
        if let value = Self.algorithms.first(where: { $1 == jsonWebAlgorithm }) {
            self = value.key
        }
        return nil
    }
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
    public static let ecdsaP256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp256r1
    )

    public static let ecdsaP384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp384r1
    )

    public static let ecdsaP521 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp521r1
    )
    
    public static let ed25519 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEd25519,
        parameters: nil
    )
    
    public static let x25519 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idX25519,
        parameters: nil
    )
    
    static let ed448 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEd448,
        parameters: nil
    )
    
    static let x448 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idX448,
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
    
    public static func rsaEncryption<H>(_ hashFunction: (H.Type)? = nil) -> Self where H: HashFunction {
        switch H.self {
        case is SHA256.Type:
            rsaEncryptionSHA256
        case is SHA384.Type:
            rsaEncryptionSHA384
        case is SHA512.Type:
            rsaEncryptionSHA512
        default:
            rsaEncryption
        }
    }
    
    public static func rsaOAEP<H>(_ hashFunction: (H.Type)? = nil) -> Self where H: HashFunction {
        RFC5480AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.rsaOAEP,
            parameters: RFC5480AlgorithmIdentifier(
                algorithm: .AlgorithmIdentifier.pSpecified,
                parameters: hashFunction.flatMap { try? RSAOAEPParams(hashFunction: $0) }
            )
        )
    }
    
    public static func rsaPSS<H>(_ hashFunction: (H.Type)? = nil) -> Self where H: HashFunction {
        RFC5480AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.rsaPSS,
            parameters: hashFunction.flatMap { try? RSASSAPSSParams(hashFunction: $0) }
        )
    }
    
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
