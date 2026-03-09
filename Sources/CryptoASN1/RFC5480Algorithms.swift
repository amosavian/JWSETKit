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
            if let parameters {
                try coder.serialize(parameters)
            } else if shouldEncodeNullParameters {
                try coder.serialize(ASN1Null())
            }
        }
    }
}

extension [ASN1ObjectIdentifier] {
    public enum AlgorithmIdentifier {
        public static let rsa: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.rsaEncryption,
            .AlgorithmIdentifier.rsaPSS,
            .AlgorithmIdentifier.sha256WithRSAEncryption,
            .AlgorithmIdentifier.sha384WithRSAEncryption,
            .AlgorithmIdentifier.sha512WithRSAEncryption,
        ]
        
        public static let edwardsCurveAlgs: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.idX25519,
            .AlgorithmIdentifier.idX448,
            .AlgorithmIdentifier.idEd25519,
            .AlgorithmIdentifier.idEd448,
        ]
        
        public static let moduleLatticeAlgs: [ASN1ObjectIdentifier] = moduleLatticeDSAs + moduleLatticeKEMs
        
        public static let moduleLatticeDSAs: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.mldsa44,
            .AlgorithmIdentifier.mldsa65,
            .AlgorithmIdentifier.mldsa87,
        ]
        
        public static let moduleLatticeKEMs: [ASN1ObjectIdentifier] = [
            .AlgorithmIdentifier.mlkem512,
            .AlgorithmIdentifier.mlkem768,
            .AlgorithmIdentifier.mlkem1024,
        ]
    }
}

extension ASN1ObjectIdentifier.AlgorithmIdentifier {
    public static let rsaOAEP: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 7]
    public static let mgf1: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 8]
    public static let pSpecified: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 9]
    public static let md5: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 2, 5]
    public static let idX25519: ASN1ObjectIdentifier = [1, 3, 101, 110]
    public static let idX448: ASN1ObjectIdentifier = [1, 3, 101, 111]
    public static let idEd25519: ASN1ObjectIdentifier = [1, 3, 101, 112]
    public static let idEd448: ASN1ObjectIdentifier = [1, 3, 101, 113]
    public static let sha1: ASN1ObjectIdentifier = [1, 3, 14, 3, 2, 26]
    public static let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    public static let sha384: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]
    public static let sha512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]
    public static let mldsa44: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 17]
    public static let mldsa65: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 18]
    public static let mldsa87: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 3, 19]
    public static let mlkem512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 1]
    public static let mlkem768: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 2]
    public static let mlkem1024: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 4, 3]
}

extension ASN1ObjectIdentifier.NamedCurves {
    /// Represents the secp256k1 curve.
    public static let secp256k1: ASN1ObjectIdentifier = [1, 3, 132, 0, 10]
}

extension RFC5480AlgorithmIdentifier {
    public static let sha1Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1,
        parameters: nil
    )
    
    public static let sha256Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256,
        parameters: nil
    )
    
    public static let sha384Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384,
        parameters: nil
    )
    
    public static let sha512Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512,
        parameters: nil
    )
    
    public static let mgf1SHA1Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: .sha1Identifier
    )
    
    public static let mgf1SHA256Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: sha256Identifier
    )
    
    public static let mgf1SHA384Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: .sha384Identifier
    )
    
    public static let mgf1SHA512Identifier = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: .sha512Identifier
    )
    
    public static func digestIdentifier<H: HashFunction>(_ hashFunction: H.Type) throws -> Self {
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
    
    public static func maskGenFunction1<H: HashFunction>(_ hashFunction: H.Type) throws -> Self {
        try .init(algorithm: .AlgorithmIdentifier.mgf1, parameters: .digestIdentifier(hashFunction))
    }
}

extension RFC5480AlgorithmIdentifier {
    public static let ecdsaP256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp256r1
    )
    
    public static let ecdsaSecp256k1 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: .NamedCurves.secp256k1
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
    
    public static let ed448 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEd448,
        parameters: nil
    )
    
    public static let x448 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idX448,
        parameters: nil
    )
    
    public static let rsaEncryption = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaEncryption,
        parameters: nil
    )
    
    public static let rsaEncryptionSHA256 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256WithRSAEncryption,
        parameters: nil
    )
    
    public static let rsaEncryptionSHA384 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384WithRSAEncryption,
        parameters: nil
    )
    
    public static let rsaEncryptionSHA512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512WithRSAEncryption,
        parameters: nil
    )
    
    public static func rsaEncryption<H>(_: (H.Type)? = nil) -> Self where H: HashFunction {
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
    
    public static let mldsa44 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mldsa44,
        parameters: nil
    )
    
    public static let mldsa65 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mldsa65,
        parameters: nil
    )
    
    public static let mldsa87 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mldsa87,
        parameters: nil
    )
    
    public static let mlkem512 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mlkem512,
        parameters: nil
    )
    
    public static let mlkem768 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mlkem768,
        parameters: nil
    )
    
    public static let mlkem1024 = RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mlkem1024,
        parameters: nil
    )
}

package protocol DERKeyContainer {
    var algorithmIdentifier: RFC5480AlgorithmIdentifier { get }
}
