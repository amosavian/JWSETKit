//
//  JSONWebCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 2/6/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
#if canImport(X509)
import X509
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

#if canImport(X509)
public typealias CertificateType = Certificate
#elseif canImport(CommonCrypto)
public typealias CertificateType = SecCertificate
#else
public typealias CertificateType = Data
#endif

#if canImport(X509) || canImport(CommonCrypto)
/// JSON Web Key (JWK) container for X509 Certificate chain.
///
/// - Important: Only `x5c` is supported. Loading from `x5u` is not supported now.
@frozen
public struct JSONWebCertificateChain: MutableJSONWebKey, JSONWebValidatingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public var leaf: CertificateType {
        get throws {
            try .init(from: self)
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard !self.certificateChain.isEmpty else {
            throw JSONWebKeyError.keyNotFound
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try leaf.verifySignature(signature, for: data, using: algorithm)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try leaf.thumbprint(format: format, using: hashFunction)
    }
}

extension JSONWebCertificateChain: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try leaf.verifyDate(currentDate)
    }
}
#endif

#if canImport(X509)
extension Verifier {
    public mutating func validate(
        chain: JSONWebCertificateChain,
        diagnosticCallback: ((VerificationDiagnostic) -> Void)? = nil
    ) async -> CertificateValidationResult {
        do {
            return try await validate(
                leaf: chain.leaf,
                intermediates: .init(chain.certificateChain.dropFirst()),
                diagnosticCallback: diagnosticCallback
            )
        } catch {
            return .couldNotValidate([])
        }
    }
}
#endif
