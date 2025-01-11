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
import X509

/// JSON Web Key (JWK) container for X509 Certificate chain.
///
/// - Important: Only `x5c` is supported. Loading from `x5u` is not supported now.
public struct JSONWebCertificateChain: MutableJSONWebKey, JSONWebValidatingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    public var leaf: Certificate {
        get throws {
            try Certificate.create(storage: storage)
        }
    }
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebCertificateChain {
        .init(storage: storage)
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

extension Verifier {
    public mutating func validate(
        chain: JSONWebCertificateChain,
        diagnosticCallback: ((VerificationDiagnostic) -> Void)? = nil
    ) async -> VerificationResult {
        do {
            return try await validate(
                leafCertificate: chain.leaf,
                intermediates: .init(chain.certificateChain.dropFirst()),
                diagnosticCallback: diagnosticCallback
            )
        } catch {
            return .couldNotValidate([])
        }
    }
}
