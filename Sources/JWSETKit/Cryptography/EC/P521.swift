//
//  P521.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

extension P521.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p521 }
}

extension P521.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        if !isValidSignature(signature, for: SHA512.hash(data: data)) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P521.Signing.PrivateKey: CryptoECPrivateKey {
    public init(algorithm _: any JSONWebAlgorithm) throws {
        self.init(compactRepresentable: true)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA512.hash(data: data)).rawRepresentation
    }
}
