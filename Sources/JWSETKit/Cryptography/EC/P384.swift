//
//  P384.swift
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

extension P384.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p384 }
}

extension P384.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
        if !isValidSignature(signature, for: SHA384.hash(data: data)) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P384.Signing.PublicKey: CryptoECPublicKeyPortable {}

extension P384.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey {
    public init(algorithm _: any JSONWebAlgorithm) throws {
        self.init(compactRepresentable: true)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA384.hash(data: data)).rawRepresentation
    }
}

extension P384.Signing.PrivateKey: CryptoECPrivateKeyPortable {}
