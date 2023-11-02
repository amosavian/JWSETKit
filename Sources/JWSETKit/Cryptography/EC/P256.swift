//
//  P256.swift
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

extension P256.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p256 }
}

extension P256.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        if !isValidSignature(signature, for: SHA256.hash(data: data)) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P256.Signing.PrivateKey: CryptoECPrivateKey {
    public init(algorithm _: any JSONWebAlgorithm) throws {
        self.init(compactRepresentable: true)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA256.hash(data: data)).rawRepresentation
    }
}

#if canImport(Darwin)
extension SecureEnclave.P256.Signing.PrivateKey: CryptoECPrivateKey {
    public var storage: JSONWebValueStorage {
        // Keys stored in SecureEnclave are not exportable.
        //
        // In order to get key type and other necessary information in signing
        // process, public key is returned which contains these values.
        publicKey.storage
    }
    
    var rawRepresentation: Data {
        fatalError("Private Keys in Secure Enclave are not encodable.")
    }
    
    public init(algorithm _: any JSONWebAlgorithm) throws {
        try self.init(compactRepresentable: true)
    }
    
    init(rawRepresentation _: Data) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA256.hash(data: data)).rawRepresentation
    }
}
#endif
