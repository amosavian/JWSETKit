//
//  P521.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

extension Crypto.P521.Signing.PublicKey: Swift.Hashable, Swift.Codable {}

extension P521.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p521 }
}

extension Crypto.P521.KeyAgreement.PublicKey: Swift.Hashable, Swift.Codable {}

extension P521.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p521 }
}

extension P521.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let ecdsaSignature: P521.Signing.ECDSASignature
        // swiftformat:disable:next redundantSelf
        if signature.count == (self.curve?.coordinateSize ?? 0) * 2 {
            ecdsaSignature = try .init(rawRepresentation: signature)
        } else {
            ecdsaSignature = try .init(derRepresentation: signature)
        }
        if !isValidSignature(ecdsaSignature, for: SHA512.hash(data: data)) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P521.Signing.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension P521.KeyAgreement.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension Crypto.P521.Signing.PrivateKey: Swift.Hashable, Swift.Codable {}

extension P521.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey {
    public typealias PublicKey = P521.Signing.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA512.hash(data: data)).rawRepresentation
    }
}

extension Crypto.P521.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Codable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension P521.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public typealias PublicKey = P521.KeyAgreement.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
}

extension P521.Signing.PrivateKey: CryptoECKeyPortable {}

extension P521.KeyAgreement.PrivateKey: CryptoECKeyPortable {}
