//
//  P384.swift
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

extension Crypto.P384.Signing.PublicKey: Swift.Hashable, Swift.Codable {}

extension P384.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p384 }
}

extension Crypto.P384.KeyAgreement.PublicKey: Swift.Hashable, Swift.Codable {}

extension P384.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p384 }
}

extension P384.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let ecdsaSignature: P384.Signing.ECDSASignature
        // swiftformat:disable:next redundantSelf
        if signature.count == (self.curve?.coordinateSize ?? 0) * 2 {
            ecdsaSignature = try .init(rawRepresentation: signature)
        } else {
            ecdsaSignature = try .init(derRepresentation: signature)
        }
        if !isValidSignature(ecdsaSignature, for: SHA384.hash(data: data)) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P384.Signing.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension P384.KeyAgreement.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension Crypto.P384.Signing.PrivateKey: Swift.Hashable, Swift.Codable {}

extension P384.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey {
    public typealias PublicKey = P384.Signing.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA384.hash(data: data)).rawRepresentation
    }
}

extension Crypto.P384.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Codable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension P384.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public typealias PublicKey = P384.KeyAgreement.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
}

extension P384.Signing.PrivateKey: CryptoECKeyPortable {}

extension P384.KeyAgreement.PrivateKey: CryptoECKeyPortable {}
