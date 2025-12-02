//
//  P256K.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/11/30.
//

#if P256K
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import LibSECP256k1
import SwiftASN1

extension P256K.Signing.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension P256K.Signing.PublicKey: CryptoECPublicKey, JSONWebKeyAlgorithmIdentified {
    public static var algorithm: any JSONWebAlgorithm { .ecdsaSignatureSecp256k1SHA256 }
    public static var algorithmIdentifier: RFC5480AlgorithmIdentifier { .ecdsaSecp256k1 }
    static var curve: JSONWebKeyCurve { .secp256k1 }
}

extension P256K.KeyAgreement.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension P256K.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .secp256k1 }
}

extension P256K.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let ecdsaSignature: P256K.Signing.ECDSASignature
        // swiftformat:disable:next redundantSelf
        if signature.count == (self.curve?.coordinateSize ?? 0) * 2 {
            ecdsaSignature = try .init(rawRepresentation: signature)
        } else {
            ecdsaSignature = try .init(derRepresentation: signature)
        }
        if !isValidSignature(ecdsaSignature, for: SHA256.hash(data: data)) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension P256K.Signing.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension P256K.KeyAgreement.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension P256K.Signing.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension P256K.Signing.PrivateKey: JSONWebSigningKey, JSONWebKeyAlgorithmIdentified, CryptoECPrivateKey {
    public typealias PublicKey = P256K.Signing.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        guard let hashFunction = algorithm.hashFunction else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try signature(for: hashFunction.hash(data: data)).rawRepresentation
    }
}

extension P256K.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension P256K.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public typealias PublicKey = P256K.KeyAgreement.PublicKey
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
}

extension P256K.Signing.PrivateKey: CryptoECKeyPortable {}

extension P256K.KeyAgreement.PrivateKey: CryptoECKeyPortable {}

#endif
