//
//  P256.swift
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

extension Crypto.P256.Signing.PublicKey: Swift.Hashable, Swift.Codable {}

extension P256.Signing.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p256 }
}

extension Crypto.P256.KeyAgreement.PublicKey: Swift.Hashable, Swift.Codable {}

extension P256.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .p256 }
}

extension P256.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let ecdsaSignature: P256.Signing.ECDSASignature
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

extension P256.Signing.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension P256.KeyAgreement.PublicKey: CryptoECKeyPortableCompactRepresentable {}

extension Crypto.P256.Signing.PrivateKey: Swift.Hashable, Swift.Codable {}

extension P256.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey {
    public typealias PublicKey = P256.Signing.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA256.hash(data: data)).rawRepresentation
    }
}

extension Crypto.P256.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Codable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension P256.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public typealias PublicKey = P256.KeyAgreement.PublicKey
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init(compactRepresentable: false)
    }
}

extension P256.Signing.PrivateKey: CryptoECKeyPortable {}

extension P256.KeyAgreement.PrivateKey: CryptoECKeyPortable {}

#if canImport(Darwin)
extension Crypto.SecureEnclave.P256.Signing.PrivateKey: Swift.Hashable, Swift.Codable {}

extension SecureEnclave.P256.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey {
    public typealias PublicKey = P256.Signing.PublicKey
    
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
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(compactRepresentable: true)
    }
    
    init(rawRepresentation _: Data) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: SHA256.hash(data: data)).rawRepresentation
    }
}

extension Crypto.SecureEnclave.P256.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Codable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public typealias PublicKey = P256.KeyAgreement.PublicKey
    
    var rawRepresentation: Data {
        fatalError("Private Keys in Secure Enclave are not encodable.")
    }
    
    init(rawRepresentation _: Data) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
}
#endif
