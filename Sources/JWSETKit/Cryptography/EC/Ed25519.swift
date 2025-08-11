//
//  Ed25519.swift
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
import SwiftASN1

extension Crypto.Curve25519.Signing.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension Curve25519.Signing.PublicKey: CryptoECPublicKey, JSONWebKeyAlgorithmIdentified {
    static var curve: JSONWebKeyCurve { .ed25519 }
    public static var algorithm: any JSONWebAlgorithm { .eddsaSignature }
    public static var algorithmIdentifier: RFC5480AlgorithmIdentifier { .ed25519 }
    
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .octetKeyPair // Ed25519 is OKP per RFC8037
        result.curve = Self.curve
        result.xCoordinate = rawRepresentation
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, !x.isEmpty else {
            throw CryptoKitError.incorrectKeySize
        }
        try self.init(rawRepresentation: x)
    }
}

extension Crypto.Curve25519.KeyAgreement.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension Curve25519.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .x25519 }
    
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        result.keyType = .octetKeyPair // X25519 is OKP per RFC8037
        result.curve = Self.curve
        result.xCoordinate = rawRepresentation
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, !x.isEmpty else {
            throw CryptoKitError.incorrectKeySize
        }
        try self.init(rawRepresentation: x)
    }
}

extension Curve25519.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        if !isValidSignature(signature, for: data) {
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension Curve25519.Signing.PublicKey: CryptoEdKeyPortable {}

extension Curve25519.KeyAgreement.PublicKey: CryptoEdKeyPortable {
    public static var algorithm: any JSONWebAlgorithm { .ecdhEphemeralStatic }
    public static var algorithmIdentifier: RFC5480AlgorithmIdentifier { .x25519 }
}

extension Crypto.Curve25519.Signing.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension Curve25519.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey, CryptoEdKeyPortable {
    public typealias PublicKey = Curve25519.Signing.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init()
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: data)
    }
}

extension Crypto.Curve25519.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension Curve25519.KeyAgreement.PrivateKey: CryptoECPrivateKey, CryptoEdKeyPortable {
    public typealias PublicKey = Curve25519.KeyAgreement.PublicKey
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        self.init()
    }
}

protocol CryptoEdKeyPortable: JSONWebKeyAlgorithmIdentified, JSONWebKeyImportable, JSONWebKeyExportable {
    var rawRepresentation: Data { get }
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
}

extension CryptoEdKeyPortable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(rawRepresentation: Data(key))
        case .spki where Self.self is (any CryptoECPublicKey.Type):
            let spki = try SubjectPublicKeyInfo(derEncoded: key)
            guard spki.algorithmIdentifier == Self.algorithmIdentifier else {
                throw CryptoKitASN1Error.invalidObjectIdentifier
            }
            guard spki.key.bytes.count == spki.algorithmIdentifier.jsonWebAlgorithm?.curve?.coordinateSize else {
                throw CryptoKitError.incorrectKeySize
            }
            self = try .init(rawRepresentation: Data(spki.key.bytes))
        case .pkcs8 where Self.self is (any CryptoECPrivateKey.Type):
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            guard pkcs8.algorithmIdentifier == Self.algorithmIdentifier,
                  let privateKey = (pkcs8.privateKey as? ASN1OctetString)?.bytes
            else {
                throw JSONWebKeyError.invalidKeyFormat
            }
            guard privateKey.count == pkcs8.algorithmIdentifier.jsonWebAlgorithm?.curve?.coordinateSize else {
                throw CryptoKitError.incorrectKeySize
            }
            self = try .init(rawRepresentation: Data(privateKey))
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .raw:
            return rawRepresentation
        case .spki where self is (any CryptoECPublicKey):
            return try SubjectPublicKeyInfo(
                algorithmIdentifier: Self.algorithmIdentifier,
                key: [UInt8](rawRepresentation)
            ).derRepresentation
        case .pkcs8 where self is (any CryptoECPrivateKey):
            return try PKCS8PrivateKey(
                algorithm: Self.algorithmIdentifier,
                privateKey: [UInt8](rawRepresentation)
            ).derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}
