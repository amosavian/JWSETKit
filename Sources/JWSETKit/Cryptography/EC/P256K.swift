//
//  P256K.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(P256K)
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import P256K

extension P256K.Signing.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension P256K.Signing.PublicKey: CryptoECPublicKey, JSONWebKeyAlgorithmIdentified {
    public static var algorithm: any JSONWebAlgorithm { .ecdsaSignatureSecp256k1SHA256 }
    
    public static var algorithmIdentifier: RFC5480AlgorithmIdentifier { .ecdsaSecp256k1 }
    
    static var curve: JSONWebKeyCurve { .secp256k1 }
    
    public var rawRepresentation: Data {
        dataRepresentation
    }
    
    public init(rawRepresentation: Data) throws {
        try self.init(dataRepresentation: rawRepresentation, format: .uncompressed)
    }
}

extension P256K.KeyAgreement.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

extension P256K.KeyAgreement.PublicKey: CryptoECPublicKey {
    static var curve: JSONWebKeyCurve { .secp256k1 }
    
    public var rawRepresentation: Data {
        dataRepresentation
    }
    
    public init(rawRepresentation: Data) throws {
        try self.init(dataRepresentation: rawRepresentation, format: .uncompressed)
    }
}

extension P256K.Signing.PublicKey: JSONWebValidatingKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let ecdsaSignature: P256K.Signing.ECDSASignature
        // swiftformat:disable:next redundantSelf
        if signature.count == (self.curve?.coordinateSize ?? 0) * 2 {
            ecdsaSignature = try .init(dataRepresentation: signature)
        } else {
            ecdsaSignature = try .init(derRepresentation: signature)
        }
        if !isValidSignature(ecdsaSignature, for: SHA256.hash(data: data)) {
            throw Crypto.CryptoKitError.authenticationFailure
        }
    }
}

extension P256K.Signing.PublicKey: CryptoECKeyPortableCompactRepresentable {
    var x963Representation: Data {
        uncompressedRepresentation
    }
    
    var derRepresentation: Data {
        let der = SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaSecp256k1, key: [UInt8](x963Representation))
        return (try? der.derRepresentation) ?? .init()
    }
    
    init<Bytes>(compressedRepresentation: Bytes) throws where Bytes: ContiguousBytes {
        try self.init(dataRepresentation: compressedRepresentation, format: .compressed)
    }
}

extension P256K.Signing.PrivateKey: Swift.Hashable, Swift.Decodable, Swift.Encodable {}

extension P256K.Signing.PrivateKey: JSONWebSigningKey, CryptoECPrivateKey, JSONWebKeyAlgorithmIdentified {
    public typealias PublicKey = P256K.Signing.PublicKey
    
    static var curve: JSONWebKeyCurve { .secp256k1 }
    
    public var rawRepresentation: Data {
        dataRepresentation
    }
    
    public init(rawRepresentation: Data) throws {
        try self.init(dataRepresentation: rawRepresentation, format: .uncompressed)
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(format: .uncompressed)
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        let signature = try signature(for: data)
        return signature.dataRepresentation
    }
}

extension P256K.KeyAgreement.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

extension P256K.KeyAgreement.PrivateKey: CryptoECPrivateKey {
    public typealias PublicKey = P256K.KeyAgreement.PublicKey
    
    public init(rawRepresentation: Data) throws {
        try self.init(dataRepresentation: rawRepresentation, format: .uncompressed)
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init(format: .uncompressed)
    }
}

extension P256K.Signing.PrivateKey: CryptoECKeyPortable {
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes {
        try self.init(dataRepresentation: x963Representation.data.suffix(32))
    }
    
    var x963Representation: Data {
        publicKey.x963Representation + dataRepresentation
    }
    
    var derRepresentation: Data {
        (try? PKCS8PrivateKey(algorithm: .ecdsaSecp256k1, privateKey: [UInt8](dataRepresentation)).derRepresentation) ?? .init()
    }
}
#endif
