//
//  MLDSA65.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 7/16/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// TODO: Remove condition after release of swift-crypto 4.0
#if canImport(CryptoKit) && swift(>=6.2)
import Crypto

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension Crypto.MLDSA65.PublicKey: Swift.Hashable, Swift.Codable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65.PublicKey: JSONWebValidatingKey, JSONWebKeyRawRepresentable, JSONWebKeyImportable, JSONWebKeyExportable, CryptoModuleLatticePublicKey {
    public static let algorithm: any JSONWebAlgorithm = .mldsa65Signature
    
    public static let algorithmIdentifier: RFC5480AlgorithmIdentifier = .mldsa65
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension Crypto.MLDSA65.PrivateKey: Swift.Hashable, Swift.Codable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65.PrivateKey: JSONWebSigningKey, JSONWebKeyImportable, JSONWebKeyExportable, CryptoModuleLatticePrivateKey {}

#if canImport(Darwin) && swift(>=6.2)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension Crypto.SecureEnclave.MLDSA65.PrivateKey: Swift.Hashable, Swift.Codable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension SecureEnclave.MLDSA65.PrivateKey: JSONWebSigningKey {
    public var storage: JSONWebValueStorage {
        // Keys stored in SecureEnclave are not exportable.
        //
        // In order to get key type and other necessary information in signing
        // process, public key is returned which contains these values.
        publicKey.storage
    }
    
    public init(algorithm _: some JSONWebAlgorithm) throws {
        try self.init()
    }
    
    public init(storage _: JSONWebValueStorage) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
    
    public func signature<D>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signature(for: data)
    }
}
#endif
#endif
