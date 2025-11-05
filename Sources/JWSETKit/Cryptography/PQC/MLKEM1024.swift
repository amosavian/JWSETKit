//
//  MLKEM1024.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/10/30.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if compiler(>=6.2) || !canImport(CryptoKit)
import Crypto

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension Crypto.MLKEM1024.PublicKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLKEM1024.PublicKey: JSONWebKeyAlgorithmKeyPairPublic, JSONWebKeyRawRepresentable, JSONWebKeyImportable, JSONWebKeyExportable, JSONWebKeyAlgorithmIdentified {
    public static let algorithm: any JSONWebAlgorithm = .mldsa65Signature
    
    public static let algorithmIdentifier: RFC5480AlgorithmIdentifier = .mlkem768
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension Crypto.MLKEM1024.PrivateKey: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLKEM1024.PrivateKey: JSONWebKeyAlgorithmKeyPairPrivate, JSONWebKeyImportable, JSONWebKeyExportable, JSONWebKeyAlgorithmIdentified {}

#endif
