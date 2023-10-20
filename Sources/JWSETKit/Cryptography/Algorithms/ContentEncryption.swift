//
//  ContentEncryption.swift
//
//
//  Created by Amir Abbas Mousavian on 10/13/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// JSON Web Key Encryption Algorithms
public struct JSONWebContentEncryptionAlgorithm: JSONWebAlgorithm {
    public let rawValue: String
    
    public init<S>(_ rawValue: S) where S: StringProtocol {
        self.rawValue = String(rawValue)
    }
}

extension JSONWebContentEncryptionAlgorithm {
    private static var keyRegistryClasses: [Self: any JSONWebSealingKey.Type] = [
        .aesEncryptionGCM128: JSONWebKeyAESGCM.self,
        .aesEncryptionGCM192: JSONWebKeyAESGCM.self,
        .aesEncryptionGCM256: JSONWebKeyAESGCM.self,
        .aesEncryptionCBC128SHA256: JSONWebKeyAESCBCHMAC.self,
        .aesEncryptionCBC192SHA384: JSONWebKeyAESCBCHMAC.self,
        .aesEncryptionCBC256SHA512: JSONWebKeyAESCBCHMAC.self,
    ]
    
    private static var keyLengths: [Self: SymmetricKeySize] = [
        .aesEncryptionGCM128: .bits128,
        .aesEncryptionGCM192: .bits192,
        .aesEncryptionGCM256: .bits256,
        .aesEncryptionCBC128SHA256: .bits128,
        .aesEncryptionCBC192SHA384: .bits192,
        .aesEncryptionCBC256SHA512: .bits256,
    ]
    
    public var keyType: JSONWebKeyType? {
        .symmetric
    }
    
    public var keyClass: (any JSONWebSealingKey.Type)? {
        Self.keyRegistryClasses[self]
    }
    
    public var keyLength: SymmetricKeySize? {
        Self.keyLengths[self]
    }
    
    /// Registers a new symmeric key for JWE content encryption.
    ///
    /// - Parameters:
    ///   - algorithm: New algorithm name.
    ///   - keyClass: Key class of symmetric key.
    ///   - keyLength: The sizes that a symmetric cryptographic key can take.
    public static func register<KT>(
        _ algorithm: Self,
        keyClass: KT.Type,
        keyLength: SymmetricKeySize
    ) where KT: JSONWebSealingKey {
        keyRegistryClasses[algorithm] = keyClass
        keyLengths[algorithm] = keyLength
    }
}

extension JSONWebContentEncryptionAlgorithm {
    /// Generates new random key with minimum key length.
    ///
    /// - Returns: New random key.
    public func generateRandomKey() throws -> any JSONWebSealingKey {
        guard let keyClass = keyClass, let keyLength = keyLength else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try keyClass.init(SymmetricKey(size: keyLength))
    }
}

// Content Encryption
extension JSONWebAlgorithm where Self == JSONWebContentEncryptionAlgorithm {
    /// **Content Encryption**: AES GCM using 128-bit key.
    public static var aesEncryptionGCM128: Self { "A128GCM" }
    
    /// **Content Encryption**: AES GCM using 192-bit key.
    public static var aesEncryptionGCM192: Self { "A192GCM" }
    
    /// **Content Encryption**: AES GCM using 256-bit key.
    public static var aesEncryptionGCM256: Self { "A256GCM" }
    
    static func aesEncryptionGCM(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)GCM")
    }
    
    /// **Content Encryption**: `AES_128_CBC_HMAC_SHA_256` authenticated encryption algorithm.
    public static var aesEncryptionCBC128SHA256: Self { "A128CBC-HS256" }
    
    /// **Content Encryption**: `AES_192_CBC_HMAC_SHA_384` authenticated encryption algorithm.
    public static var aesEncryptionCBC192SHA384: Self { "A192CBC-HS384" }
    
    /// **Content Encryption**: `AES_256_CBC_HMAC_SHA_512` authenticated encryption algorithm.
    public static var aesEncryptionCBC256SHA512: Self { "A256CBC-HS512" }
    
    static func aesEncryptionCBCSHA(bitCount: Int) -> Self {
        .init(rawValue: "A\(bitCount)CBC-HS\(bitCount * 2)")
    }
}
