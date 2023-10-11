//
//  KeyGenerator.swift
//
//
//  Created by Amir Abbas Mousavian on 10/7/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import _CryptoExtras

extension JSONWebSignatureAlgorithm {
    public func generateRandomKey() throws -> any JSONWebSigningKey {
        switch self {
        case .hmacSHA256:
            return try JSONWebKeyHMAC<SHA256>()
        case .hmacSHA384:
            return try JSONWebKeyHMAC<SHA384>()
        case .hmacSHA512:
            return try JSONWebKeyHMAC<SHA512>()
        case .ecdsaSignatureP256SHA256:
            return P256.Signing.PrivateKey()
        case .ecdsaSignatureP384SHA384:
            return P384.Signing.PrivateKey()
        case .ecdsaSignatureP521SHA512:
            return P521.Signing.PrivateKey()
        case .rsaSignaturePKCS1v15SHA256, .rsaSignaturePSSSHA256,
             .rsaSignaturePKCS1v15SHA384, .rsaSignaturePSSSHA384,
             .rsaSignaturePKCS1v15SHA512, .rsaSignaturePSSSHA512:
            return try _RSA.Signing.PrivateKey(keySize: .bits2048)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    private func generateAESKW(keySize: SymmetricKeySize) throws -> any JSONWebDecryptingKey {
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return JSONWebKeyAESKW(keySize)
        } else {
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public func generateRandomKey() throws -> any JSONWebDecryptingKey {
        switch self {
        case .aesKeyWrap128:
            return try generateAESKW(keySize: .bits128)
        case .aesKeyWrap192:
            return try generateAESKW(keySize: .bits192)
        case .aesKeyWrap256:
            return try generateAESKW(keySize: .bits256)
        case .rsaEncryptionPKCS1, .rsaEncryptionOAEP, .rsaEncryptionOAEPSHA256,
             .rsaEncryptionOAEPSHA384, .rsaEncryptionOAEPSHA512:
            return try _RSA.Encryption.PrivateKey(keySize: .bits2048)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension JSONWebContentEncryptionAlgorithm {
    public func generateRandomKey() throws -> any JSONWebSealingKey {
        switch self {
        case .aesEncryptionGCM128:
            return JSONWebKeyAESGCM(.bits128)
        case .aesEncryptionGCM192:
            return JSONWebKeyAESGCM(.bits192)
        case .aesEncryptionGCM256:
            return JSONWebKeyAESGCM(.bits256)
        case .aesEncryptionCBC128SHA256:
            return JSONWebKeyAESCBCHMAC(.bits128)
        case .aesEncryptionCBC192SHA384:
            return JSONWebKeyAESCBCHMAC(.bits192)
        case .aesEncryptionCBC256SHA512:
            return JSONWebKeyAESCBCHMAC(.bits256)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}
