//
//  AlgorithmsTests.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/12/18.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite
struct AlgorithmsTests {
    @Test
    func detectECAlgorithms() throws {
        #expect(try JSONWebECPrivateKey(curve: .p256).resolveAlgorithm(nil) == .ecdsaSignatureP256SHA256)
        #expect(P256.Signing.PrivateKey().resolveAlgorithm(nil) == .ecdsaSignatureP256SHA256)
        #expect(try JSONWebECPrivateKey(curve: .p384).resolveAlgorithm(nil) == .ecdsaSignatureP384SHA384)
        #expect(P384.Signing.PrivateKey().resolveAlgorithm(nil) == .ecdsaSignatureP384SHA384)
        #expect(try JSONWebECPrivateKey(curve: .p521).resolveAlgorithm(nil) == .ecdsaSignatureP521SHA512)
        #expect(P521.Signing.PrivateKey().resolveAlgorithm(nil) == .ecdsaSignatureP521SHA512)
        #expect(try JSONWebECPrivateKey(curve: .ed25519).resolveAlgorithm(nil) == .eddsaSignature)
        #expect(Curve25519.Signing.PrivateKey().resolveAlgorithm(nil) == .eddsaSignature)
#if P256K
        #expect(try JSONWebECPrivateKey(curve: .secp256k1).resolveAlgorithm(nil) == .ecdsaSignatureSecp256k1SHA256)
        #expect(P256K.Signing.PrivateKey().resolveAlgorithm(nil) == .ecdsaSignatureSecp256k1SHA256)
#endif
    }
    
    @Test
    func detectRSAAlgorithms() throws {
        #expect(try JSONWebRSAPrivateKey(keySize: .bits2048).resolveAlgorithm(nil) == .rsaSignaturePSSSHA256)
        var key = try JSONWebRSAPrivateKey(keySize: .bits2048)
        key.algorithm = .rsaSignaturePKCS1v15SHA256
        #expect(key.resolveAlgorithm(nil) == .rsaSignaturePKCS1v15SHA256)
    }
    
#if compiler(>=6.2) || !canImport(CryptoKit)
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    @Test
    func detectMLDSAAlgorithms() throws {
        #expect(try JSONWebMLDSAPrivateKey(algorithm: .mldsa65Signature).resolveAlgorithm(nil) == .mldsa65Signature)
        #expect(try MLDSA65.PrivateKey().resolveAlgorithm(nil) == .mldsa65Signature)
        #expect(try JSONWebMLDSAPrivateKey(algorithm: .mldsa87Signature).resolveAlgorithm(nil) == .mldsa87Signature)
        #expect(try MLDSA87.PrivateKey().resolveAlgorithm(nil) == .mldsa87Signature)
    }
#endif
    
    
    @Test
    func detectSymmetricAlgorithms() throws {
        #expect(JSONWebKeyHMAC<SHA384>().keyValue?.size == .bits384)
        #expect(JSONWebKeyHMAC<SHA256>().resolveAlgorithm(nil) == .hmacSHA256)
        #expect(JSONWebKeyHMAC<SHA384>().resolveAlgorithm(nil) == .hmacSHA384)
        #expect(JSONWebKeyHMAC<SHA512>().resolveAlgorithm(nil) == .hmacSHA512)
        #expect(SymmetricKey(size: .bits128).resolveAlgorithm(nil) == nil)
        #expect(SymmetricKey(size: .bits256).resolveAlgorithm(nil) == .hmacSHA256)
        #expect(SymmetricKey(size: .bits384).resolveAlgorithm(nil) == .hmacSHA384)
        #expect(SymmetricKey(size: .bits512).resolveAlgorithm(nil) == .hmacSHA512)
    }
}
