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
#if P256K
@testable import CryptoP256K
#endif

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
    func detectSymmetricAlgorithms() {
        #expect(JSONWebKeyHMAC<SHA384>().keyValue?.size == .bits384)
        #expect(JSONWebKeyHMAC<SHA256>().resolveAlgorithm(nil) == .hmacSHA256)
        #expect(JSONWebKeyHMAC<SHA384>().resolveAlgorithm(nil) == .hmacSHA384)
        #expect(JSONWebKeyHMAC<SHA512>().resolveAlgorithm(nil) == .hmacSHA512)
        #expect(SymmetricKey(size: .bits128).resolveAlgorithm(nil) == nil)
        #expect(SymmetricKey(size: .bits256).resolveAlgorithm(nil) == .hmacSHA256)
        #expect(SymmetricKey(size: .bits384).resolveAlgorithm(nil) == .hmacSHA384)
        #expect(SymmetricKey(size: .bits512).resolveAlgorithm(nil) == .hmacSHA512)
    }

    // MARK: AES-GCM materialized-key cache hazards (cache must never outlive its key material).

    @Test
    func aesGCMMutatingKeyMaterialInvalidatesCache() throws {
        let plaintext = Data("the quick brown fox".utf8)
        let alg = JSONWebContentEncryptionAlgorithm.aesEncryptionGCM256
        var key = try JSONWebKeyAESGCM(SymmetricKey(size: .bits256))
        // Warm the cache, then seal with the original key.
        let sealed = try key.seal(plaintext, iv: Data?.none, authenticating: Data?.none, using: alg)
        #expect(try key.open(sealed, authenticating: Data?.none, using: alg) == plaintext)

        // Reassign storage to unrelated key material — the cached key must NOT survive, else the old
        // key's ciphertext would still open (a security hazard).
        let other = try JSONWebKeyAESGCM(SymmetricKey(size: .bits256))
        key.storage = other.storage
        #expect(throws: (any Error).self) {
            try key.open(sealed, authenticating: Data?.none, using: alg)
        }
        // The mutated key now seals/opens under the new material.
        let resealed = try key.seal(plaintext, iv: Data?.none, authenticating: Data?.none, using: alg)
        #expect(try key.open(resealed, authenticating: Data?.none, using: alg) == plaintext)
    }

    @Test
    func aesGCMCopyThenMutateKeepsOriginalKey() throws {
        let plaintext = Data("the quick brown fox".utf8)
        let alg = JSONWebContentEncryptionAlgorithm.aesEncryptionGCM256
        let original = try JSONWebKeyAESGCM(SymmetricKey(size: .bits256))
        let sealed = try original.seal(plaintext, iv: Data?.none, authenticating: Data?.none, using: alg)

        // Mutating a copy must not corrupt the original's cached key (the cache box is replaced
        // wholesale in `storage.didSet`, not mutated in place).
        var copy = original
        copy.storage = try JSONWebKeyAESGCM(SymmetricKey(size: .bits256)).storage
        #expect(try original.open(sealed, authenticating: Data?.none, using: alg) == plaintext)
    }
}
