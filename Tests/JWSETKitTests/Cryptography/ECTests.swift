//
//  ECTests.swift
//
//
//  Created by Amir Abbas Mousavian on 12/27/23.
//

import Crypto
import Foundation
import Testing
@testable import CryptoP256K
@testable import JWSETKit

struct ECTests {
    let plaintext = Data("The quick brown fox jumps over the lazy dog.".utf8)
    
    @Test
    func p256() throws {
        let key = P256.Signing.PrivateKey()
        
        #expect(key.xCoordinate != nil)
        #expect(key.yCoordinate != nil)
        #expect(key.privateKey != nil)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try key.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    @Test
    func p256Decode() throws {
        let signature = try ExampleKeys.privateEC256.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try ExampleKeys.publicEC256.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    @Test
    func p384() throws {
        let key = P384.Signing.PrivateKey()
        
        #expect(key.xCoordinate != nil)
        #expect(key.yCoordinate != nil)
        #expect(key.privateKey != nil)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureP384SHA384)
        try key.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP384SHA384)
    }
    
    @Test
    func p384Decode() throws {
        let signature = try ExampleKeys.privateEC384.signature(plaintext, using: .ecdsaSignatureP384SHA384)
        try ExampleKeys.publicEC384.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP384SHA384)
    }
    
    @Test
    func p521() throws {
        let key = P521.Signing.PrivateKey()
        
        #expect(key.xCoordinate != nil)
        #expect(key.yCoordinate != nil)
        #expect(key.privateKey != nil)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureP521SHA512)
        try key.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP521SHA512)
    }
    
    @Test
    func p521Decode() throws {
        let signature = try ExampleKeys.privateEC521.signature(plaintext, using: .ecdsaSignatureP521SHA512)
        try ExampleKeys.publicEC521.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP521SHA512)
    }
    
    @Test
    func rawImportRoundTrip() throws {
        func roundTrip(_ priv: some CryptoECPrivateKey & CryptoECKeyPortable, expected curve: JSONWebKeyCurve) throws {
            let pub = try #require(priv.publicKey as? any CryptoECKeyPortable)
            let importedPub = try JSONWebECPublicKey(importing: pub.x963Representation, format: .raw)
            #expect(importedPub.curve == curve)
            let importedPriv = try JSONWebECPrivateKey(importing: priv.x963Representation, format: .raw)
            #expect(importedPriv.curve == curve)
        }
        try roundTrip(P256.Signing.PrivateKey(), expected: .p256)
        try roundTrip(P384.Signing.PrivateKey(), expected: .p384)
        try roundTrip(P521.Signing.PrivateKey(), expected: .p521)
    }
    
    @Test
    func eddsa() throws {
        let key = Curve25519.Signing.PrivateKey()
        
        #expect(key.xCoordinate != nil)
        #expect(key.yCoordinate == nil)
        #expect(key.privateKey != nil)
        
        let signature = try key.signature(plaintext, using: .eddsaSignature)
        try key.verifySignature(signature, for: plaintext, using: .eddsaSignature)
    }
    
    @Test
    func eddsaDecode() throws {
        let key = ExampleKeys.privateEd25519
        
        #expect(key.keyId != nil)
        #expect(key.xCoordinate != nil)
        #expect(key.yCoordinate == nil)
        #expect(key.privateKey != nil)
        
        let signature = try ExampleKeys.privateEd25519.signature(plaintext, using: .eddsaSignature)
        try ExampleKeys.publicEd25519.verifySignature(signature, for: plaintext, using: .eddsaSignature)
    }
    
    @Test
    func eddsaPublicDecodeSPKI() throws {
        let key = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=".decoded
        #expect(try JSONWebECPublicKey(importing: key, format: .spki).keyType == .octetKeyPair)
        #expect(throws: Never.self) {
            try Curve25519.Signing.PublicKey(importing: key, format: .spki)
        }
    }
    
    @Test
    func eddsaPrivateDecodePKCS8() throws {
        let key = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC".decoded
        #expect(try JSONWebECPrivateKey(importing: key, format: .pkcs8).keyType == .octetKeyPair)
        #expect(throws: Never.self) {
            try Curve25519.Signing.PrivateKey(importing: key, format: .pkcs8)
        }
        #expect(try Curve25519.Signing.PrivateKey(importing: key, format: .pkcs8).exportKey(format: .pkcs8) == key)
    }
    
    @Test
    func eddsaPrivateDecodePKCS8v2() throws {
        let key = """
        MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\
        oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\
        Z9w7lshQhqowtrbLDFw4rXAxZuE=
        """.decoded
        #expect(throws: Never.self) {
            try Curve25519.Signing.PrivateKey(importing: key, format: .pkcs8)
        }
    }
    
    // MARK: - Materialized-key cache (copy-on-write) hazards
    
    /// Signing repeatedly reuses the cached CryptoKit key and still produces verifiable signatures.
    @Test
    func cachedSigningKeyRoundTrips() throws {
        let key = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        for _ in 0 ..< 3 {
            let sig = try key.signature(plaintext, using: .ecdsaSignatureP256SHA256)
            try key.publicKey.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        }
    }
    
    /// Mutating a copy's storage must not corrupt the original's cached key: the original keeps
    /// signing with its own material, and the mutated copy signs with the new material.
    @Test
    func copyThenMutateKeepsOriginalKey() throws {
        let original = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        // Prime the original's cache.
        _ = try original.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        
        var copy = original
        copy.keyId = "rotated" // mutates copy.storage → copy detaches to a fresh cache box
        
        // Original still verifies against its own public key.
        let originalSig = try original.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try original.publicKey.verifySignature(originalSig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        
        // Copy shares the same key material (only kid changed), so its signature also verifies
        // against the same public key.
        let copySig = try copy.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try original.publicKey.verifySignature(copySig, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    /// Replacing a copy's private scalar with different material must invalidate the cache so the
    /// copy signs with the NEW key, while the original is unaffected.
    @Test
    func mutatingPrivateScalarInvalidatesCache() throws {
        let original = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        _ = try original.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        
        let other = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        var copy = original
        copy.storage = other.storage // overwrite copy with a different key entirely
        
        // Copy now signs with `other`'s key: verifies against other's public key, not original's.
        let sig = try copy.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try other.publicKey.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        #expect(throws: (any Error).self) {
            try original.publicKey.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        }
        
        // Original is untouched.
        let originalSig = try original.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try original.publicKey.verifySignature(originalSig, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    /// The public key caches its materialized validating key; reassigning storage to a different
    /// key must invalidate it, otherwise the old key's signature would still verify (security hazard).
    @Test
    func publicKeyMutatingCoordinatesInvalidatesCache() throws {
        let signer = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        let sig = try signer.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        
        var pub = signer.publicKey
        try pub.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256) // warm cache
        
        let other = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        pub.storage = other.publicKey.storage
        #expect(throws: (any Error).self) {
            try pub.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        }
        let otherSig = try other.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try pub.verifySignature(otherSig, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    /// Mutating a public key copy detaches it to a fresh cache box; the original keeps verifying.
    @Test
    func publicKeyCopyThenMutateKeepsOriginalKey() throws {
        let signer = try JSONWebECPrivateKey(algorithm: .ecdsaSignatureP256SHA256)
        let sig = try signer.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        
        let original = signer.publicKey
        try original.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        
        var copy = original
        copy.keyId = "rotated"
        try original.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
        try copy.verifySignature(sig, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
#if P256K
    @Test
    func secp256k1() throws {
        let key = P256K.Signing.PrivateKey()
        
        #expect(key.xCoordinate != nil)
        #expect(key.yCoordinate != nil)
        #expect(key.privateKey != nil)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureSecp256k1SHA256)
        try key.publicKey.verifySignature(signature, for: plaintext, using: .ecdsaSignatureSecp256k1SHA256)
    }
    
    @Test
    func secp256k1Decode() throws {
        let signature = try ExampleKeys.privateEC256K.signature(plaintext, using: .ecdsaSignatureSecp256k1SHA256)
        try ExampleKeys.publicEC256K.verifySignature(signature, for: plaintext, using: .ecdsaSignatureSecp256k1SHA256)
    }
    
    @Test
    func secp256k1PublicDecodeSPKI() throws {
        // Generate a fresh P256K key and export to SPKI
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let spki = publicKey.derRepresentation
        
        #expect(try JSONWebECPublicKey(importing: spki, format: .spki).keyType == .ellipticCurve)
        #expect(try JSONWebECPublicKey(importing: spki, format: .spki).curve == .secp256k1)
        #expect(throws: Never.self) {
            try P256K.Signing.PublicKey(importing: spki, format: .spki)
        }
    }
    
    @Test
    func secp256k1PrivateDecodePKCS8() throws {
        // Generate a fresh P256K key and export to PKCS8
        let privateKey = P256K.Signing.PrivateKey()
        let pkcs8 = privateKey.derRepresentation
        
        #expect(try JSONWebECPrivateKey(importing: pkcs8, format: .pkcs8).keyType == .ellipticCurve)
        #expect(try JSONWebECPrivateKey(importing: pkcs8, format: .pkcs8).curve == .secp256k1)
        #expect(throws: Never.self) {
            try P256K.Signing.PrivateKey(importing: pkcs8, format: .pkcs8)
        }
        #expect(try P256K.Signing.PrivateKey(importing: pkcs8, format: .pkcs8).exportKey(format: .pkcs8) == pkcs8)
    }
#endif
}
