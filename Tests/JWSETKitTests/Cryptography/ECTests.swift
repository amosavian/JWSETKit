//
//  ECTests.swift
//
//
//  Created by Amir Abbas Mousavian on 12/27/23.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite
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
