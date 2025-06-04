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
}
