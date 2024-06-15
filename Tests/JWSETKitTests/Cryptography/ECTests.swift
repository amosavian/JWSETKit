//
//  ECTests.swift
//
//
//  Created by Amir Abbas Mousavian on 12/27/23.
//

import XCTest
import Crypto
@testable import JWSETKit

final class ECTests: XCTestCase {
    let plaintext = Data("The quick brown fox jumps over the lazy dog.".utf8)
    
    func testP256() throws {
        let key = P256.Signing.PrivateKey()
        
        XCTAssertNotNil(key.xCoordinate)
        XCTAssertNotNil(key.yCoordinate)
        XCTAssertNotNil(key.privateKey)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try key.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    func testP256Decode() throws {
        let signature = try ExampleKeys.privateEC256.signature(plaintext, using: .ecdsaSignatureP256SHA256)
        try ExampleKeys.publicEC256.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP256SHA256)
    }
    
    func testP384() throws {
        let key = P384.Signing.PrivateKey()
        
        XCTAssertNotNil(key.xCoordinate)
        XCTAssertNotNil(key.yCoordinate)
        XCTAssertNotNil(key.privateKey)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureP384SHA384)
        try key.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP384SHA384)
    }
    
    func testP384Decode() throws {
        let signature = try ExampleKeys.privateEC384.signature(plaintext, using: .ecdsaSignatureP384SHA384)
        try ExampleKeys.publicEC384.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP384SHA384)
    }
    
    func testP521() throws {
        let key = P521.Signing.PrivateKey()
        
        XCTAssertNotNil(key.xCoordinate)
        XCTAssertNotNil(key.yCoordinate)
        XCTAssertNotNil(key.privateKey)
        
        let signature = try key.signature(plaintext, using: .ecdsaSignatureP521SHA512)
        try key.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP521SHA512)
    }
    
    func testP521Decode() throws {
        let signature = try ExampleKeys.privateEC521.signature(plaintext, using: .ecdsaSignatureP521SHA512)
        try ExampleKeys.publicEC521.verifySignature(signature, for: plaintext, using: .ecdsaSignatureP521SHA512)
    }
    
    func testEdDSA() throws {
        let key = Curve25519.Signing.PrivateKey()
        
        XCTAssertNotNil(key.xCoordinate)
        XCTAssertNil(key.yCoordinate)
        XCTAssertNotNil(key.privateKey)
        
        let signature = try key.signature(plaintext, using: .eddsaSignature)
        try key.verifySignature(signature, for: plaintext, using: .eddsaSignature)
    }
    
    func testEdDSADecode() throws {
        let key = ExampleKeys.privateEd25519
        
        XCTAssertNotNil(key.keyId)
        XCTAssertNotNil(key.xCoordinate)
        XCTAssertNil(key.yCoordinate)
        XCTAssertNotNil(key.privateKey)
        
        let signature = try ExampleKeys.privateEd25519.signature(plaintext, using: .eddsaSignature)
        try ExampleKeys.publicEd25519.verifySignature(signature, for: plaintext, using: .eddsaSignature)
    }
}
