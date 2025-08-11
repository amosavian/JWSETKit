//
//  MLDSATests.swift
//
//
//  Created by Amir Abbas Mousavian on 10/31/23.
//

import Foundation
import Testing
@testable import JWSETKit

#if canImport(Darwin) && compiler(>=6.2)
@Suite
#else
@Suite(.enabled(if: false))
#endif
struct MLDSATests {
    let mldsaSeed = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".decoded
    
    let mldsa65PrivateDER = """
    MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ\
    GhscHR4f
    """.decoded
    
    let mldsa87PrivateDER = """
    MDQCAQAwCwYJYIZIAWUDBAMTBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ\
    GhscHR4f
    """.decoded
    
    let mldsa87PrivateBothDER = """
    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\
    WWVn6UNk36ptnVpuuZrk3fQk    
    """.decoded
    
    let mldsa65PublicDER = """
    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\
    HgLy6ERP
    """.decoded
    
    let mldsa87PublicDER = """
    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\
    5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==
    """.decoded
    
    let plaintext = Data("The quick brown fox jumps over the lazy dog.".utf8)
    
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @Test
    func derImport() throws {
        #expect(throws: Never.self) { try JSONWebMLDSAPrivateKey(derRepresentation: mldsa65PrivateDER) }
        #expect(throws: Never.self) { try JSONWebMLDSAPublicKey(derRepresentation: mldsa65PublicDER) }
        #expect(throws: Never.self) { try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateDER) }
        #expect(throws: Never.self) { try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateBothDER) }
        #expect(throws: Never.self) { try JSONWebMLDSAPublicKey(derRepresentation: mldsa87PublicDER) }
        #expect(try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateDER).seed == mldsaSeed)
        #expect(try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateBothDER).seed == mldsaSeed)
    }
    
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @Test
    func derExport() throws {
        try print(JSONWebMLDSAPrivateKey(derRepresentation: mldsa65PrivateDER).exportKey(format: .pkcs8).base64EncodedString())
        #expect(try JSONWebMLDSAPublicKey(derRepresentation: mldsa65PublicDER).exportKey(format: .spki) == mldsa65PublicDER)
        #expect(try JSONWebMLDSAPublicKey(derRepresentation: mldsa87PublicDER).exportKey(format: .spki) == mldsa87PublicDER)
        #expect(try JSONWebMLDSAPrivateKey(derRepresentation: mldsa65PrivateDER).exportKey(format: .pkcs8) == mldsa65PrivateDER)
        #expect(try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateDER).exportKey(format: .pkcs8) == mldsa87PrivateDER)
        #expect(try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateBothDER).exportKey(format: .pkcs8) == mldsa87PrivateDER)
    }
    
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @Test
    func signing_MLDSA65_DER() throws {
        let publicKey = try JSONWebMLDSAPublicKey(derRepresentation: mldsa65PublicDER)
        let privateKey = try JSONWebMLDSAPrivateKey(derRepresentation: mldsa65PrivateDER)
        
        let signature = try privateKey.signature(plaintext, using: .mldsa65Signature)
        #expect(throws: Never.self) { try publicKey.verifySignature(signature, for: plaintext, using: .mldsa65Signature) }
        
        #expect(plaintext != signature)
    }
    
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @Test
    func signing_MLDSA87_DER() throws {
        let publicKey = try JSONWebMLDSAPublicKey(derRepresentation: mldsa87PublicDER)
        let privateKey = try JSONWebMLDSAPrivateKey(derRepresentation: mldsa87PrivateDER)
        
        let signature = try privateKey.signature(plaintext, using: .mldsa87Signature)
        #expect(throws: Never.self) { try publicKey.verifySignature(signature, for: plaintext, using: .mldsa87Signature) }
        
        #expect(plaintext != signature)
    }
}
