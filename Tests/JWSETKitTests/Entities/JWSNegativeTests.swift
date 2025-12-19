//
//  JWSNegativeTests.swift
//
//
//  Created by Claude on 12/13/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

/// Tests for invalid JWS inputs and error handling
@Suite
struct JWSNegativeTests {
    // MARK: - Test Fixture
    
    /// Creates a basic JWS for testing that can be modified
    func createTestJWS() throws -> JSONWebToken {
        let claims = try JSONWebTokenClaims { $0.issuer = "test" }
        return try JSONWebToken(
            payload: claims,
            algorithm: .hmacSHA256,
            using: ExampleKeys.symmetric
        )
    }
    
    // MARK: - Invalid Base64 Tests
    
    @Test
    func invalidBase64InHeader() throws {
        // Header contains invalid base64url characters (!, @, #)
        let invalidJWS = "!!!invalid@@@.eyJpc3MiOiJqb2UifQ.signature"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    @Test
    func invalidBase64InPayload() throws {
        // Valid header, but payload has invalid base64url
        let header = "eyJhbGciOiJIUzI1NiJ9" // {"alg":"HS256"}
        let invalidJWS = "\(header).###invalid###.signature"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    @Test
    func invalidBase64InSignature() throws {
        // Valid header and payload, but signature has invalid base64url
        let header = "eyJhbGciOiJIUzI1NiJ9" // {"alg":"HS256"}
        let payload = "eyJpc3MiOiJqb2UifQ" // {"iss":"joe"}
        let invalidJWS = "\(header).\(payload).***invalid***"
        
        #expect(throws: DecodingError.self) {
            let jws = try JSONWebToken(from: invalidJWS)
            try jws.verifySignature(using: ExampleKeys.symmetric)
        }
    }
    
    // MARK: - Truncated/Malformed Structure Tests
    
    @Test
    func truncatedCompactOnlyOneSegment() throws {
        let invalidJWS = "eyJhbGciOiJIUzI1NiJ9"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    @Test
    func truncatedCompactOnlyTwoSegments() throws {
        let invalidJWS = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    @Test
    func emptyString() throws {
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: "")
        }
    }
    
    @Test
    func onlyDots() throws {
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: "..")
        }
    }
    
    @Test
    func extraSegments() throws {
        // JWS compact should have exactly 3 segments
        let header = "eyJhbGciOiJIUzI1NiJ9"
        let payload = "eyJpc3MiOiJqb2UifQ"
        let invalidJWS = "\(header).\(payload).sig.extra"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    // MARK: - Invalid JSON Tests
    
    @Test
    func invalidJSONInHeader() throws {
        // Base64 of "not json at all"
        let invalidHeader = Data("not json at all".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let invalidJWS = "\(invalidHeader).\(payload).sig"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    @Test
    func invalidJSONInPayload() throws {
        let header = "eyJhbGciOiJIUzI1NiJ9"
        // Base64 of "not json"
        let invalidPayload = Data("not json".utf8).urlBase64EncodedString()
        let invalidJWS = "\(header).\(invalidPayload).sig"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    @Test
    func headerIsJSONArray() throws {
        // Header should be an object, not an array
        let arrayHeader = Data("[\"alg\",\"HS256\"]".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let invalidJWS = "\(arrayHeader).\(payload).sig"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: invalidJWS)
        }
    }
    
    // MARK: - Algorithm Tests
    
    @Test
    func algorithmNoneWithNonEmptySignature() throws {
        // When alg is "none", signature should be empty
        let header = Data("{\"alg\":\"none\"}".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let jwsString = "\(header).\(payload).AAAAAA"
        
        #expect(throws: JSONWebKeyError.self) {
            let jws = try JSONWebToken(from: jwsString)
            try jws.verifySignature(using: ExampleKeys.publicRSA2048)
        }
    }
    
    @Test
    func unsupportedAlgorithm() throws {
        // Using a made-up algorithm
        let header = Data("{\"alg\":\"FAKE256\"}".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let jwsString = "\(header).\(payload).fakesig"
        
        let jws = try JSONWebToken(from: jwsString)
        #expect(throws: JSONWebKeyError.keyNotFound) {
            try jws.verifySignature(using: ExampleKeys.publicRSA2048)
        }
    }
    
    // MARK: - Wrong Key Type Tests
    
    @Test
    func rsaKeyWithECAlgorithm() throws {
        // Create a JWS with ES256 algorithm
        let header = Data("{\"alg\":\"ES256\"}".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let jwsString = "\(header).\(payload).fakesig"
        
        let jws = try JSONWebToken(from: jwsString)
        // Try to verify with RSA key - should fail
        #expect(throws: JSONWebKeyError.keyNotFound) {
            try jws.verifySignature(using: ExampleKeys.publicRSA2048)
        }
    }
    
    @Test
    func ecKeyWithRSAAlgorithm() throws {
        // Create a JWS with RS256 algorithm
        let header = Data("{\"alg\":\"RS256\"}".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let jwsString = "\(header).\(payload).fakesig"
        
        let jws = try JSONWebToken(from: jwsString)
        // Try to verify with EC key - should fail
        #expect(throws: JSONWebKeyError.keyNotFound) {
            try jws.verifySignature(using: ExampleKeys.publicEC256)
        }
    }
    
    @Test
    func symmetricKeyWithAsymmetricAlgorithm() throws {
        let header = Data("{\"alg\":\"RS256\"}".utf8).urlBase64EncodedString()
        let payload = "eyJpc3MiOiJqb2UifQ"
        let jwsString = "\(header).\(payload).fakesig"
        
        let jws = try JSONWebToken(from: jwsString)
        let symmetricKey = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        #expect(throws: JSONWebKeyError.keyNotFound) {
            try jws.verifySignature(using: symmetricKey)
        }
    }
    
    // MARK: - Signature Verification Failure Tests
    
    @Test
    func verifyWithWrongKey() throws {
        var jws = try createTestJWS()
        let key1 = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        try jws.updateSignature(using: key1)
        
        let differentKey = SymmetricKey(size: .bits256)
        let key2 = try JSONWebKeyHMAC<SHA256>(differentKey)
        #expect(throws: CryptoKitError.self) {
            try jws.verifySignature(using: key2)
        }
    }
    
    @Test
    func tamperedPayload() throws {
        var jws = try createTestJWS()
        jws.payload.value.issuer = "original"
        let key = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        try jws.updateSignature(using: key)
        jws.payload.value.issuer = "tampered"
        #expect(throws: CryptoKitError.self) {
            try jws.verifySignature(using: key)
        }
    }
    
    @Test
    func tamperedHeader() throws {
        // Create a valid JWS with HS256
        var jws = try createTestJWS()
        let key = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        try jws.updateSignature(using: key)
        jws.signatures[0].protected.algorithm = .hmacSHA384
        #expect(throws: CryptoKitError.self) {
            try jws.verifySignature(using: key)
        }
    }
    
    @Test
    func truncatedSignature() throws {
        // Create a valid compact JWS
        var jws = try createTestJWS()
        let key = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        try jws.updateSignature(using: key)
        
        // Get compact representation and truncate signature
        let compact = jws.description
        let parts = compact.split(separator: ".")
        let truncatedSig = String(parts[2].prefix(10))
        let tamperedJWS = "\(parts[0]).\(parts[1]).\(truncatedSig)"
        
        let parsedJWS = try JSONWebToken(from: tamperedJWS)
        #expect(throws: CryptoKitError.self) {
            try parsedJWS.verifySignature(using: key)
        }
    }
    
    // MARK: - Edge Cases
    
    @Test
    func emptyPayload() throws {
        // Empty JSON object as payload
        let header = "eyJhbGciOiJIUzI1NiJ9" // {"alg":"HS256"}
        let emptyPayload = Data("{}".utf8).urlBase64EncodedString()
        let jwsString = "\(header).\(emptyPayload).sig"
        let jws = try JSONWebToken(from: jwsString)
        #expect(jws.payload.storage.isEmpty)
    }
    
    @Test
    func nullBytesInPayload() throws {
        let header = "eyJhbGciOiJIUzI1NiJ9"
        var payloadData = Data("{\"iss\":\"test".utf8)
        payloadData.append(0x00) // null byte
        payloadData.append(contentsOf: "\"}".utf8)
        let payloadB64 = payloadData.urlBase64EncodedString()
        let jwsString = "\(header).\(payloadB64).sig"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: jwsString)
        }
    }
    
    @Test
    func newlinesInCompact() throws {
        let jwsWithNewlines = "eyJhbGciOiJIUzI1NiJ9\n.eyJpc3MiOiJqb2UifQ\n.sig"
        #expect(throws: DecodingError.self) {
            try JSONWebToken(from: jwsWithNewlines)
        }
    }
}
