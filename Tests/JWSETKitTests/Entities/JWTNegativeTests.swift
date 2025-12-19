//
//  JWTNegativeTests.swift
//
//
//  Created by Claude on 12/13/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

/// Tests for invalid JWT claims and validation errors
@Suite
struct JWTNegativeTests {
    // MARK: - Test Helper
    
    /// Creates a test JWT with given claims configuration
    func createTestJWT(configure: (inout JSONWebTokenClaims) -> Void) throws -> JSONWebToken {
        var claims = try JSONWebTokenClaims { _ in }
        configure(&claims)
        
        return try JSONWebToken(
            payload: claims,
            algorithm: .hmacSHA256,
            using: ExampleKeys.symmetric
        )
    }
    
    // MARK: - Expiration Tests
    
    @Test
    func expiredToken() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Set expiration to 1 hour ago
            claims.expiry = Date().addingTimeInterval(-3600)
        }
        
        // Verify signature succeeds
        #expect(throws: Never.self) {
            try jwt.verifySignature(using: ExampleKeys.symmetric)
        }
        
        // But date validation should fail
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
    }
    
    @Test
    func tokenExpiredByOneSecond() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Set expiration to 1 second ago
            claims.expiry = Date().addingTimeInterval(-1)
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
    }
    
    @Test
    func tokenExpiredLongAgo() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Set expiration to year 2000
            claims.expiry = Date(timeIntervalSince1970: 946_684_800)
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
    }
    
    // MARK: - Not Before Tests
    
    @Test
    func notYetValidToken() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Set not-before to 1 hour in the future
            claims.notBefore = Date().addingTimeInterval(3600)
            // Set expiration to 2 hours in the future
            claims.expiry = Date().addingTimeInterval(7200)
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
    }
    
    @Test
    func notYetValidByOneSecond() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Set not-before to 1 second in the future
            claims.notBefore = Date().addingTimeInterval(1)
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
    }
    
    // MARK: - Issuer Validation Tests
    
    @Test
    func issuerMismatch() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "actual-issuer"
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        // Issuer should not match
        #expect(jwt.payload.value.issuer != "expected-issuer")
        #expect(jwt.payload.value.issuer == "actual-issuer")
    }
    
    @Test
    func emptyIssuer() throws {
        let jwt = try createTestJWT { claims in
            // Don't set issuer
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        #expect(jwt.payload.value.issuer == nil)
    }
    
    @Test
    func issuerCaseSensitivity() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "MyIssuer"
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        // Issuers are case-sensitive
        #expect(jwt.payload.value.issuer != "myissuer")
        #expect(jwt.payload.value.issuer != "MYISSUER")
        #expect(jwt.payload.value.issuer == "MyIssuer")
    }
    
    // MARK: - Audience Validation Tests
    
    @Test
    func invalidAudience() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            claims.audience = ["app1", "app2"]
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyAudience(includes: "app3")
        }
    }
    
    @Test
    func emptyAudienceWhenExpected() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Don't set audience
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyAudience(includes: "expected-audience")
        }
    }
    
    @Test
    func audienceCaseSensitivity() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            claims.audience = ["MyApp"]
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        // Should fail - audience is case-sensitive
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyAudience(includes: "myapp")
        }
    }
    
    // MARK: - Combined Validation Tests
    
    @Test
    func expiredAndWrongIssuer() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "wrong-issuer"
            claims.expiry = Date().addingTimeInterval(-3600) // expired
        }
        
        // Both should fail
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
        #expect(jwt.payload.value.issuer != "correct-issuer")
    }
    
    @Test
    func validDateButWrongAudience() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            claims.audience = ["app1"]
            claims.expiry = Date().addingTimeInterval(3600)
            claims.notBefore = Date().addingTimeInterval(-60)
        }
        
        // Date should pass
        #expect(throws: Never.self) {
            try jwt.verifyDate()
        }
        
        // Audience should fail
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyAudience(includes: "app2")
        }
    }
    
    // MARK: - Signature + Claims Combined Tests
    
    @Test
    func validClaimsButInvalidSignature() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        // Claims are valid
        #expect(throws: Never.self) {
            try jwt.verifyDate()
        }
        #expect(jwt.payload.value.issuer == "test")
        
        // But signature verification with wrong key should fail
        let wrongKey = try JSONWebKeyHMAC<SHA256>(SymmetricKey(size: .bits256))
        #expect(throws: CryptoKitError.self) {
            try jwt.verifySignature(using: wrongKey)
        }
    }
    
    // MARK: - Edge Cases
    
    @Test
    func expirationAtExactlyNow() throws {
        let now = Date()
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            // Expiration at exactly now (could go either way due to timing)
            claims.expiry = now
        }
        
        // By the time verification runs, it should be expired
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyDate()
        }
    }
    
    @Test
    func notBeforeAtExactlyNow() throws {
        let now = Date()
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            claims.notBefore = now
            claims.expiry = now.addingTimeInterval(3600)
        }
        
        // Should pass - nbf at now is valid
        #expect(throws: Never.self) {
            try jwt.verifyDate()
        }
    }
    
    @Test
    func veryLongIssuer() throws {
        let longIssuer = String(repeating: "a", count: 10000)
        let jwt = try createTestJWT { claims in
            claims.issuer = longIssuer
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        // Should work with long issuer
        #expect(jwt.payload.value.issuer == longIssuer)
        #expect(jwt.payload.value.issuer != String(repeating: "b", count: 10000))
    }
    
    @Test
    func unicodeIssuer() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "测试发行者"
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        #expect(jwt.payload.value.issuer == "测试发行者")
        #expect(jwt.payload.value.issuer != "测试")
    }
    
    @Test
    func emojiInAudience() throws {
        let jwt = try createTestJWT { claims in
            claims.issuer = "test"
            claims.audience = ["app-🚀", "app-🎉"]
            claims.expiry = Date().addingTimeInterval(3600)
        }
        
        #expect(throws: Never.self) {
            try jwt.verifyAudience(includes: "app-🚀")
        }
        
        #expect(throws: JSONWebValidationError.self) {
            try jwt.verifyAudience(includes: "app-🔥")
        }
    }
}
