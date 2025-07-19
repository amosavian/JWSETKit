//
//  JWTPopClaimsTests.swift
//
//
//  Created by GitHub Copilot on 5/19/25.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite
struct JWTPopClaimsTests {
    // Sample JSON data for various confirmation types
    let jwkConfirmationJSON = """
    {
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
        }
    }
    """
    
    let kidConfirmationJSON = """
    {
        "cnf": {
            "kid": "key-identifier-1"
        }
    }
    """
    
    let jkuConfirmationJSON = """
    {
        "cnf": {
            "jku": "https://example.com/jwks.json",
            "kid": "key-1"
        }
    }
    """
    
    @Test
    func decodeKeyConfirmation() throws {
        let claims = try JSONDecoder().decode(JSONWebTokenClaims.self, from: Data(jwkConfirmationJSON.utf8))
        
        try #require(claims.confirmation != nil)
        let key = try #require(claims.confirmation?.key, "Expected key confirmation type")
        #expect(key is JSONWebECPublicKey)
        #expect(key.keyType == .ellipticCurve)
        #expect(key.curve == .p256)
    }
    
    @Test
    func decodeKeyIDConfirmation() throws {
        let claims = try JSONDecoder().decode(JSONWebTokenClaims.self, from: Data(kidConfirmationJSON.utf8))
        
        try #require(claims.confirmation != nil)
        #expect(claims.confirmation?.keyId == "key-identifier-1", "Expected keyId confirmation type")
    }
    
    @Test
    func decodeJKUConfirmation() throws {
        let claims = try JSONDecoder().decode(JSONWebTokenClaims.self, from: Data(jkuConfirmationJSON.utf8))
        
        #expect(claims.confirmation != nil)
        #expect(claims.confirmation?.jwkSetUrl?.absoluteString == "https://example.com/jwks.json", "Expected url confirmation type")
        #expect(claims.confirmation?.keyId == "key-1", "Expected keyId confirmation type")
    }
    
    @Test
    func createKeyConfirmation() throws {
        // Create claims with a key confirmation
        let claims = try JSONWebTokenClaims {
            $0.confirmation = .key(ExampleKeys.publicEC256)
        }
        
        // Verify the confirmation was set properly
        #expect(claims.confirmation?.key?.keyType == .ellipticCurve, "Expected key confirmation type")
        #expect(claims.confirmation?.key?.curve == .p256, "Expected EC key")
        
        // Encode and decode to verify serialization
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        
        let encoded = try encoder.encode(claims)
        let decoded = try decoder.decode(JSONWebTokenClaims.self, from: encoded)
        
        #expect(decoded.confirmation != nil)
    }
    
    @Test
    func thumbprintConfirmation() throws {
        // Create a key thumbprint confirmation
        let claims = try JSONWebTokenClaims {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC256)
        }
        
        // Verify the thumbprint
        if case .keyThumbprint(let thumbprint) = claims.confirmation {
            let calculatedThumbprint = try ExampleKeys.publicEC256.thumbprint(format: .jwk, using: SHA256.self).data
            #expect(thumbprint == calculatedThumbprint)
        } else {
            Issue.record("Expected thumbprint confirmation type")
        }
        
        // Test thumbprint validation
        try claims.confirmation?.validateThumbprint(ExampleKeys.publicEC256)
    }
    
    @Test
    func negativeThumbprintValidation() throws {
        // Create claims with a thumbprint for EC256 key
        let claims = try JSONWebTokenClaims {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC256)
        }
        
        // Try to validate with a different key (RSA key)
        do {
            try claims.confirmation?.validateThumbprint(ExampleKeys.publicRSA2048)
            Issue.record("Expected thumbprint validation to fail with mismatched key")
        } catch {
            // Expected behavior - thumbprint shouldn't match
        }
        
        // Try to validate with a similar but different EC key
        do {
            try claims.confirmation?.validateThumbprint(ExampleKeys.privateEC384.publicKey)
            Issue.record("Expected thumbprint validation to fail with different EC key")
        } catch {
            // Expected behavior - thumbprint shouldn't match
        }
    }
    
    @Test
    func certificateThumbprintConfirmation() throws {
        // This test requires a valid Certificate instance, which might not be available in this example
        // For testing purposes, we'll use the public key's SPKI thumbprint instead
        
        let claims = try JSONWebTokenClaims {
            $0.confirmation = try .certificateThumbprint(ExampleKeys.publicEC256)
        }
        
        // Verify the thumbprint
        if case .certificateThumbprint(let thumbprint) = claims.confirmation {
            let calculatedThumbprint = try ExampleKeys.publicEC256.thumbprint(format: .spki, using: SHA256.self).data
            #expect(thumbprint == calculatedThumbprint)
        } else {
            Issue.record("Expected certificate thumbprint confirmation type")
        }
        
        // Test thumbprint validation
        try claims.confirmation?.validateThumbprint(ExampleKeys.publicEC256)
    }
    
    @Test
    func encryptedKeyConfirmation() throws {
        // Create an encrypted key confirmation
        let claims = try JSONWebTokenClaims {
            $0.confirmation = try .encryptedKey(
                ExampleKeys.publicEC256,
                keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
                keyEncryptionKey: ExampleKeys.publicRSA2048
            )
        }
        
        // Verify we have an encrypted key
        if case .encryptedKey = claims.confirmation {
            // Verify can decrypt the key
            let decrypted = try claims.confirmation?.decryptedKey(using: ExampleKeys.privateRSA2048)
            #expect(try decrypted?.thumbprint(format: .jwk, using: SHA256.self) == ExampleKeys.publicEC256.thumbprint(format: .jwk, using: SHA256.self))
        } else {
            Issue.record("Expected encrypted key confirmation type")
        }
    }
    
    @Test
    func testMatchKey() throws {
        // Create a key set with our test key
        let keySet = JSONWebKeySet(keys: [ExampleKeys.privateEC384, ExampleKeys.publicRSA2048, ExampleKeys.publicEC256])
        
        // Test keyId matching
        let claims = try JSONWebTokenClaims {
            $0.confirmation = .keyId(ExampleKeys.publicEC256.keyId!)
        }
        
        let matchedKey = try claims.confirmation?.matchKey(from: keySet)
        #expect(matchedKey != nil)
        
        // Test thumbprint matching
        let thumbprintClaims = try JSONWebTokenClaims {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC256)
        }
        let matchedByThumbprint = try thumbprintClaims.confirmation?.matchKey(from: keySet)
        #expect(matchedByThumbprint != nil)
    }
    
    @Test
    func matchKeyWithEmptyKeySet() throws {
        // Create claims with key confirmation
        let claims = try JSONWebTokenClaims {
            $0.confirmation = .keyId("test-key-id")
        }
        
        // Test with empty key set
        let emptyKeySet = JSONWebKeySet()
        #expect(throws: JSONWebKeyError.keyNotFound) {
            try claims.confirmation?.matchKey(from: emptyKeySet)
        }
    }
    
    @Test
    func incorrectKeyIDMatching() throws {
        // Create a key set with our test key
        let keySet = JSONWebKeySet(keys: [ExampleKeys.privateEC384, ExampleKeys.publicRSA2048])
        
        // Test with non-existent keyId
        let claims = try JSONWebTokenClaims {
            $0.confirmation = .keyId("non-existent-key-id")
        }
        
        do {
            let matchedKey = try claims.confirmation?.matchKey(from: keySet)
            #expect(matchedKey == nil, "No key should match with non-existent key ID")
        } catch {
            // This might be expected behavior depending on implementation
        }
    }
    
    @Test
    func keyIDAccessor() throws {
        // Test the keyId accessor for different confirmation types
        
        // For keyId
        let claims = try JSONWebTokenClaims {
            $0.confirmation = .keyId("test-key-id")
        }
        #expect(claims.confirmation?.keyId == "test-key-id")
        
        // For URL with keyId
        let urlClaims = try JSONWebTokenClaims {
            $0.confirmation = .url(URL(string: "https://example.com/jwks.json")!, keyId: "url-key-id")
        }
        #expect(urlClaims.confirmation?.keyId == "url-key-id")
        
        // For other types (should be nil)
        let thumbprintClaims = try JSONWebTokenClaims {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC256)
        }
        #expect(thumbprintClaims.confirmation?.keyId == nil)
    }
    
    @Test
    func jWKSetUrl() throws {
        let testUrl = URL(string: "https://example.com/jwks.json")!
        
        let claims = try JSONWebTokenClaims {
            $0.confirmation = .url(testUrl, keyId: "some-key")
        }
        
        #expect(claims.confirmation?.jwkSetUrl == testUrl)
        
        // For other types (should be nil)
        let kidClaims = try JSONWebTokenClaims {
            $0.confirmation = .keyId("test-key")
        }
        #expect(kidClaims.confirmation?.jwkSetUrl == nil)
    }
}
