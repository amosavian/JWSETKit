//
//  JWKNegativeTests.swift
//
//
//  Created by Claude on 12/13/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

/// Tests for invalid JWK formats and key parsing errors
@Suite
struct JWKNegativeTests {
    // MARK: - RSA Key Tests
    
    @Test
    func rsaMissingN() throws {
        // RSA key without modulus (n)
        let jwk = """
        {"kty":"RSA",
         "e":"AQAB"}
        """
        #expect(throws: CryptoKitError.self) {
            try JSONWebRSAPublicKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    @Test
    func rsaMissingE() throws {
        // RSA key without exponent (e)
        let jwk = """
        {"kty":"RSA",
         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
        """
        #expect(throws: CryptoKitError.self) {
            try JSONWebRSAPublicKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    @Test
    func rsaPrivateMissingD() throws {
        // RSA private key without private exponent (d)
        let jwk = """
        {"kty":"RSA",
         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB",
         "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
         "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc"}
        """
        #expect(throws: CryptoKitError.self) {
            try JSONWebRSAPrivateKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    // MARK: - EC Key Tests
    
    @Test
    func ecMissingX() throws {
        // EC key without x coordinate
        let jwk = """
        {"kty":"EC",
         "crv":"P-256",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        """
        #expect(throws: CryptoKitError.self) {
            try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    @Test
    func ecMissingY() throws {
        // EC key without y coordinate (for non-OKP curves)
        let jwk = """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}
        """
        #expect(throws: CryptoKitError.self) {
            try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    @Test
    func ecPrivateMissingD() throws {
        // EC private key without d parameter
        let jwk = """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        """
        // Should successfully parse as public key
        let publicKey = try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        #expect(publicKey.xCoordinate != nil)
        
        // But fail as private key
        #expect(throws: CryptoKitError.self) {
            try JSONWebECPrivateKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    // MARK: - OKP (Ed25519/X25519) Tests
    
    @Test
    func okpMissingX() throws {
        // OKP key without x coordinate
        let jwk = """
        {"kty":"OKP",
         "crv":"Ed25519"}
        """
        #expect(throws: CryptoKitError.self) {
            try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    // MARK: - Symmetric Key Tests
    
    @Test
    func symmetricMissingK() throws {
        // Symmetric key without key material
        let jwk = """
        {"kty":"oct"}
        """
        #expect(throws: CryptoKitError.self) {
            try SymmetricKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    // MARK: - Missing Key Type Tests
    
    @Test
    func missingKeyType() throws {
        // Missing kty field
        let jwk = """
        {"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "crv":"P-256"}
        """
        #expect(throws: JSONWebKeyError.unknownKeyType) {
            try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        }
    }
    
    // MARK: - JWK Set Tests
    
    @Test
    func jwkSetInvalidJSON() throws {
        let invalidJSON = "not json at all"
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(JSONWebKeySet.self, from: Data(invalidJSON.utf8))
        }
    }
    
    @Test
    func jwkSetMissingKeys() throws {
        // JWKS without "keys" array
        let jwks = """
        {"other":"field"}
        """
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(JSONWebKeySet.self, from: Data(jwks.utf8))
        }
    }
    
    @Test
    func jwkSetKeysNotArray() throws {
        // "keys" is not an array
        let jwks = """
        {"keys":"not an array"}
        """
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(JSONWebKeySet.self, from: Data(jwks.utf8))
        }
    }
    
    @Test
    func jwkSetEmptyKeys() throws {
        // Empty keys array is valid
        let jwks = """
        {"keys":[]}
        """
        let keySet = try JSONDecoder().decode(JSONWebKeySet.self, from: Data(jwks.utf8))
        #expect(keySet.keys.isEmpty)
    }
    
    @Test
    func jwkSetWithInvalidKey() throws {
        // One valid key, one invalid
        let jwks = """
        {"keys":[
            {"kty":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
             "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},
            {"kty":"INVALID"}
        ]}
        """
        // Behavior depends on implementation - may skip invalid keys
        let keySet = try JSONDecoder().decode(JSONWebKeySet.self, from: Data(jwks.utf8))
        // At least the valid key should be present
        #expect(keySet.keys.count >= 1)
    }
    
    // MARK: - Format Mismatch Tests
    
    @Test
    func parseJWKAsJWKSet() throws {
        // Try to parse a single JWK as a JWK Set
        let jwk = """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        """
        // Should fail since there's no "keys" array
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(JSONWebKeySet.self, from: Data(jwk.utf8))
        }
    }
    
    // MARK: - Edge Cases
    
    @Test
    func emptyJWK() throws {
        let emptyJWK = "{}"
        #expect(throws: JSONWebKeyError.unknownKeyType) {
            try JSONWebECPublicKey(importing: Data(emptyJWK.utf8), format: .jwk)
        }
    }
    
    @Test
    func jwkIsArray() throws {
        // JWK should be an object, not an array
        let arrayJWK = "[{\"kty\":\"EC\"}]"
        #expect(throws: DecodingError.self) {
            try JSONWebECPublicKey(importing: Data(arrayJWK.utf8), format: .jwk)
        }
    }
    
    @Test
    func veryLongKeyId() throws {
        // Valid key with very long kid
        let longKid = String(repeating: "a", count: 10000)
        let jwk = """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "kid":"\(longKid)"}
        """
        // Should work with long kid
        let key = try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        #expect(key.keyId == longKid)
    }
    
    @Test
    func unicodeKeyId() throws {
        let jwk = """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "kid":"密钥标识符🔑"}
        """
        let key = try JSONWebECPublicKey(importing: Data(jwk.utf8), format: .jwk)
        #expect(key.keyId == "密钥标识符🔑")
    }
}
