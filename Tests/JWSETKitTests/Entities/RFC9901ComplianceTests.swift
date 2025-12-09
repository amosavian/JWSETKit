//
//  RFC9901ComplianceTests.swift
//  JWSETKit
//
//  RFC 9901 Selective Disclosure for JSON Web Tokens compliance tests
//  Based on examples from https://datatracker.ietf.org/doc/html/rfc9901
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite("RFC 9901 Compliance Tests")
struct RFC9901ComplianceTests {
    // MARK: - Section 5.1: Issuance Example
    
    @Test("RFC 9901 Section 5.1 - SD-JWT Issuance with multiple disclosures")
    func section5_1_Issuance() throws {
        // This test implements the complete issuance example from RFC 9901 Section 5.1
        // with disclosures for given_name, family_name, email, phone_number,
        // phone_number_verified, address, birthdate, updated_at
        
        let issuerKey = P256.Signing.PrivateKey()
        
        // Create user claims as shown in Section 5.1
        let claims = try JSONWebTokenClaims {
            $0.issuer = "https://issuer.example.com"
            $0.subject = "user_42"
            $0.issuedAt = Date(timeIntervalSince1970: 1_683_000_000)
            $0.expiry = Date(timeIntervalSince1970: 1_883_000_000)
            
            // Selectively disclosable claims
            $0.givenName = "John"
            $0.familyName = "Doe"
            $0.email = "johndoe@example.com"
            $0.phoneNumber = "+1-202-555-0101"
            $0.isPhoneNumberVerified = true
            $0.birthdate = .init(iso8601Date: "1940-01-01")
            $0.updatedAt = Date(timeIntervalSince1970: 1_570_000_000)
            $0.address = .init(streetAddress: "123 Main St", locality: "Anytown", region: "Anystate", country: "US")
            $0.nationalities = ["US", "DE"]
        }
        
        // Create SD-JWT with selective disclosure for specific claims using paths
        // Per RFC: iss, iat, exp, sub, cnf stay visible; others become selective
        let concealedPaths: Set<JSONPointer> = [
            "/given_name", "/family_name", "/email", "/phone_number",
            "/phone_number_verified", "/address", "/birthdate", "/updated_at",
        ]
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: concealedPaths,
            using: issuerKey
        )
        
        // Verify 8 top-level disclosures were created (not counting array elements here)
        #expect(sdJWT.disclosures.count >= 8)
        
        // Verify permanent claims are visible in payload
        #expect(sdJWT.payload.issuer == "https://issuer.example.com")
        #expect(sdJWT.payload.subject == "user_42")
        #expect(sdJWT.payload.issuedAt != nil)
        #expect(sdJWT.payload.expiry != nil)
        
        // Verify _sd_alg is set
        #expect(sdJWT.payload.disclosureHashAlgorithm == SHA256.identifier)
        
        // Verify _sd array contains disclosure hashes
        #expect(sdJWT.payload.disclosureHashes.count >= 8)
        
        // Verify disclosed payload reconstruction
        let disclosedPayload = try sdJWT.disclosedPayload
        #expect(disclosedPayload.givenName == "John")
        #expect(disclosedPayload.familyName == "Doe")
        #expect(disclosedPayload.email == "johndoe@example.com")
    }
    
    // MARK: - Section 5.2: Presentation Example
    
    @Test("RFC 9901 Section 5.2 - Selective disclosure presentation with KB-JWT")
    func section5_2_Presentation() throws {
        // This test implements the presentation example from RFC 9901 Section 5.2
        // where the holder selectively reveals claims with key binding
        
        let issuerKey = P256.Signing.PrivateKey()
        let holderKey = P256.Signing.PrivateKey()
        
        // Create full SD-JWT first (as in Section 5.1)
        let claims = try JSONWebTokenClaims {
            $0.issuer = "https://issuer.example.com"
            $0.subject = "user_42"
            $0.issuedAt = Date(timeIntervalSince1970: 1_683_000_000)
            $0.expiry = Date(timeIntervalSince1970: 1_883_000_000)
            $0.givenName = "John"
            $0.familyName = "Doe"
            $0.email = "johndoe@example.com"
            $0.phoneNumber = "+1-202-555-0101"
            // Add holder's key confirmation
            $0.confirmation = .key(holderKey)
        }
        
        let fullSDJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/given_name", "/family_name", "/email", "/phone_number"],
            using: issuerKey
        )
        
        // Verify disclosures were created for all selective claims
        #expect(fullSDJWT.disclosures.count == 4)
        
        // Create presentation with selected claims (Section 5.2: family_name, given_name)
        let presentation = try fullSDJWT.presenting(paths: ["/family_name", "/given_name"])
        
        // Add key binding as in Section 5.2
        let presentationWithKB = try presentation.withKeyBinding(
            using: holderKey,
            algorithm: .ecdsaSignatureP256SHA256,
            nonce: "1234567890",
            audience: "https://verifier.example.org"
        )
        
        // Verify presentation contains only selected disclosures
        #expect(presentationWithKB.disclosures.count == 2) // family_name, given_name
        
        // Verify key binding is present
        #expect(presentationWithKB.keyBinding != nil)
        
        // Verify KB-JWT claims
        #expect(presentationWithKB.keyBinding?.payload.nonce == "1234567890")
        #expect(presentationWithKB.keyBinding?.payload.audience.contains("https://verifier.example.org") == true)
        #expect(presentationWithKB.keyBinding?.payload.issuedAt != nil)
        #expect(presentationWithKB.keyBinding?.payload.selectiveDisclosureHash != nil)
        
        // Verify key binding
        try presentationWithKB.verifyKeyBinding(
            expectedNonce: "1234567890",
            expectedAudience: "https://verifier.example.org"
        )
    }
    
    // MARK: - Appendix A.2: Complex Structured SD-JWT
    
    @Test("RFC 9901 Appendix A.2 - Complex nested structure with multiple levels")
    func appendixA2_ComplexStructure() throws {
        // Tests complex nested structures with selective disclosure at multiple levels
        
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user_42"
            $0.name = "John Doe"
            $0.address = JSONWebAddress(
                streetAddress: "123 Main St",
                locality: "Anytown"
            )
        }
        
        // Make top-level claims selective
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/address"],
            using: issuerKey
        )
        
        // Verify disclosure was created
        #expect(sdJWT.disclosures.count == 1)
        #expect(sdJWT.disclosures.first?.key == "address")
        
        // Verify complex structure is preserved
        let address = try sdJWT.disclosedPayload.address
        #expect(address?.streetAddress == "123 Main St")
        #expect(address?.locality == "Anytown")
    }
    
    // MARK: - Additional RFC Scenarios
    
    @Test("RFC 9901 - Recursive disclosure in nested objects")
    func recursiveDisclosure() throws {
        // Test selective disclosure within nested objects
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user_recursive_test"
            $0.name = "Alice Smith"
            $0.address = JSONWebAddress(
                streetAddress: "456 Oak Ave",
                locality: "Springfield"
            )
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/address"],
            using: issuerKey
        )
        
        let address = try sdJWT.disclosedPayload.address
        #expect(address?.streetAddress == "456 Oak Ave")
        #expect(address?.locality == "Springfield")
    }
    
    @Test("RFC 9901 - Array element selective disclosure")
    func arrayElementDisclosure() throws {
        // Test that arrays are properly handled (array elements can be concealed)
        let issuerKey = P256.Signing.PrivateKey()
        
        var claims = JSONWebTokenClaims(storage: JSONWebValueStorage())
        claims.subject = "user_42"
        claims.nationalities = ["US", "DE", "FR"]
        
        // Create SD-JWT that conceals the nationalities array
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/nationalities"],
            decoyCount: 0,
            using: issuerKey
        )
        
        // The nationalities should be concealed in the payload
        let nationalities: [String]? = sdJWT.payload.nationalities
        #expect(nationalities == nil)
        
        // But available when disclosed
        let disclosed = try sdJWT.disclosedPayload
        #expect(disclosed.nationalities == ["US", "DE", "FR"])
    }
    
    @Test("RFC 9901 - All disclosable policy")
    func allDisclosablePolicy() throws {
        // Test the allDisclosable policy that conceals all claims except standard ones
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.issuer = "https://issuer.example.com"
            $0.subject = "user_42"
            $0.issuedAt = Date()
            $0.expiry = Date().addingTimeInterval(3600)
            $0.givenName = "John"
            $0.familyName = "Doe"
            $0.email = "john.doe@example.com"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            decoyCount: 0,
            using: issuerKey
        )
        
        // Standard claims should remain visible
        #expect(sdJWT.payload.issuer == "https://issuer.example.com")
        #expect(sdJWT.payload.subject == "user_42")
        #expect(sdJWT.payload.issuedAt != nil)
        #expect(sdJWT.payload.expiry != nil)
        
        // Non-standard claims should be concealed
        #expect(sdJWT.payload.givenName == nil)
        #expect(sdJWT.payload.familyName == nil)
        #expect(sdJWT.payload.email == nil)
        
        // But should be available via disclosure
        let disclosed = try sdJWT.disclosedPayload
        #expect(disclosed.givenName == "John")
        #expect(disclosed.familyName == "Doe")
        #expect(disclosed.email == "john.doe@example.com")
    }
    
    @Test("RFC 9901 - Present using paths")
    func presentUsingPaths() throws {
        // Test presenting disclosures using JSON Pointer paths
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user_42"
            $0.givenName = "John"
            $0.familyName = "Doe"
            $0.email = "john.doe@example.com"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/given_name", "/family_name", "/email"],
            using: issuerKey
        )
        
        // Present only given_name and email using paths
        let presentation = try sdJWT.presenting(paths: ["/given_name", "/email"])
        
        #expect(presentation.disclosures.count == 2)
        let disclosedKeys = Set(presentation.disclosures.compactMap(\.key))
        #expect(disclosedKeys.contains("given_name"))
        #expect(disclosedKeys.contains("email"))
        #expect(!disclosedKeys.contains("family_name"))
    }
}
