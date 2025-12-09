//
//  JSONWebSelectiveDisclosureJWTTests.swift
//
//
//  Created by Claude Code on 9/9/25.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite("SD-JWT Tests")
struct JSONWebSelectiveDisclosureJWTTests {
    // MARK: - Basic Disclosure Tests
    
    @Test("Create selective disclosure")
    func createSelectiveDisclosure() throws {
        let disclosure = JSONWebSelectiveDisclosure(
            "email",
            value: "john.doe@example.com",
            salt: "ZorVSr3xmOK--ZAzjIWUzw".decoded
        )
        
        #expect(disclosure.key == "email")
        #expect(disclosure.value as? String == "john.doe@example.com")
        #expect(disclosure.salt.count >= 16) // At least 128 bits
        #expect(try disclosure.encoded == "WyJab3JWU3IzeG1PSy0tWkF6aklXVXp3IiwiZW1haWwiLCJqb2huLmRvZUBleGFtcGxlLmNvbSJd")
        #expect(try disclosure.digest(using: SHA256.self) == "slGGh6U1smz_WBQPhlfX90TCr98fg7UfXLJcT-Qf8kY".decoded)
    }
    
    @Test("Encode and decode selective disclosure")
    func selectiveDisclosureCodec() throws {
        let originalDisclosure = JSONWebSelectiveDisclosure("test", value: "value123")
        
        let encoded = try originalDisclosure.encoded
        let decodedDisclosure = try JSONWebSelectiveDisclosure(encoded: encoded)
        
        #expect(decodedDisclosure.key == originalDisclosure.key)
        #expect(decodedDisclosure.value as? String == originalDisclosure.value as? String)
        #expect(try decodedDisclosure.digest(using: SHA256.self) == originalDisclosure.digest(using: SHA256.self))
    }
    
    @Test("Merge disclosures with JWT claims")
    func payloadMerging() throws {
        var baseClaims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.name = "John Doe"
        }
        
        let emailDisclosure = JSONWebSelectiveDisclosure("email", value: "john.doe@example.com")
        let ageDisclosure = JSONWebSelectiveDisclosure("age", value: 30)
        let disclosures = try JSONWebSelectiveDisclosureList([emailDisclosure, ageDisclosure], hashFunction: SHA256.self)
        
        baseClaims.disclosureHashAlgorithm = SHA256.identifier
        baseClaims.disclosureHashes = disclosures.hashes
        let mergedClaims = try baseClaims.disclosed(with: disclosures)
        
        // Verify merged claims contain all data
        #expect(mergedClaims.subject == "user123")
        #expect(mergedClaims.name == "John Doe")
        #expect(mergedClaims.email == "john.doe@example.com")
        #expect(mergedClaims.age == 30)
        #expect(mergedClaims.disclosureHashes.isEmpty)
    }
    
    @Test("Handle missing disclosures gracefully")
    func missingDisclosures() throws {
        // Create base claims using proper JWT claims
        var baseClaims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.name = "John Doe"
        }
        // Create a disclosure
        let emailDisclosure = JSONWebSelectiveDisclosure("email", value: "john.doe@example.com")
        let emailHash = try emailDisclosure.digest(using: SHA256.self)
        
        // Add a hash that won't have a matching disclosure
        let fakeHash = Data(count: 32) // 32 zero bytes
        baseClaims.disclosureHashAlgorithm = SHA256.identifier
        baseClaims.disclosureHashes = [emailHash, fakeHash]
        
        // Test merging - should work even with missing disclosure
        let partialDisclosures = try JSONWebSelectiveDisclosureList([emailDisclosure], hashFunction: SHA256.self)
        let mergedClaims = try baseClaims.disclosed(with: partialDisclosures)
        
        // Verify available claims are present
        #expect(mergedClaims.subject == "user123")
        #expect(mergedClaims.name == "John Doe")
        #expect(mergedClaims.email == "john.doe@example.com")
        
        // Missing disclosure should not cause any issues - SD metadata should be removed
        #expect(mergedClaims.disclosureHashes.isEmpty)
    }
    
    @Test("Disclose nested dictionary claims")
    func nestedDictionaryDisclosing() throws {
        // Create disclosures for nested address fields
        let streetDisclosure = JSONWebSelectiveDisclosure("street", value: "123 Main St")
        let cityDisclosure = JSONWebSelectiveDisclosure("city", value: "Anytown")
        let zipDisclosure = JSONWebSelectiveDisclosure("zip", value: "12345")
        let disclosureList = try JSONWebSelectiveDisclosureList([streetDisclosure, cityDisclosure, zipDisclosure], hashFunction: SHA256.self)
        
        // Create a nested dictionary with selective disclosures (simulating what would be in a JWT payload)
        let addressDict: [String: any Sendable] = [
            "country": "USA",
            "_sd": disclosureList.hashes,
        ]
        
        // Test the disclosure process directly on the dictionary
        let disclosedAddress = try addressDict.disclosed(with: disclosureList)
        
        // Verify the disclosed address contains all data
        #expect(disclosedAddress["country"] as? String == "USA")
        #expect(disclosedAddress["street"] as? String == "123 Main St")
        #expect(disclosedAddress["city"] as? String == "Anytown")
        #expect(disclosedAddress["zip"] as? String == "12345")
    }
    
    @Test("Disclose array element claims")
    func arrayElementDisclosing() throws {
        // Create disclosures for array elements (note: key is nil for array elements)
        let element1Disclosure = JSONWebSelectiveDisclosure(value: "secret-item-1")
        let element2Disclosure = JSONWebSelectiveDisclosure(value: "secret-item-2")
        let disclosureList = try JSONWebSelectiveDisclosureList([element1Disclosure, element2Disclosure], hashFunction: SHA256.self)
        
        // Create array with regular items and selective disclosure markers
        let itemsArray: [any Sendable] = [
            "public-item-1",
            ["...": disclosureList.hashes[0].urlBase64EncodedString()],
            "public-item-2",
            ["...": disclosureList.hashes[1]],
            "public-item-3",
        ]
        let disclosedItems = try itemsArray.disclosed(with: disclosureList)
        print(disclosedItems)
        #expect(disclosedItems as? [String] == ["public-item-1", "secret-item-1", "public-item-2", "secret-item-2", "public-item-3"])
    }
    
    @Test("Complex nested structure with multiple disclosure levels")
    func complexNestedDisclosing() throws {
        // Create disclosures for various nested levels
        let phoneDisclosure = JSONWebSelectiveDisclosure("phone", value: "+1-555-1234")
        let departmentDisclosure = JSONWebSelectiveDisclosure("department", value: "Engineering")
        let skillDisclosure = JSONWebSelectiveDisclosure(value: "Swift Programming")
        let disclosureList = try JSONWebSelectiveDisclosureList([phoneDisclosure, departmentDisclosure, skillDisclosure], hashFunction: SHA256.self)
        
        let phoneHash = try phoneDisclosure.digest(using: SHA256.self)
        let departmentHash = try departmentDisclosure.digest(using: SHA256.self)
        let skillHash = try skillDisclosure.digest(using: SHA256.self)
        
        let contactInfo: [String: any Sendable] = [
            "email": "john@example.com",
            "_sd": [phoneHash],
        ]
        
        let skillsArray: [any Sendable] = [
            "iOS Development",
            ["...": skillHash],
            "Team Leadership",
        ]
        
        let workInfo: [String: any Sendable] = [
            "company": "TechCorp",
            "_sd": [departmentHash],
            "skills": skillsArray,
        ]
        
        // Test disclosing contact info
        let disclosedContact = try contactInfo.disclosed(with: disclosureList)
        #expect(disclosedContact["email"] as? String == "john@example.com")
        #expect(disclosedContact["phone"] as? String == "+1-555-1234")
        
        // Test disclosing work info (which includes nested skills array)
        let disclosedWork = try workInfo.disclosed(with: disclosureList)
        #expect(disclosedWork["company"] as? String == "TechCorp")
        #expect(disclosedWork["department"] as? String == "Engineering")
        #expect(disclosedWork["skills"] as? [String] == ["iOS Development", "Swift Programming", "Team Leadership"])
    }
    
    // MARK: - SD-JWT Token Tests
    
    @Test("Create SD-JWT with selective claims using paths")
    func createSDJWT() throws {
        let issuerKey = try JSONWebECPrivateKey(curve: .p256)
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.name = "John Doe"
            $0.email = "john.doe@example.com"
            $0.age = 30
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: [.init(\.email), "/age"],
            using: issuerKey
        )
        
        // Verify structure
        #expect(sdJWT.disclosures.count == 2)
        #expect(Set(sdJWT.disclosures.compactMap(\.key)) == ["email", "age"])
        
        // Verify issuer JWT contains _sd array
        let issuerPayload = sdJWT.jwt.payload
        #expect(!issuerPayload.disclosureHashes.isEmpty)
        #expect(issuerPayload.disclosureHashAlgorithm == SHA256.identifier)
        
        // Verify selective fields are not in issuer payload directly
        #expect(issuerPayload.email == nil)
        #expect((issuerPayload.age as Int?) == nil)
        
        // Verify non-selective fields remain
        #expect(issuerPayload.name == "John Doe")
        #expect(issuerPayload.subject == "user123")
    }
    
    @Test("Create SD-JWT with all claims concealed")
    func createSDJWTAllConcealed() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.name = "John Doe"
            $0.email = "john.doe@example.com"
        }
        
        // Use default policy (all disclosable) with no decoys
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            decoyCount: 0,
            using: issuerKey
        )
        
        // All non-standard claims should be concealed (name and email)
        #expect(sdJWT.disclosures.count == 2)
        
        // Standard claims should remain visible
        #expect(sdJWT.jwt.payload.subject == "user123")
    }
    
    @Test("Reconstruct disclosed payload from SD-JWT")
    func testDisclosedPayload() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.name = "John Doe"
            $0.email = "john.doe@example.com"
            $0.age = 30
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: [.init(\.email), "/age"],
            using: issuerKey
        )
        
        // Reconstruct full payload
        let disclosedPayload = try sdJWT.disclosedPayload
        
        #expect(disclosedPayload.subject == "user123")
        #expect(disclosedPayload.name == "John Doe")
        #expect(disclosedPayload.email == "john.doe@example.com")
        #expect(disclosedPayload.age == 30)
        
        // _sd should be removed after disclosure
        #expect(disclosedPayload.disclosureHashes.isEmpty)
    }
    
    @Test("Create presentation with selected claims")
    func selectivePresentation() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
            $0.age = 30
            $0.name = "John Doe"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email", "/age"],
            using: issuerKey
        )
        
        // Present only email
        let presentation = try sdJWT.presenting(paths: ["/email"])
        
        #expect(presentation.disclosures.count == 1)
        #expect(presentation.disclosures.first?.key == "email")
        
        // JWT should be the same
        #expect(presentation.jwt.description == sdJWT.jwt.description)
    }
    
    @Test("Create presentation with paths")
    func selectivePresentationWithPaths() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
            $0.age = 30
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email", "/age"],
            using: issuerKey
        )
        
        // Present only email using path
        let presentation = try sdJWT.presenting(paths: ["/email"])
        
        #expect(presentation.disclosures.count == 1)
        #expect(presentation.disclosures.first?.key == "email")
    }
    
    @Test("Validate SD-JWT structure")
    func validateSDJWT() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        
        // Should validate without error
        #expect(throws: Never.self) {
            try sdJWT.validate()
        }
    }
    
    @Test("Detect orphan disclosures")
    func orphanDisclosureDetection() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        
        // Create an orphan disclosure (not in JWT payload)
        let orphanDisclosure = JSONWebSelectiveDisclosure("orphan", value: "orphan_value")
        let tamperedSDJWT = JSONWebSelectiveDisclosureToken(
            jwt: sdJWT.jwt,
            disclosures: sdJWT.disclosures + [orphanDisclosure],
            keyBinding: nil
        )
        
        // Validation should fail with orphan disclosure error
        #expect(throws: JSONWebValidationError.self) {
            try tamperedSDJWT.validate()
        }
    }
    
    // MARK: - Key Binding Tests
    
    @Test("Create SD-JWT with key binding")
    func createKeyBinding() throws {
        let issuerKey = P256.Signing.PrivateKey()
        let holderKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
            $0.confirmation = .key(holderKey)
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        
        // Create presentation with key binding
        let presentation = try sdJWT.withKeyBinding(
            using: holderKey,
            algorithm: .ecdsaSignatureP256SHA256,
            nonce: "test-nonce-123",
            audience: "https://verifier.example.com"
        )
        
        #expect(presentation.keyBinding != nil)
        
        // Verify KB-JWT header
        #expect(presentation.keyBinding?.signatures.first?.protected.type == .keyBindingJWT)
        
        // Verify KB-JWT claims
        let kbPayload = presentation.keyBinding!.payload
        #expect(kbPayload.nonce == "test-nonce-123")
        #expect(kbPayload.audience.contains("https://verifier.example.com"))
        #expect(kbPayload.selectiveDisclosureHash != nil)
        #expect(kbPayload.issuedAt != nil)
    }
    
    @Test("Verify key binding with correct parameters")
    func verifyKeyBindingSuccess() throws {
        let issuerKey = P256.Signing.PrivateKey()
        let holderKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
            $0.confirmation = .key(holderKey)
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        
        let presentation = try sdJWT.withKeyBinding(
            using: holderKey,
            algorithm: .ecdsaSignatureP256SHA256,
            nonce: "test-nonce-123",
            audience: "https://verifier.example.com"
        )
        
        // Verification should succeed
        #expect(throws: Never.self) {
            try presentation.verifyKeyBinding(
                expectedNonce: "test-nonce-123",
                expectedAudience: "https://verifier.example.com"
            )
        }
    }
    
    @Test("Verify key binding fails with wrong nonce")
    func verifyKeyBindingWrongNonce() throws {
        let issuerKey = P256.Signing.PrivateKey()
        let holderKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.confirmation = .key(holderKey)
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            using: issuerKey
        )
        
        let presentation = try sdJWT.withKeyBinding(
            using: holderKey,
            algorithm: .ecdsaSignatureP256SHA256,
            nonce: "correct-nonce",
            audience: "https://verifier.example.com"
        )
        
        // Verification should fail with wrong nonce
        #expect(throws: JSONWebValidationError.self) {
            try presentation.verifyKeyBinding(
                expectedNonce: "wrong-nonce",
                expectedAudience: "https://verifier.example.com"
            )
        }
    }
    
    @Test("Verify key binding fails with wrong audience")
    func verifyKeyBindingWrongAudience() throws {
        let issuerKey = P256.Signing.PrivateKey()
        let holderKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.confirmation = .key(holderKey)
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            using: issuerKey
        )
        
        let presentation = try sdJWT.withKeyBinding(
            using: holderKey,
            algorithm: .ecdsaSignatureP256SHA256,
            nonce: "test-nonce",
            audience: "https://correct-verifier.example.com"
        )
        
        // Verification should fail with wrong audience
        #expect(throws: JSONWebValidationError.self) {
            try presentation.verifyKeyBinding(
                expectedNonce: "test-nonce",
                expectedAudience: "https://wrong-verifier.example.com"
            )
        }
    }
    
    @Test("Verify key binding required error")
    func verifyKeyBindingRequired() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            using: issuerKey
        )
        
        // SD-JWT without key binding should fail verification
        #expect(throws: JSONWebValidationError.self) {
            try sdJWT.verifyKeyBinding(
                expectedNonce: "test-nonce",
                expectedAudience: "https://verifier.example.com"
            )
        }
    }
    
    // MARK: - Serialization Tests
    
    @Test("SD-JWT compact serialization roundtrip")
    func compactSerializationRoundtrip() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        
        // Encode to compact format
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.compact
        let compactData = try encoder.encode(sdJWT)
        let compactString = String(decoding: compactData, as: UTF8.self)
        
        // Should contain tilde separators
        #expect(compactString.contains("~"))
        
        // Decode back
        let decoder = JSONDecoder()
        decoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.compact
        let decoded = try decoder.decode(JSONWebSelectiveDisclosureToken.self, from: compactData)
        
        #expect(decoded.jwt.description == sdJWT.jwt.description)
        #expect(decoded.disclosures.count == sdJWT.disclosures.count)
    }
    
    // MARK: - JWT Verification Tests
    
    @Test("Verify issuer JWT signature")
    func verifyIssuerJWTSignature() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
        }
        
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        
        // Verify with correct key should succeed
        #expect(throws: Never.self) {
            try sdJWT.jwt.verifySignature(using: issuerKey.publicKey)
        }
        
        // Verify with wrong key should fail
        let wrongKey = P256.Signing.PrivateKey()
        #expect(throws: Error.self) {
            try sdJWT.jwt.verifySignature(using: wrongKey.publicKey)
        }
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Handle invalid disclosure format")
    func invalidDisclosureFormat() throws {
        #expect(throws: Error.self) {
            try JSONWebSelectiveDisclosure(encoded: "invalid-base64!!!")
        }
        
        #expect(throws: Error.self) {
            try JSONWebSelectiveDisclosure(encoded: "")
        }
    }
    
    // MARK: - Disclosure Policy Tests
    
    @Test("Create SD-JWT with disclosure policy")
    func disclosurePolicy() throws {
        let issuerKey = P256.Signing.PrivateKey()
        
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.issuer = "https://issuer.example.com"
            $0.name = "John Doe"
            $0.email = "john.doe@example.com"
        }
        
        // Create with explicit disclosable paths
        let policy = DisclosurePolicy.disclosable(["/name", "/email"])
        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            policy: policy,
            using: issuerKey
        )
        
        // Verify structure
        #expect(sdJWT.disclosures.count == 2)
        
        // Verify standard claims remain visible
        #expect(sdJWT.jwt.payload.subject == "user123")
        #expect(sdJWT.jwt.payload.issuer == "https://issuer.example.com")
    }
}
