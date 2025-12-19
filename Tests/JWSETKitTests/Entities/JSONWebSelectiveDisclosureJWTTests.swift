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
        #expect(disclosure.encoded == "WyJab3JWU3IzeG1PSy0tWkF6aklXVXp3IiwiZW1haWwiLCJqb2huLmRvZUBleGFtcGxlLmNvbSJd")
        #expect(disclosure.digest(using: SHA256.self) == "slGGh6U1smz_WBQPhlfX90TCr98fg7UfXLJcT-Qf8kY".decoded)
    }
    
    @Test("Encode and decode selective disclosure")
    func selectiveDisclosureCodec() throws {
        let originalDisclosure = JSONWebSelectiveDisclosure("test", value: "value123")
        
        let encoded = originalDisclosure.encoded
        let decodedDisclosure = try JSONWebSelectiveDisclosure(encoded: encoded)
        
        #expect(decodedDisclosure.key == originalDisclosure.key)
        #expect(decodedDisclosure.value as? String == originalDisclosure.value as? String)
        #expect(decodedDisclosure.digest(using: SHA256.self) == originalDisclosure.digest(using: SHA256.self))
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
        let emailHash = emailDisclosure.digest(using: SHA256.self)
        
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
        #expect(disclosedItems as? [String] == ["public-item-1", "secret-item-1", "public-item-2", "secret-item-2", "public-item-3"])
    }
    
    @Test("Complex nested structure with multiple disclosure levels")
    func complexNestedDisclosing() throws {
        // Create disclosures for various nested levels
        let phoneDisclosure = JSONWebSelectiveDisclosure("phone", value: "+1-555-1234")
        let departmentDisclosure = JSONWebSelectiveDisclosure("department", value: "Engineering")
        let skillDisclosure = JSONWebSelectiveDisclosure(value: "Swift Programming")
        let disclosureList = try JSONWebSelectiveDisclosureList([phoneDisclosure, departmentDisclosure, skillDisclosure], hashFunction: SHA256.self)
        
        let phoneHash = phoneDisclosure.digest(using: SHA256.self)
        let departmentHash = departmentDisclosure.digest(using: SHA256.self)
        let skillHash = skillDisclosure.digest(using: SHA256.self)
        
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
    
    @Test("SD-JWT JSON flattened serialization roundtrip")
    func jsonFlattenedSerializationRoundtrip() throws {
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

        // Encode to flattened JSON format
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.jsonFlattened
        let jsonData = try encoder.encode(sdJWT)

        // Should be valid JSON with expected structure
        let json = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        #expect(json?["payload"] != nil)
        #expect(json?["protected"] != nil)
        #expect(json?["header"] != nil)
        #expect(json?["signature"] != nil)

        // The header should contain disclosures
        let header = json?["header"] as? [String: Any]
        #expect(header?["disclosures"] != nil)

        // Decode back
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(JSONWebSelectiveDisclosureToken.self, from: jsonData)

        #expect(decoded.disclosures.count == sdJWT.disclosures.count)
        #expect(decoded.payload.subject == "user123")
    }

    @Test("SD-JWT JSON general serialization roundtrip")
    func jsonGeneralSerializationRoundtrip() throws {
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

        // Encode to general JSON format
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.jsonGeneral
        let jsonData = try encoder.encode(sdJWT)

        // Should be valid JSON with signatures array
        let json = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        #expect(json?["payload"] != nil)
        #expect(json?["signatures"] != nil)

        // Decode back
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(JSONWebSelectiveDisclosureToken.self, from: jsonData)

        #expect(decoded.disclosures.count == sdJWT.disclosures.count)
        #expect(decoded.payload.subject == "user123")
    }

    @Test("SD-JWT JSON serialization with key binding")
    func jsonSerializationWithKeyBinding() throws {
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
            nonce: "test-nonce",
            audience: "https://verifier.example.com"
        )

        // Encode to flattened JSON format
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.jsonFlattened
        let jsonData = try encoder.encode(presentation)

        // The header should contain kb_jwt
        let json = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        let header = json?["header"] as? [String: Any]
        #expect(header?["kb_jwt"] != nil)

        // Decode back
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(JSONWebSelectiveDisclosureToken.self, from: jsonData)

        #expect(decoded.keyBinding != nil)
        #expect(decoded.keyBinding?.payload.nonce == "test-nonce")
    }

    @Test("SD-JWT automatic representation selection")
    func automaticRepresentationSelection() throws {
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

        // Encode with automatic representation (should choose compact for single signature)
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.automatic
        let data = try encoder.encode(sdJWT)
        let string = String(decoding: data, as: UTF8.self)

        // Should use compact format (contains ~)
        #expect(string.contains("~"))
    }

    @Test("SD-JWT compact serialization with key binding")
    func compactSerializationWithKeyBinding() throws {
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
            audience: "https://verifier.example.com"
        )

        // Encode to compact format
        let compactString = try String(presentation)

        // Should contain KB-JWT at the end (not empty after last ~)
        let components = compactString.split(separator: "~", omittingEmptySubsequences: false)
        let lastComponent = String(components.last!)
        #expect(!lastComponent.isEmpty)
        #expect(lastComponent.hasPrefix("ey")) // JWT prefix
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
        #expect(throws: CryptoKitError.self) {
            try sdJWT.jwt.verifySignature(using: wrongKey.publicKey)
        }
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Handle invalid disclosure format")
    func invalidDisclosureFormat() throws {
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: "invalid-base64!!!")
        }
        #expect(throws: DecodingError.self) {
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

    // MARK: - Disclosure Codable Tests

    @Test("Decode disclosure from encoded string")
    func decodeDisclosureFromEncodedString() throws {
        // Create a disclosure and encode it
        let original = JSONWebSelectiveDisclosure("name", value: "John Doe")
        let encoded = original.encoded

        // Decode from encoded string
        let decoded = try JSONWebSelectiveDisclosure(encoded: encoded)
        #expect(decoded.key == "name")
        #expect(decoded.value as? String == "John Doe")
    }

    @Test("Encode disclosure")
    func encodeDisclosure() throws {
        let disclosure = JSONWebSelectiveDisclosure("email", value: "test@example.com")

        // Test the encoded property
        let encoded = disclosure.encoded
        #expect(!encoded.isEmpty)
        // Should be valid base64url
        #expect(encoded.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })

        // Can decode back
        let decoded = try JSONWebSelectiveDisclosure(encoded: encoded)
        #expect(decoded.key == "email")
    }

    @Test("Disclosure with complex value types")
    func disclosureWithComplexValues() throws {
        // Test with dictionary value
        let disclosure1 = try JSONWebSelectiveDisclosure(
            "address",
            value: ["street": "123 Main", "city": "NYC"] as [String: String]
        )
        #expect(disclosure1.key == "address")

        // Test with integer value
        let disclosure2 = JSONWebSelectiveDisclosure("age", value: 25)
        #expect(disclosure2.value as? Int == 25)

        // Test with boolean value
        let disclosure3 = try JSONWebSelectiveDisclosure("verified", value: true)
        #expect(disclosure3.value as? Bool == true)

        // Test with array value
        let disclosure4 = try JSONWebSelectiveDisclosure("tags", value: ["a", "b", "c"])
        let tags = disclosure4.value as? [String]
        #expect(tags == ["a", "b", "c"])
    }

    @Test("Disclosure digest determinism")
    func disclosureDigestDeterminism() throws {
        // Same disclosure should produce same digest
        let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        let d1 = JSONWebSelectiveDisclosure("key", value: "value", salt: salt)
        let d2 = JSONWebSelectiveDisclosure("key", value: "value", salt: salt)

        #expect(d1.digest(using: SHA256.self) == d2.digest(using: SHA256.self))
        #expect(d1.encoded == d2.encoded)
    }

    @Test("Disclosure list operations")
    func disclosureListOperations() throws {
        let d1 = JSONWebSelectiveDisclosure("a", value: "1")
        let d2 = JSONWebSelectiveDisclosure("b", value: "2")
        let d3 = JSONWebSelectiveDisclosure("c", value: "3")

        var list = try JSONWebSelectiveDisclosureList([d1, d2], hashFunction: SHA256.self)
        #expect(list.count == 2)

        // Test append
        let hash = list.append(d3)
        #expect(list.count == 3)
        #expect(list[hash] == d3)

        // Test index lookup
        let d1Hash = d1.digest(using: SHA256.self)
        #expect(list.index(for: d1Hash) == 0)

        // Test remove
        list.remove(d1)
        #expect(list.count == 2)
        #expect(list.index(for: d1Hash) == nil)

        // Test remove by digest
        let d2Hash = d2.digest(using: SHA256.self)
        list.remove(digest: d2Hash)
        #expect(list.count == 1)

        // Test remove at index
        list.remove(at: 0)
        #expect(list.isEmpty)
    }

    @Test("Disclosure list append another list")
    func disclosureListAppendList() throws {
        let d1 = JSONWebSelectiveDisclosure("a", value: "1")
        let d2 = JSONWebSelectiveDisclosure("b", value: "2")

        var list1 = try JSONWebSelectiveDisclosureList([d1], hashFunction: SHA256.self)
        let list2 = try JSONWebSelectiveDisclosureList([d2], hashFunction: SHA256.self)

        try list1.append(list2)
        #expect(list1.count == 2)
    }

    @Test("Invalid disclosure decoding errors")
    func invalidDisclosureDecodingErrors() throws {
        // Invalid encoded string (not base64)
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: "not-valid-base64-at-all!!!")
        }

        // Empty encoded string
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: "")
        }

        // Valid base64 but not valid JSON inside
        let invalidJSON = Data([0x00, 0x01, 0x02]).urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: invalidJSON)
        }

        // Valid base64 but wrong array length (1 element)
        let oneElement = try JSONEncoder().encode(["only-salt"])
        let oneElementB64 = oneElement.urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: oneElementB64)
        }
    }

    // MARK: - Additional SD-JWT Tests

    @Test("SD-JWT description and debug description")
    func sdJWTDescriptions() throws {
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

        // description should be compact format
        let description = sdJWT.description
        #expect(description.contains("~"))

        // debugDescription should include detailed info
        let debugDesc = sdJWT.debugDescription
        #expect(debugDesc.contains("Signatures:"))
        #expect(debugDesc.contains("Payload:"))
        #expect(debugDesc.contains("Disclosures:"))
    }

    @Test("SD-JWT string description format")
    func sdJWTStringDescription() throws {
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

        // Description should be compact format with ~ separators
        let description = sdJWT.description
        #expect(description.contains("~"))

        // Should start with JWT header (eyJ...)
        #expect(description.hasPrefix("ey"))
    }

    @Test("SD-JWT with SHA384 hash algorithm")
    func sdJWTWithSHA384() throws {
        let issuerKey = P256.Signing.PrivateKey()

        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
        }

        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            hashAlgorithm: SHA384.self,
            using: issuerKey
        )

        #expect(sdJWT.payload.disclosureHashAlgorithm == SHA384.identifier)
    }

    @Test("SD-JWT with custom header")
    func sdJWTWithCustomHeader() throws {
        let issuerKey = P256.Signing.PrivateKey()

        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
        }

        var header = JOSEHeader()
        header.type = .sdJWT

        let sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            header: header,
            using: issuerKey
        )

        // Type should be set to sd+jwt
        #expect(sdJWT.signatures.first?.protected.type == .sdJWT)
        // Algorithm should be inferred from key
        #expect(sdJWT.signatures.first?.protected.algorithm != nil)
    }
}
