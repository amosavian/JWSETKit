//
//  SDJWTNegativeTests.swift
//
//
//  Created by Claude on 12/13/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

/// Tests for invalid SD-JWT inputs and validation errors
@Suite("SD-JWT Negative Tests")
struct SDJWTNegativeTests {
    // MARK: - Invalid Disclosure Format Tests
    
    @Test("Invalid disclosure base64 should fail")
    func invalidDisclosureBase64() throws {
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: "!!!invalid_base64!!!")
        }
    }
    
    @Test("Disclosure with invalid JSON should fail")
    func invalidDisclosureJSON() throws {
        // Base64 of "not json"
        let encoded = Data("not json".utf8).urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: encoded)
        }
    }
    
    @Test("Disclosure with wrong array length should fail")
    func disclosureWrongArrayLength() throws {
        // Array with only 1 element (should be 2 or 3)
        let singleElement = Data("[\"salt\"]".utf8).urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: singleElement)
        }
        
        // Array with 4 elements
        let fourElements = Data("[\"salt\",\"key\",\"value\",\"extra\"]".utf8).urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: fourElements)
        }
    }
    
    @Test("Disclosure with non-string salt should fail")
    func disclosureNonStringSalt() throws {
        // Salt is not a string
        let encoded = Data("[123,\"key\",\"value\"]".utf8).urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: encoded)
        }
    }
    
    @Test("Disclosure with non-string key should fail")
    func disclosureNonStringKey() throws {
        // Key is not a string (for object disclosure)
        let encoded = Data("[\"salt\",123,\"value\"]".utf8).urlBase64EncodedString()
        #expect(throws: DecodingError.self) {
            try JSONWebSelectiveDisclosure(encoded: encoded)
        }
    }
    
    // MARK: - _sd_alg Tests
    
    @Test("Present-but-unknown _sd_alg must throw, not silently default to SHA-256")
    func unknownDisclosureHashAlgorithm() throws {
        let issuerKey = P256.Signing.PrivateKey()
        let claims = try JSONWebTokenClaims {
            $0.subject = "user123"
            $0.email = "john.doe@example.com"
        }
        var sdJWT = try JSONWebSelectiveDisclosureToken(
            claims: claims,
            concealedPaths: ["/email"],
            using: issuerKey
        )
        sdJWT.payload.value.disclosureHashAlgorithm = "sha-1"
        
        #expect(throws: JSONWebKeyError.self) {
            _ = try sdJWT.disclosureList
        }
    }
    
    @Test("Absent _sd_alg defaults to SHA-256")
    func absentDisclosureHashAlgorithm() throws {
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
        #expect(sdJWT.payload.value.storage["_sd_alg"] as String? == nil)
        #expect(sdJWT.payload.disclosureHashAlgorithm == SHA256.identifier)
        #expect(throws: Never.self) {
            _ = try sdJWT.disclosureList
        }
    }
    
    // MARK: - Disclosure Creation Tests
    
    @Test("Disclosure with very long value")
    func veryLongDisclosureValue() throws {
        let longValue = String(repeating: "a", count: 100_000)
        let disclosure = JSONWebSelectiveDisclosure("data", value: longValue)
        
        // Should work
        #expect(disclosure.key == "data")
        #expect(disclosure.value as? String == longValue)
        
        // Should round-trip
        let decoded = try JSONWebSelectiveDisclosure(encoded: disclosure.encoded)
        #expect(decoded.value as? String == longValue)
    }
    
    @Test("Disclosure with unicode value")
    func unicodeDisclosureValue() throws {
        let unicodeValue = "测试数据 🔐 العربية"
        let disclosure = JSONWebSelectiveDisclosure("data", value: unicodeValue)
        
        #expect(disclosure.value as? String == unicodeValue)
        
        let decoded = try JSONWebSelectiveDisclosure(encoded: disclosure.encoded)
        #expect(decoded.value as? String == unicodeValue)
    }
    
    @Test("Disclosure list creation")
    func disclosureList() throws {
        var disclosures: [JSONWebSelectiveDisclosure] = []
        for i in 0 ..< 10 {
            disclosures.append(JSONWebSelectiveDisclosure("field\(i)", value: "value\(i)"))
        }
        
        let list = try JSONWebSelectiveDisclosureList(disclosures, hashFunction: SHA256.self)
        #expect(list.disclosures.count == 10)
    }
    
    // MARK: - Edge Cases
    
    @Test("Empty disclosure list is valid")
    func emptyDisclosureList() throws {
        let list = try JSONWebSelectiveDisclosureList([], hashFunction: SHA256.self)
        #expect(list.disclosures.isEmpty)
    }
    
    @Test("Disclosure with null value")
    func disclosureWithNullValue() throws {
        // Array disclosure with null value
        let encoded = Data("[\"salt\",null]".utf8).urlBase64EncodedString()
        
        let disclosure = try JSONWebSelectiveDisclosure(encoded: encoded)
        #expect(disclosure.key == nil) // Array disclosure has no key
    }
    
    @Test("Disclosure with boolean values")
    func disclosureWithBooleanValue() throws {
        let trueEncoded = Data("[\"salt\",\"flag\",true]".utf8).urlBase64EncodedString()
        let trueDisclosure = try JSONWebSelectiveDisclosure(encoded: trueEncoded)
        #expect(trueDisclosure.key == "flag")
        #expect(trueDisclosure.value as? Bool == true)
        
        let falseEncoded = Data("[\"salt\",\"flag\",false]".utf8).urlBase64EncodedString()
        let falseDisclosure = try JSONWebSelectiveDisclosure(encoded: falseEncoded)
        #expect(falseDisclosure.value as? Bool == false)
    }
    
    @Test("Disclosure with numeric values")
    func disclosureWithNumericValue() throws {
        let intEncoded = Data("[\"salt\",\"age\",42]".utf8).urlBase64EncodedString()
        let intDisclosure = try JSONWebSelectiveDisclosure(encoded: intEncoded)
        #expect(intDisclosure.key == "age")
        #expect(intDisclosure.value as? Int == 42)
        
        let floatEncoded = Data("[\"salt\",\"score\",99.5]".utf8).urlBase64EncodedString()
        let floatDisclosure = try JSONWebSelectiveDisclosure(encoded: floatEncoded)
        #expect(floatDisclosure.key == "score")
        #expect(floatDisclosure.value as? Double == 99.5)
    }
    
    @Test("Disclosure with array value")
    func disclosureWithArrayValue() throws {
        let encoded = Data("[\"salt\",\"tags\",[\"a\",\"b\",\"c\"]]".utf8).urlBase64EncodedString()
        let disclosure = try JSONWebSelectiveDisclosure(encoded: encoded)
        #expect(disclosure.key == "tags")
        
        let values = disclosure.value as? [String]
        #expect(values == ["a", "b", "c"])
    }
}
