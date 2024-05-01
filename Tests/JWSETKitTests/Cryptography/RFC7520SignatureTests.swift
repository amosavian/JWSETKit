//
//  RFC7520SignatureTests.swift
//
//
//  Created by Amir Abbas Mousavian on 1/5/24.
//

import XCTest
@testable import JWSETKit
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

typealias JWS = JSONWebSignature<ProtectedDataWebContainer>
final class RFC7520Tests: XCTestCase {
    let payload = """
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4
    """
    
    func testSignatureSignRS256() throws {
        let jwsString = """
        eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
        hhbXBsZSJ9\
        .\(payload).
        """
        let signature = """
        MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK\
        ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J\
        IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w\
        W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP\
        xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f\
        cIe8u9ipH84ogoree7vjbU5y18kDquDg
        """
        var jws = JWS(jwsString)!
        try jws.updateSignature(using: RFC7520ExampleKeys.rsaPrivateKey.signingKey)
        XCTAssertEqual(jws.signatures[0].signature, signature.decoded)
    }
    
    func testSignatureVerifyRS256() throws {
        let jwsString = """
        eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
        hhbXBsZSJ9\
        .\(payload).\
        MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK\
        ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J\
        IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w\
        W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP\
        xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f\
        cIe8u9ipH84ogoree7vjbU5y18kDquDg
        """
        let jws = JWS(jwsString)!
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.rsaPublicKey.validatingKey))
    }
    
    func testSignatureSignPS384() throws {
        let jwsString = """
        eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
        hhbXBsZSJ9\
        .\(payload).
        """
        var jws = JWS(jwsString)!
        try jws.updateSignature(using: RFC7520ExampleKeys.rsaPrivateKey.signingKey)
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.rsaPublicKey.validatingKey))
    }
    
    func testSignatureVerifyPS384() throws {
        let jwsString = """
        eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
        hhbXBsZSJ9\
        .\(payload).\
        cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I\
        pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU\
        vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX\
        e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT\
        0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a\
        6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw
        """
        let jws = JWS(jwsString)!
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.rsaPublicKey.validatingKey))
    }
    
    func testSignatureSignES521() throws {
        let jwsString = """
        eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
        hhbXBsZSJ9\
        .\(payload).
        """
        var jws = JWS(jwsString)!
        try jws.updateSignature(using: RFC7520ExampleKeys.ecPrivateKey.signingKey)
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.ecPublicKey.validatingKey))
    }
    
    func testSignatureVerifyES521() throws {
        let jwsString = """
        eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX\
        hhbXBsZSJ9\
        .\(payload).\
        AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb\
        u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv\
        AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2
        """
        let jws = JWS(jwsString)!
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.ecPublicKey.validatingKey))
    }
    
    func testSignatureSignHS256() throws {
        let jwsString = """
        eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW\
        VlZjMxNGJjNzAzNyJ9\
        .\(payload).
        """
        let signature = """
        s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0
        """
        var jws = JWS(jwsString)!
        try jws.updateSignature(using: RFC7520ExampleKeys.macSymmetricKey.signingKey)
        XCTAssertEqual(jws.signatures[0].signature, signature.decoded)
    }
    
    func testSignatureVerifyHS256() throws {
        let jwsString = """
        eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW\
        VlZjMxNGJjNzAzNyJ9\
        .\(payload).\
        s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0
        """
        let jws = JWS(jwsString)!
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.macSymmetricKey.validatingKey))
    }
    
    func testSignatureDeteched() throws {
        let jwsString = """
        eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW\
        VlZjMxNGJjNzAzNyJ9\
        ..\
        s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0
        """
        let jws = JWS(jwsString)!
        XCTAssertEqual(jws.payload.encoded, .init())
        
        let encoder = JSONEncoder()
        encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.jsonFlattened
        let jwsFlattened = try encoder.encode(jws)
        let jwsFlattenedValue = try JSONDecoder().decode(JSONWebValueStorage.self, from: jwsFlattened)
        XCTAssertFalse(jwsFlattenedValue.contains(key: "payload"))
        
        encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.jsonGeneral
        let jwsJSON = try encoder.encode(jws)
        let jwsJSONValue = try JSONDecoder().decode(JSONWebValueStorage.self, from: jwsJSON)
        XCTAssertFalse(jwsJSONValue.contains(key: "payload"))
    }
    
    func testSignatureUnprotectedHeader() throws {
        let jws = try JWS(signatures: [
            .init(protected: "eyJhbGciOiJIUzI1NiJ9".decoded,
                  unprotected: .init { $0.keyId = "018c0ae5-4d9b-471b-bfd6-eef314bc7037" },
                  signature: "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20".decoded),
        ], payload: .init(encoded: payload.decoded))
        
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.macSymmetricKey.validatingKey))
        
        let encoder = JSONEncoder()
        let jwsFlattened = try encoder.encode(jws)
        let jwsFlattenedValue = try JSONDecoder().decode(JSONWebValueStorage.self, from: jwsFlattened)
        XCTAssertTrue(jwsFlattenedValue.contains(key: "header"))
        XCTAssertEqual((jwsFlattenedValue.header as JOSEHeader?)?.keyId, "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
        
        encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.jsonGeneral
        let jwsJSON = try encoder.encode(jws)
        let jwsJSONValue = try JSONDecoder().decode(JSONWebValueStorage.self, from: jwsJSON)
        XCTAssertTrue(jwsJSONValue.contains(key: "signatures"))
        XCTAssertEqual((jwsJSONValue.signatures as [JSONWebSignatureHeader]?)?.first?.unprotected?.keyId, "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
    }
    
    func testSignatureProtectedContentOnly() throws {
        let jws = try JWS(signatures: [
            .init(protected: JOSEHeader(),
                  unprotected: .init {
                      $0.algorithm = JSONWebSignatureAlgorithm.hmacSHA256
                      $0.keyId = "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
                  },
                  signature: "xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk".decoded),
        ], payload: .init(encoded: payload.decoded))
        
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.macSymmetricKey.validatingKey, strict: false))
        
        let encoder = JSONEncoder()
        let jwsFlattened = try encoder.encode(jws)
        let jwsFlattenedValue = try JSONDecoder().decode(JSONWebValueStorage.self, from: jwsFlattened)
        XCTAssertTrue(jwsFlattenedValue.contains(key: "header"))
        let jwsFlattenedHeader = jwsFlattenedValue.header as JOSEHeader?
        XCTAssert(jwsFlattenedHeader?.algorithm == .hmacSHA256)
        XCTAssertEqual(jwsFlattenedHeader?.keyId, "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
        
        encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.jsonGeneral
        let jwsJSON = try encoder.encode(jws)
        let jwsJSONValue = try JSONDecoder().decode(JSONWebValueStorage.self, from: jwsJSON)
        XCTAssertTrue(jwsJSONValue.contains(key: "signatures"))
        XCTAssertEqual((jwsJSONValue.signatures as [JSONWebSignatureHeader]?)?.first?.unprotected?.keyId, "018c0ae5-4d9b-471b-bfd6-eef314bc7037")
    }
    
    func testMultipleSignatures() throws {
        let jwsString = """
        {
             "payload": "\(payload)",
             "signatures": [
               {
                 "protected": "eyJhbGciOiJSUzI1NiJ9",
                 "header": {
                   "kid": "bilbo.baggins@hobbiton.example"
                 },
                 "signature": "MIsjqtVlOpa71KE-Mss8_Nq2YH4FGhiocsqrgi5Nvy\
        G53uoimic1tcMdSg-qptrzZc7CG6Svw2Y13TDIqHzTUrL_lR2ZFc\
        ryNFiHkSw129EghGpwkpxaTn_THJTCglNbADko1MZBCdwzJxwqZc\
        -1RlpO2HibUYyXSwO97BSe0_evZKdjvvKSgsIqjytKSeAMbhMBdM\
        ma622_BG5t4sdbuCHtFjp9iJmkio47AIwqkZV1aIZsv33uPUqBBC\
        XbYoQJwt7mxPftHmNlGoOSMxR_3thmXTCm4US-xiNOyhbm8afKK6\
        4jU6_TPtQHiJeQJxz9G3Tx-083B745_AfYOnlC9w"
               },
               {
                 "header": {
                   "alg": "ES512",
                   "kid": "bilbo.baggins@hobbiton.example"
                 },
                 "signature": "ARcVLnaJJaUWG8fG-8t5BREVAuTY8n8YHjwDO1muhc\
        dCoFZFFjfISu0Cdkn9Ybdlmi54ho0x924DUz8sK7ZXkhc7AFM8Ob\
        LfTvNCrqcI3Jkl2U5IX3utNhODH6v7xgy1Qahsn0fyb4zSAkje8b\
        AWz4vIfj5pCMYxxm4fgV3q7ZYhm5eD"
               },
               {
                 "protected": "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LT\
        RkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9",
                 "signature": "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
               }
             ]
           }
        """
        
        let jws = try JSONDecoder().decode(JWS.self, from: jwsString.data)
        XCTAssertEqual(jws.signatures.count, 3)
        
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.rsaPublicKey.validatingKey))
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.ecPublicKey.validatingKey, strict: false))
        XCTAssertNoThrow(try jws.verifySignature(using: RFC7520ExampleKeys.macSymmetricKey.validatingKey))
    }
}
