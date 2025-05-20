//
//  JWTTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/21/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct JWTTests {
    let jwtString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiZ29vZ2xlLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMiwibmJmIjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDkwMjJ9.vGoQSvaLlU1lh_rsJT-vCPG6DNe_a9rHeJiezXRswKQ"
    
    @Test
    func testDecode() throws {
        let jwt = try JSONWebToken(from: jwtString)
        #expect(jwt.signatures.first?.protected.algorithm == .hmacSHA256)
        #expect(jwt.payload.value.issuedAt == Date(timeIntervalSince1970: 1_516_239_022))
        #expect(throws: Never.self) { try jwt.verifySignature(using: ExampleKeys.symmetric) }
    }
    
    @Test
    func testEncode() throws {
        let jwt = try JSONWebToken(from: jwtString)
        #expect(try String(jwt) == jwtString)
        #expect(jwt.description == jwtString)
    }
    
    @Test
    func testInit() throws {
        let payload = try JSONWebTokenClaims { container in
            container.issuedAt = .init()
            container.expiry = .init(timeIntervalSinceNow: 3600)
            container.jwtUUID = .init()
        }
        let jwt = try JSONWebToken(payload: payload, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        #expect(throws: Never.self) { try jwt.verifySignature(using: JSONWebKeySet(keys: [ExampleKeys.symmetric])) }
    }
    
    @Test
    func testVerify() throws {
        let jwt = try JSONWebToken(from: jwtString)
        #expect(throws: Never.self) { try jwt.verifyDate(.init(timeIntervalSince1970: 1_516_239_024)) }
        #expect(throws: JSONWebValidationError.self) { try jwt.verifyDate(.init(timeIntervalSince1970: 1_516_239_021)) }
        #expect(throws: JSONWebValidationError.self) { try jwt.verifyDate(.init(timeIntervalSince1970: 1_516_249_024)) }
        #expect(throws: Never.self) { try jwt.verifyAudience(includes: "google.com") }
        #expect(throws: JSONWebValidationError.self) { try jwt.verifyAudience(includes: "yahoo.com") }
    }

#if canImport(Foundation.NSURLSession)
    @Test
    func testAuthorization() throws {
        let jwt = try JSONWebToken(from: jwtString)
        var request = URLRequest(url: .init(string: "https://www.example.com/")!)
        request.authorizationToken = jwt
        #expect(request.authorizationToken == jwt)
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(jwtString)")
    }
#endif
}
