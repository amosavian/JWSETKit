//
//  JWTTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/21/23.
//

import Foundation
import XCTest
@testable import JWSETKit

final class JWTTests: XCTestCase {
    let jwtString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiZ29vZ2xlLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMiwibmJmIjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDkwMjJ9.vGoQSvaLlU1lh_rsJT-vCPG6DNe_a9rHeJiezXRswKQ"
    
    func testDecode() throws {
        let jwt = try JSONWebToken(from: jwtString)
        XCTAssert(jwt.signatures.first?.protected.value.algorithm == .hmacSHA256)
        XCTAssertEqual(jwt.payload.value.issuedAt, Date(timeIntervalSince1970: 1_516_239_022))
        XCTAssertNoThrow(try jwt.verifySignature(using: ExampleKeys.symmetric))
    }
    
    func testEncode() throws {
        let jwt = try JSONWebToken(from: jwtString)
        XCTAssertEqual(try String(jws: jwt), jwtString)
        XCTAssertEqual(jwt.description, jwtString)
    }
    
    func testInit() throws {
        let payload = try JSONWebTokenClaims { container in
            container.issuedAt = .init()
            container.expiry = .init(timeIntervalSinceNow: 3600)
            container.jwtUUID = .init()
        }
        let jwt = try JSONWebToken(payload: payload, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        XCTAssertNoThrow(try jwt.verifySignature(using: JSONWebKeySet(keys: [ExampleKeys.symmetric])))
    }
    
    func testVerify() throws {
        let jwt = try JSONWebToken(from: jwtString)
        XCTAssertNoThrow(try jwt.verifyDate(.init(timeIntervalSince1970: 1_516_239_024)))
        XCTAssertThrowsError(try jwt.verifyDate(.init(timeIntervalSince1970: 1_516_239_021)))
        XCTAssertThrowsError(try jwt.verifyDate(.init(timeIntervalSince1970: 1_516_249_024)))
        XCTAssertNoThrow(try jwt.verifyAudience(includes: "google.com"))
        XCTAssertThrowsError(try jwt.verifyAudience(includes: "yahoo.com"))
    }

#if canImport(Foundation.NSURLSession)
    func testAuthorization() throws {
        let jwt = try JSONWebToken(from: jwtString)
        var request = URLRequest(url: .init(string: "https://www.example.com/")!)
        request.authorizationToken = jwt
        XCTAssertEqual(request.authorizationToken, jwt)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(jwtString)")
    }
#endif
}
