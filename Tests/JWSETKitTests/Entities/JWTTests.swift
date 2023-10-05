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
    let jwtString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SVT7VUK8eOve-SCacPaU_bkzT3SFr9wk5EQciofG4Qo"
    
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

#if canImport(Foundation.NSURLSession)
    func testAuthorization() throws {
        let jwt = try JSONWebToken(from: jwtString)
        var request = URLRequest(url: .init(string: "https://www.example.com.")!)
        request.authorizationToken = jwt
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(jwtString)")
    }
#endif
}
