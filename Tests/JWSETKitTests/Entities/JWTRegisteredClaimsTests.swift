//
//  JWTRegisteredClaimsTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import XCTest
@testable import JWSETKit

final class JWTRegisteredClaimsTests: XCTestCase {
    let testClaims = """
    {
       "iss": "https://self-issued.me",
       "sub": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
       "aud": "https://client.example.org/cb",
       "exp": 1311281970,
       "iat": 1311280970,
       "nbf": 1311280970,
       "jti": "88150e93-6dc8-4a7a-bb47-8b6052d62875"
    }
    """
    
    func testDecodeClaims() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims.issuer, "https://self-issued.me")
        XCTAssertEqual(claims.issuerURL, URL(string: "https://self-issued.me"))
        
        XCTAssertEqual(claims.subject, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        XCTAssertEqual(claims.subjectURL?.host, nil)
        
        XCTAssertEqual(claims.audience, ["https://client.example.org/cb"])
        XCTAssertEqual(claims.audienceURL, [URL(string: "https://client.example.org/cb")!])
        
        XCTAssertEqual(claims.expiry, Date(timeIntervalSince1970: 1_311_281_970))
        XCTAssertEqual(claims.exp, Date(timeIntervalSince1970: 1_311_281_970))
        XCTAssertEqual(claims.exp, 1_311_281_970)
        
        XCTAssertEqual(claims.issuedAt, Date(timeIntervalSince1970: 1_311_280_970))
        XCTAssertEqual(claims.iat, Date(timeIntervalSince1970: 1_311_280_970))
        XCTAssertEqual(claims.iat, 1_311_280_970)
        
        XCTAssertEqual(claims.notBefore, Date(timeIntervalSince1970: 1_311_280_970))
        XCTAssertEqual(claims.nbf, Date(timeIntervalSince1970: 1_311_280_970))
        XCTAssertEqual(claims.nbf, 1_311_280_970)
        
        XCTAssertEqual(claims.jwtId, "88150e93-6dc8-4a7a-bb47-8b6052d62875")
        XCTAssertEqual(claims.jwtUUID, UUID(uuidString: "88150E93-6DC8-4A7A-BB47-8B6052D62875"))
    }
    
    func testEncodeClaims() throws {
        var claims = JSONWebTokenClaims(storage: .init())
        claims.issuerURL = URL(string: "https://self-issued.me")
        claims.subject = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        claims.audienceURL = [URL(string: "https://client.example.org/cb")!]
        claims.expiry = Date(timeIntervalSince1970: 1_311_281_970)
        claims.issuedAt = Date(timeIntervalSince1970: 1_311_280_970)
        claims.notBefore = Date(timeIntervalSince1970: 1_311_280_970)
        claims.jwtUUID = UUID(uuidString: "88150E93-6DC8-4A7A-BB47-8B6052D62875")
        
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims.exp, 1_311_281_970)
        XCTAssertEqual(claims, decodedClaims)
    }
}
