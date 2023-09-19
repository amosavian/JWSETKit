//
//  JWTOAuthClaimsTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import XCTest
@testable import JWSETKit

final class JWTOAuthClaimsTests: XCTestCase {
    let testClaims = """
    {
      "client_id": "s6BhdRkqt3",
      "scope": "openid profile reademail"
    }
    """
    
    func testEncodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims.clientID, "s6BhdRkqt3")
        
        XCTAssertEqual(claims.scope, "openid profile reademail")
        XCTAssertEqual(claims.scopes, ["openid", "profile", "reademail"])
    }
    
    func testDecodeParams() throws {
        var claims = JSONWebTokenClaims(storage: .init())
        claims.clientID = "s6BhdRkqt3"
        claims.scopes = ["openid", "profile", "reademail"]
        
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims, decodedClaims)
    }
}
