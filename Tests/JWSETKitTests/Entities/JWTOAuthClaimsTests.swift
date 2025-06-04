//
//  JWTOAuthClaimsTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct JWTOAuthClaimsTests {
    let testClaims = """
    {
      "client_id": "s6BhdRkqt3",
      "scope": "openid profile reademail"
    }
    """
    
    @Test
    func encodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        #expect(claims.clientID == "s6BhdRkqt3")
        
        #expect(claims.scope == "openid profile reademail")
        #expect(claims.scopes == ["openid", "profile", "reademail"])
    }
    
    @Test
    func decodeParams() throws {
        var claims = JSONWebTokenClaims(storage: .init())
        claims.clientID = "s6BhdRkqt3"
        claims.scopes = ["openid", "profile", "reademail"]
        
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        #expect(claims == decodedClaims)
    }
}
