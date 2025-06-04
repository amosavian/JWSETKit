//
//  JWTOIDCAuthClaimsTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct JWTOIDCAuthClaimsTests {
    let testClaims = """
    {
       "azp": "s6BhdRkqt3",
       "nonce": "n-0S6_WzA2Mj",
       "auth_time": 1311280969,
       "acr": "urn:mace:incommon:iap:silver",
       "amr": ["password", "otp"],
       "at_hash": "77QmUPtjPfzWtF2AnpK9RQ",
       "c_hash": "LDktKdoQak3Pk0cnXxCltA"
    }
    """
    
    @Test
    func encodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        #expect(claims.authorizedParty == "s6BhdRkqt3")
        #expect(claims.nonce == "n-0S6_WzA2Mj")
        #expect(claims.authTime == Date(timeIntervalSince1970: 1_311_280_969))
        #expect(claims.authenticationContextClassReference == "urn:mace:incommon:iap:silver")
        #expect(claims.authenticationMethodsReferences == ["password", "otp"])
        #expect(claims.accessTokenHash == Data(urlBase64Encoded: "77QmUPtjPfzWtF2AnpK9RQ"))
        #expect(claims.codeHash == Data(urlBase64Encoded: "LDktKdoQak3Pk0cnXxCltA"))
    }
    
    @Test
    func decodeParams() throws {
        var claims = JSONWebTokenClaims(storage: .init())
        claims.authorizedParty = "s6BhdRkqt3"
        claims.nonce = "n-0S6_WzA2Mj"
        claims.authTime = Date(timeIntervalSince1970: 1_311_280_969)
        claims.authenticationContextClassReference = "urn:mace:incommon:iap:silver"
        claims.authenticationMethodsReferences = ["password", "otp"]
        claims.accessTokenHash = Data(urlBase64Encoded: "77QmUPtjPfzWtF2AnpK9RQ")
        claims.codeHash = Data(urlBase64Encoded: "LDktKdoQak3Pk0cnXxCltA")
        
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        #expect(claims == decodedClaims)
    }
}
