//
//  JWTRegisteredClaimsTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import Foundation
import Testing
@testable import JWSETKit

#if canImport(Darwin)
extension JSONWebContainerCustomParameters {
    var iat: Date? { fatalError() }
}
#endif

@Suite
struct JWTRegisteredClaimsTests {
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
    
    @Test
    func decodeClaims() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        #expect(claims.issuer == "https://self-issued.me")
        #expect(claims.issuerURL == URL(string: "https://self-issued.me"))
        
        #expect(claims.subject == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        #expect(claims.subjectURL?.host == nil)
        
        #expect(claims.audience == ["https://client.example.org/cb"])
        #expect(claims.audienceURL == [URL(string: "https://client.example.org/cb")!])
        
        #expect(claims.expiry == Date(timeIntervalSince1970: 1_311_281_970))
        #expect(claims.exp == Date(timeIntervalSince1970: 1_311_281_970))
        #expect(claims["exp"] == 1_311_281_970)
        
        #expect(claims.issuedAt == Date(timeIntervalSince1970: 1_311_280_970))
        #expect(claims.iat == Date(timeIntervalSince1970: 1_311_280_970))
        #expect(claims["iat"] == 1_311_280_970)
        
        #expect(claims.notBefore == Date(timeIntervalSince1970: 1_311_280_970))
        #expect(claims["nbf"] == Date(timeIntervalSince1970: 1_311_280_970))
        #expect(claims.nbf == 1_311_280_970)
        
        #expect(claims.jwtId == "88150e93-6dc8-4a7a-bb47-8b6052d62875")
        #expect(claims.jwtUUID == UUID(uuidString: "88150E93-6DC8-4A7A-BB47-8B6052D62875"))
    }
    
    @Test
    func encodeClaims() throws {
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
        
        #expect(claims["exp"] == 1_311_281_970)
        #expect(claims == decodedClaims)
    }
}
