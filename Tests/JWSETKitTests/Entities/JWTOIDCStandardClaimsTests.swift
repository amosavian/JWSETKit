//
//  JWTOIDCStandardClaimsTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import XCTest
@testable import JWSETKit

final class JWTOIDCStandardClaimsTests: XCTestCase {
    let testClaims = """
    {
       "name": "Jane Doe",
       "given_name": "Jane",
       "middle_name": "F.",
       "family_name": "Doe",
       "nickname": "Jane",
       "preferred_username": "j.doe",
       "profile": "http://example.com/janedoe/profile",
       "picture": "http://example.com/janedoe/me.jpg",
       "website": "http://example.com/janedoe",
       "email": "janedoe@example.com",
       "email_verified": true,
       "gender": "female",
       "birthdate": "2000-10-31",
       "zoneinfo": "Asia/Tehran",
       "locale": "en-US",
       "phone_number": "+1 (310) 123-4567",
       "phone_number_verified": true,
       "address": {
         "street_address": "1234 Hollywood Blvd.",
         "locality": "Los Angeles",
         "region": "CA",
         "postal_code": "90210",
         "country": "US"},
       "updated_at": 1311280970
    }
    """
    
    func testEncodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = .withFullDate
        
        XCTAssertEqual(claims.name, "Jane Doe")
        XCTAssertEqual(claims.givenName, "Jane")
        XCTAssertEqual(claims.middleName, "F.")
        XCTAssertEqual(claims.familyName, "Doe")
        XCTAssertEqual(claims.nickname, "Jane")
        XCTAssertEqual(claims.preferredUsername, "j.doe")
        XCTAssertEqual(claims.profileURL, URL(string: "http://example.com/janedoe/profile"))
        XCTAssertEqual(claims.pictureURL, URL(string: "http://example.com/janedoe/me.jpg"))
        XCTAssertEqual(claims.websiteURL, URL(string: "http://example.com/janedoe"))
        XCTAssertEqual(claims.email, "janedoe@example.com")
        XCTAssertEqual(claims.isEmailVerified, true)
        XCTAssertEqual(claims.gender, "female")
        XCTAssertEqual(claims.birthdate, formatter.date(from: "2000-10-31"))
        XCTAssertEqual(claims.zoneInfo, TimeZone(abbreviation: "IRST"))
        XCTAssertEqual(claims.locale, Locale(identifier: "en_US"))
        XCTAssertEqual(claims.phoneNumber, "+1 (310) 123-4567")
        XCTAssertEqual(claims.isPhoneNumberVerified, true)
        XCTAssertEqual(claims.address, JSONWebAddress(streetAddress: "1234 Hollywood Blvd.", locality: "Los Angeles", region: "CA", postalCode: "90210", country: "US"))
        XCTAssertEqual(claims.updatedAt, Date(timeIntervalSince1970: 1_311_280_970))
    }
    
    func testDecodeParams() throws {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = .withFullDate
        
        var claims = JSONWebTokenClaims(storage: .init())
        claims.name = "Jane Doe"
        claims.givenName = "Jane"
        claims.middleName = "F."
        claims.familyName = "Doe"
        claims.nickname = "Jane"
        claims.preferredUsername = "j.doe"
        claims.profileURL = URL(string: "http://example.com/janedoe/profile")
        claims.pictureURL = URL(string: "http://example.com/janedoe/me.jpg")
        claims.websiteURL = URL(string: "http://example.com/janedoe")
        claims.email = "janedoe@example.com"
        claims.isEmailVerified = true
        claims.gender = "female"
        claims.birthdate = .init(timeIntervalSince1970: 972_950_400)
        claims.zoneInfo = TimeZone(abbreviation: "IRST")
        claims.locale = Locale(identifier: "en-US")
        claims.phoneNumber = "+1 (310) 123-4567"
        claims.isPhoneNumberVerified = true
        claims.address = JSONWebAddress(
            streetAddress: "1234 Hollywood Blvd.", locality: "Los Angeles",
            region: "CA", postalCode: "90210", country: "US"
        )
        claims.updatedAt = Date(timeIntervalSince1970: 1_311_280_970)
        
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims, decodedClaims)
    }
}
