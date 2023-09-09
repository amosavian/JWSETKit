import XCTest
@testable import JWSETKit

final class JWTTest: XCTestCase {
    let testClaims = """
{
   "iss": "https://self-issued.me",
   "sub": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
   "aud": "https://client.example.org/cb",
   "nonce": "n-0S6_WzA2Mj",
   "exp": 1311281970,
   "iat": 1311280970,
   "address": {
      "street_address": "1234 Hollywood Blvd.",
      "locality": "Los Angeles",
      "region": "CA",
      "postal_code": "90210",
      "country": "US"
   },
   "phone_number": "+1 (310) 123-4567",
   "phone_number_verified": true,
   "profile#fa": "https://users.example.org/fa",
   "zoneinfo": "Asia/Tehran",
   "sub_jwk": {
      "kty":"EC",
      "crv":"P-256",
      "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
   }
}
"""
    
    func testDecodeClaims() throws {
        // XCTest Documenation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
        
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JSONWebTokenClaims.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims.issuer, "https://self-issued.me")
        XCTAssertEqual(claims.issuerURL, URL(string: "https://self-issued.me"))
        
        XCTAssertEqual(claims.issuedAt, Date(timeIntervalSince1970: 1311280970))
        XCTAssertEqual(claims.iat, Date(timeIntervalSince1970: 1311280970))
        XCTAssertEqual(claims.iat, 1311280970)
        
        XCTAssertEqual(claims.nonce, "n-0S6_WzA2Mj")
        XCTAssertEqual(claims.isPhoneNumberVerified, true)
        XCTAssertEqual(claims.zoneInfo, .init(identifier: "Asia/Tehran"))
        XCTAssertEqual(claims.zoneInfo, .init(abbreviation: "IRST"))
        XCTAssertEqual(claims.address?.country, "US")
        XCTAssertEqual(claims["profile#fa"], "https://users.example.org/fa")
        
        let subJwk = claims.subJwk as [String: String]?
        XCTAssertEqual(subJwk?["kty"], "EC")
        
        let subJWK = claims.subJwk as (any JSONWebKey)?
        XCTAssertEqual(subJWK?.keyType, .elipticCurve)
    }
}
