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
     "kty":"RSA",
     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB"
    }
  }
"""
    
    func testExample() throws {
        // XCTest Documenation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
        
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JsonWebTokenClaims.self, from: .init(testClaims.utf8))
        
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
        XCTAssertEqual(subJwk?["kty"], "RSA")
    }
}
