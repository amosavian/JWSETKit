//
//  KeyLookupTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import XCTest
@testable import JWSETKit

final class KeyLookupTests: XCTestCase {
    func testJsonWebKeyNormalizer() throws {
        XCTAssertEqual("camelCase".jsonWebKey, "camel_case")
        XCTAssertEqual("clientID".jsonWebKey, "client_id")
        XCTAssertEqual("authTime".jsonWebKey, "auth_time")
    }
}
