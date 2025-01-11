//
//  KeyLookupTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct KeyLookupTests {
    @Test
    func testJsonWebKeyNormalizer() throws {
        #expect("camelCase".jsonWebKey == "camel_case")
        #expect("clientID".jsonWebKey == "client_id")
        #expect("authTime".jsonWebKey == "auth_time")
    }
}
