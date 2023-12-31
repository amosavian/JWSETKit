//
//  WebContainerTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import XCTest
@testable import JWSETKit

final class WebContainerTests: XCTestCase {
    let protected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    
    func testProtected() throws {
        let container = try ProtectedJSONWebContainer<JSONWebTokenClaims>(encoded: .init(
            urlBase64Encoded: protected)!)
        XCTAssertEqual(container.value.issuer, "joe")
        XCTAssertEqual(container.value.expiry, Date(timeIntervalSince1970: 1_300_819_380))
        XCTAssertEqual(container.value["http://example.com/is_root"], true)
        XCTAssertEqual(container.encoded, .init(urlBase64Encoded: protected)!)
    }
}
