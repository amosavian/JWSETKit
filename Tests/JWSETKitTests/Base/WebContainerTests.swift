//
//  WebContainerTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct WebContainerTests {
    let protected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    
    @Test
    func testProtected() throws {
        let container = try ProtectedJSONWebContainer<JSONWebTokenClaims>(encoded: .init(
            urlBase64Encoded: protected)!)
        #expect(container.value.issuer == "joe")
        #expect(container.value.expiry == Date(timeIntervalSince1970: 1_300_819_380))
        #expect(container.value["http://example.com/is_root"] == true)
        #expect(container.encoded == .init(urlBase64Encoded: protected)!)
    }
}
