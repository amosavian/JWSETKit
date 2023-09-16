//
//  Base64Tests.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import XCTest
@testable import JWSETKit

final class Base64Tests: XCTestCase {
    func testDecode() throws {
        let encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        let value = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
        XCTAssertEqual(Data(urlBase64Encoded: encoded), Data(value.utf8))
        
        let encoded2 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        let value2 = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        XCTAssertEqual(Data(urlBase64Encoded: encoded2), Data(value2.utf8))
    }
    
    func testEncode() throws {
        let encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        let value = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
        XCTAssertEqual(Data(value.utf8).urlBase64EncodedData(), Data(encoded.utf8))
        
        let encoded2 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        let value2 = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        XCTAssertEqual(Data(value2.utf8).urlBase64EncodedData(), Data(encoded2.utf8))
    }

    func testPerformanceDecode() throws {
        self.measure {
            let encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
            for _ in 1...10000 {
                let _ = Data(urlBase64Encoded: encoded)
            }
        }
    }
}
