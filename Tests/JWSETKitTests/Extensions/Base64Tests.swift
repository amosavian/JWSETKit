//
//  Base64Tests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation
import Testing
@testable import JWSETKit

struct Base64Tests {
    @Test
    func decode() {
        let encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        let value = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
        #expect(Data(urlBase64Encoded: encoded) == Data(value.utf8))
        
        let encoded2 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        let value2 = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        #expect(Data(urlBase64Encoded: encoded2) == Data(value2.utf8))
    }
    
    @Test
    func decodeIgnoresEmbeddedWhitespace() {
        // 4 bytes → 6 Base64url chars → 2 `=` of padding. Embedded whitespace (line-wrapped
        // `n`/`x5c` from multi-line literals or PEM wrapping) must not inflate the length used
        // to compute that padding — otherwise strict decoders (swift-corelibs-foundation on
        // Linux) reject the result while Darwin tolerates it.
        let expected = Data([0x01, 0x02, 0x03, 0x04])
        #expect(Data(urlBase64Encoded: "AQIDBA") == expected)
        #expect(Data(urlBase64Encoded: "AQ IDBA", options: .ignoreUnknownCharacters) == expected)
        #expect(Data(urlBase64Encoded: "AQ\n    ID\r\nBA", options: .ignoreUnknownCharacters) == expected)
        // Standard Base-64 (`+`/`/`, with padding) wrapped across lines also decodes.
        #expect(Data(base64Encoded: "AQ ID\nBA==", options: .ignoreUnknownCharacters) == expected)
        // Strict decoding still rejects embedded whitespace.
        #expect(Data(urlBase64Encoded: "AQ IDBA", options: []) == nil)
    }

    @Test
    func encode() {
        let encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        let value = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
        #expect(Data(value.utf8).urlBase64EncodedData() == Data(encoded.utf8))
        
        let encoded2 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        let value2 = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        #expect(Data(value2.utf8).urlBase64EncodedData() == Data(encoded2.utf8))
    }
}
