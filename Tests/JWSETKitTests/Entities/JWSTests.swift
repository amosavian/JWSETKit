//
//  JWSTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import X509
import XCTest
import Crypto
@testable import JWSETKit

final class JWSTests: XCTestCase {
    let jws = try! JSONWebToken(
        signatures: [.init(protected: Data(urlBase64Encoded: "eyJhbGciOiJSUzI1NiJ9")!, signature: Data())],
        payload: .init(encoded: Data(
            urlBase64Encoded: "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")!)
    )
    
    let jwsDetachedString =
        "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
    
    typealias JWSDetached = JSONWebSignature<ProtectedDataWebContainer>
    
    func testSignatureHS256() throws {
        let signature = "dCfJaSBBMSnC8CXslIf5orCzS7AboBan4qE7aXuYSDs=".decoded
        let key = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        var jws = jws
        jws.signatures[0].protected.algorithm = .hmacSHA256
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureHS384() throws {
        let signature = "oXDrZsBTd6/RlkXLUTQJ0DSfHx5raR4Pq5jlRHf5v0WTm+zt8xcsCvXagNl0J4eM".decoded
        let key = try JSONWebKeyHMAC<SHA384>(ExampleKeys.symmetric)
        var jws = jws
        jws.signatures[0].protected.algorithm = .hmacSHA384
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureHS512() throws {
        let signature = "CyfHecbVPqPzB3zBwYd3rgVBi2Dgg+eAeX7JT8B85QbKLwSXyll8WKGdehse606szf9G3i+jr24QGkEtMAGSpg==".decoded
        let key = try JSONWebKeyHMAC<SHA512>(ExampleKeys.symmetric)
        var jws = jws
        jws.signatures[0].protected.algorithm = .hmacSHA512
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureES256() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .ecdsaSignatureP256SHA256
        try jws.updateSignature(using: ExampleKeys.privateEC256)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC256))
    }
    
    func testSignatureES384() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .ecdsaSignatureP384SHA384
        try jws.updateSignature(using: ExampleKeys.privateEC384)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC384))
    }
    
    func testSignatureES521() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .ecdsaSignatureP521SHA512
        try jws.updateSignature(using: ExampleKeys.privateEC521)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC521))
    }
    
    func testSignatureRS256() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .rsaSignaturePKCS1v15SHA256
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignatureRS384() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .rsaSignaturePKCS1v15SHA384
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignatureRS512() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .rsaSignaturePKCS1v15SHA512
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS256() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .rsaSignaturePSSSHA256
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS384() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .rsaSignaturePSSSHA384
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS512() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .rsaSignaturePSSSHA512
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testVerifyDates() throws {
        XCTAssertThrowsError(try jws.verifyDate())
        XCTAssertNoThrow(try jws.verifyDate(.init(timeIntervalSince1970: 1_300_819_370)))
    }
    
    func testDetached() throws {
        var jws = try JWSDetached(from: jwsDetachedString)
        XCTAssertEqual(jws.payload.encoded, Data())
        XCTAssertEqual(jwsDetachedString, jws.description)
        
        let key = try JSONWebKeyHMAC<SHA256>(importing: Data("""
        {
         "kty":"oct",
         "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }
        """.utf8), format: .jwk)
        jws.payload.encoded = Data("$.02".utf8)
        XCTAssertEqual(jwsDetachedString, jws.description)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testNone() throws {
        var jws = jws
        jws.signatures[0].protected.algorithm = .none
        jws.signatures[0].signature = .init()
        XCTAssertThrowsError(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
}
