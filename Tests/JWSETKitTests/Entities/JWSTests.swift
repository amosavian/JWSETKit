//
//  JWSTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import X509
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import JWSETKit

final class JWSTests: XCTestCase {
    let jws = try! JSONWebToken(
        signatures: [.init(protected: Data(urlBase64Encoded: "eyJhbGciOiJSUzI1NiJ9")!, signature: Data())],
        payload: .init(encoded: Data(
            urlBase64Encoded: "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")!)
    )
    
    func testSignatureHS256() throws {
        let signature = Data(base64Encoded: "dCfJaSBBMSnC8CXslIf5orCzS7AboBan4qE7aXuYSDs=")
        let key = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .hmacSHA256
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureHS384() throws {
        let signature = Data(base64Encoded: "oXDrZsBTd6/RlkXLUTQJ0DSfHx5raR4Pq5jlRHf5v0WTm+zt8xcsCvXagNl0J4eM")
        let key = try JSONWebKeyHMAC<SHA384>(ExampleKeys.symmetric)
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .hmacSHA384
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureHS512() throws {
        let signature = Data(base64Encoded: "CyfHecbVPqPzB3zBwYd3rgVBi2Dgg+eAeX7JT8B85QbKLwSXyll8WKGdehse606szf9G3i+jr24QGkEtMAGSpg==")
        let key = try JSONWebKeyHMAC<SHA512>(ExampleKeys.symmetric)
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .hmacSHA512
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureES256() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .ecdsaSignatureP256SHA256
        try jws.updateSignature(using: ExampleKeys.privateEC256)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC256))
    }
    
    func testSignatureES384() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .ecdsaSignatureP384SHA384
        try jws.updateSignature(using: ExampleKeys.privateEC384)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC384))
    }
    
    func testSignatureES521() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .ecdsaSignatureP521SHA512
        try jws.updateSignature(using: ExampleKeys.privateEC521)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC521))
    }
    
    func testSignatureRS256() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .rsaSignaturePKCS1v15SHA256
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignatureRS384() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .rsaSignaturePKCS1v15SHA384
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignatureRS512() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .rsaSignaturePKCS1v15SHA512
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS256() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .rsaSignaturePSSSHA256
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS384() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .rsaSignaturePSSSHA384
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS512() throws {
        var jws = jws
        jws.signatures[0].protected.value.algorithm = .rsaSignaturePSSSHA512
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testVerifyDates() throws {
        XCTAssertThrowsError(try jws.verifyDate())
        XCTAssertNoThrow(try jws.verifyDate(.init(timeIntervalSince1970: 1_300_819_370)))
    }
}
