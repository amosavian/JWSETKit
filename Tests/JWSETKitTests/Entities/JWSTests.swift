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
        signatures: [.init(header: Data(urlBase64Encoded: "eyJhbGciOiJSUzI1NiJ9")!, unprotectedHeader: nil, signature: Data())],
        payload: .init(protected: Data(
            urlBase64Encoded: "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")!)
    )
    
    func testSignatureHS256() throws {
        let signature = Data(base64Encoded: "kPJsVyAmQ4DGGRjTQ2HO0l1WzypM3Ewvhof4s1A3HPg=")
        let key = try JSONWebKeyHMAC<SHA256>(ExampleKeys.symmetric)
        var jws = jws
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureHS384() throws {
        let signature = Data(base64Encoded: "HtUYwLglVMRcHlYsPa+/gqP1Ah/W1Yd3hXkj7p45SMSALxZ4ziCjdPcxNbVRVG1A")
        let key = try JSONWebKeyHMAC<SHA384>(ExampleKeys.symmetric)
        var jws = jws
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureHS512() throws {
        let signature = Data(base64Encoded: "9O19/Twcl/2WbpM3ZjvOnfI7V5VMSOrYOh82QG3cSkcwdQnpteLTEBpuT+0SJp/THGb3iTjK22p5U7ISACjUIw==")
        let key = try JSONWebKeyHMAC<SHA512>(ExampleKeys.symmetric)
        var jws = jws
        try jws.updateSignature(using: key)
        XCTAssertEqual(jws.signatures.first?.signature, signature)
        XCTAssertNoThrow(try jws.verifySignature(using: key))
    }
    
    func testSignatureES256() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .ecdsaSignatureP256SHA256
        try jws.updateSignature(using: ExampleKeys.privateEC256)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC256))
    }
    
    func testSignatureES384() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .ecdsaSignatureP384SHA384
        try jws.updateSignature(using: ExampleKeys.privateEC384)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC384))
    }
    
    func testSignatureES521() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .ecdsaSignatureP521SHA512
        try jws.updateSignature(using: ExampleKeys.privateEC521)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicEC521))
    }
    
    func testSignatureRS256() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .rsaSignaturePKCS1v15SHA256
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignatureRS384() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .rsaSignaturePKCS1v15SHA384
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignatureRS512() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .rsaSignaturePKCS1v15SHA512
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS256() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .rsaSignaturePSSSHA256
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS384() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .rsaSignaturePSSSHA384
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testSignaturePS512() throws {
        var jws = jws
        jws.signatures[0].header.value.algorithm = .rsaSignaturePSSSHA512
        try jws.updateSignature(using: ExampleKeys.privateRSA2048)
        XCTAssertNoThrow(try jws.verifySignature(using: ExampleKeys.publicRSA2048))
    }
    
    func testVerifyDates() throws {
        XCTAssertThrowsError(try jws.verifyDate())
        XCTAssertNoThrow(try jws.verifyDate(.init(timeIntervalSince1970: 1_300_819_370)))
    }
}
