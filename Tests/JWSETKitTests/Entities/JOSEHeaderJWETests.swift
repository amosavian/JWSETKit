//
//  JOSEHeaderJWETests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import XCTest
@testable import JWSETKit

final class JOSEHeaderJWETests: XCTestCase {
    let testClaims = """
    {
       "enc":"RS256",
       "zip":"DEF"
    }
    """
    func testEncodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JOSEHeader.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims.encryptionAlgorithm, .rsaSignaturePKCS1v15SHA256)
        XCTAssertEqual(claims.compressionAlgorithm, .deflate)
    }
    
    func testDecodeParams() throws {
        var claims = JOSEHeader(storage: .init())
        
        claims.encryptionAlgorithm = .rsaSignaturePKCS1v15SHA256
        claims.compressionAlgorithm = .deflate
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JOSEHeader.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims, decodedClaims)
    }
}
