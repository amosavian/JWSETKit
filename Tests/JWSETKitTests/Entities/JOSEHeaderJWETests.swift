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
       "enc":"A128GCM",
       "zip":"DEF"
    }
    """
    func testEncodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JOSEHeader.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims.encryptionAlgorithm, .aesEncryptionGCM128)
        XCTAssertEqual(claims.compressionAlgorithm, .deflate)
    }
    
    func testDecodeParams() throws {
        var claims = JOSEHeader(storage: .init())
        
        claims.encryptionAlgorithm = .aesEncryptionGCM128
        claims.compressionAlgorithm = .deflate
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JOSEHeader.self, from: .init(testClaims.utf8))
        
        XCTAssertEqual(claims, decodedClaims)
    }
}
