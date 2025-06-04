//
//  JOSEHeaderJWETests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct JOSEHeaderJWETests {
    let testClaims = """
    {
       "enc":"A128GCM",
       "zip":"DEF"
    }
    """
    @Test
    func encodeParams() throws {
        let decoder = JSONDecoder()
        let claims = try decoder.decode(JOSEHeader.self, from: .init(testClaims.utf8))
        
        #expect(claims.encryptionAlgorithm == .aesEncryptionGCM128)
        #expect(claims.compressionAlgorithm == .deflate)
    }
    
    @Test
    func decodeParams() throws {
        var claims = JOSEHeader(storage: .init())
        
        claims.encryptionAlgorithm = .aesEncryptionGCM128
        claims.compressionAlgorithm = .deflate
        let decoder = JSONDecoder()
        let decodedClaims = try decoder.decode(JOSEHeader.self, from: .init(testClaims.utf8))
        
        #expect(claims == decodedClaims)
    }
}
