//
//  ThumbprintTests.swift
//
//
//  Created by Amir Abbas Mousavian on 4/18/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit
#if canImport(CommonCrypto)
import CommonCrypto
#endif

@Suite
struct ThumbprintTests {
    let keyData: Data = .init("""
     {
      "kty": "RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
    VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
    4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\
    W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
    1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
    aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB",
      "alg": "RS256",
      "kid": "2011-04-29"
     }
    """.utf8)
    
    @Test
    func jwkThumbprint() throws {
        let key = try JSONWebRSAPublicKey(importing: keyData, format: .jwk)
        let thumbprint = try key.thumbprint(format: .jwk, using: SHA256.self)
        #expect(thumbprint.data == Data(urlBase64Encoded: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"))
    }
    
    @Test
    func jwkAmbiguousThumbprint() throws {
        var key = try JSONWebRSAPublicKey(importing: keyData, format: .jwk)
        key.exponent = Data([0x00, 0x01, 0x00, 0x01])
        let thumbprint = try key.thumbprint(format: .jwk, using: SHA256.self)
        #expect(thumbprint.data == Data(urlBase64Encoded: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"))
    }
    
    @Test
    func spkiThumbprint() throws {
        let key = try JSONWebRSAPublicKey(importing: keyData, format: .jwk)
        let thumbprint = try key.thumbprint(format: .spki, using: SHA256.self)
        #expect(thumbprint.data == Data(urlBase64Encoded: "rTIyDPbFltiEsFOBulc6uo3dV0m03o9KI6efmondrrI"))
    }
    
    @Test
    func jwk_URI_Thumbprint() throws {
        let key = try JSONWebRSAPublicKey(importing: keyData, format: .jwk)
        let uri = try key.thumbprintUri(format: .jwk, using: SHA256.self)
        #expect(uri == "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }
    
#if canImport(CommonCrypto)
    @Test
    func ecdsaThumbprint() throws {
        let secECKey = try SecKey(algorithm: .ecdsaSignatureP256SHA256)
        let ecKey = try P256.Signing.PrivateKey(derRepresentation: secECKey.exportKey(format: .pkcs8))
        let pkcs8 = try secECKey.exportKey(format: .pkcs8)
        #expect(ecKey.derRepresentation == pkcs8)
    }
#endif
}
