//
//  JWTAccessTokenHashTests.swift
//
//
//  Created by Amir Abbas Mousavian.
//

import Foundation
import Testing
@testable import JWSETKit

struct JWTAccessTokenHashTests {
    // Known-answer vector from OpenID Connect Core 1.0 (§3.1.3.6 / §3.2.2.10):
    // SHA-256 over the access_token, left-most 128 bits, base64url-encoded.
    let accessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
    let expectedAtHash = "77QmUPtjPfzWtF2AnpK9RQ"

    // An authorization code and its c_hash under the same SHA-256 algorithm.
    let code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
    let expectedCHash = "LDktKdoQak3Pk0cnXxCltA"

    func makeIDToken(algorithm: JSONWebSignatureAlgorithm) throws -> JSONWebToken {
        let payload = try JSONWebTokenClaims { container in
            container.subject = "user123"
        }
        return try JSONWebToken(payload: payload, algorithm: algorithm, using: ExampleKeys.symmetric)
    }

    @Test
    func leftHalfHashMatchesOIDCVector() throws {
        let hash = try JSONWebSignatureAlgorithm.hmacSHA256.leftHalfHash(of: Data(accessToken.utf8))
        #expect(hash == Data(urlBase64Encoded: expectedAtHash))
    }

    @Test
    func setAccessTokenHashComputesFromIDTokenAlgorithm() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setAccessTokenHash(accessToken)
        #expect(idToken.payload.accessTokenHash == Data(urlBase64Encoded: expectedAtHash))
    }

    @Test
    func setAccessTokenHashStripsBearerPrefix() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setAccessTokenHash("Bearer \(accessToken)")
        #expect(idToken.payload.accessTokenHash == Data(urlBase64Encoded: expectedAtHash))
    }

    @Test
    func verifyAccessTokenHashSucceedsForMatchingToken() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setAccessTokenHash(accessToken)
        #expect(throws: Never.self) { try idToken.verifyAccessTokenHash(accessToken) }
        // Bearer-prefixed input must also verify.
        #expect(throws: Never.self) { try idToken.verifyAccessTokenHash("Bearer \(accessToken)") }
    }

    @Test
    func verifyAccessTokenHashThrowsForWrongToken() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setAccessTokenHash(accessToken)
        #expect(throws: (any Error).self) { try idToken.verifyAccessTokenHash("a-different-access-token") }
    }

    @Test
    func verifyAccessTokenHashThrowsWhenClaimMissing() throws {
        let idToken = try makeIDToken(algorithm: .hmacSHA256)
        #expect(throws: (any Error).self) { try idToken.verifyAccessTokenHash(accessToken) }
    }

    @Test
    func setCodeHashComputesFromIDTokenAlgorithm() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setCodeHash(code)
        #expect(idToken.payload.codeHash == Data(urlBase64Encoded: expectedCHash))
    }

    @Test
    func verifyCodeHashSucceedsForMatchingCode() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setCodeHash(code)
        #expect(throws: Never.self) { try idToken.verifyCodeHash(code) }
    }

    @Test
    func verifyCodeHashThrowsForWrongCode() throws {
        var idToken = try makeIDToken(algorithm: .hmacSHA256)
        try idToken.setCodeHash(code)
        #expect(throws: (any Error).self) { try idToken.verifyCodeHash("wrong-code") }
    }
}
