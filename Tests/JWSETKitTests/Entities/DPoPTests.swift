//
//  DPoPTests.swift
//
//
//  Created by Amir Abbas Mousavian.
//

import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
#if canImport(HTTPTypes)
import HTTPTypes
#endif
#if canImport(NIOHTTP1)
import NIOHTTP1
#endif
#if canImport(AsyncHTTPClient)
import AsyncHTTPClient
#endif
@testable import JWSETKit

struct DPoPTests {
    // Values aligned with the RFC 9449 §4.2 worked example.
    let method = "POST"
    let url = URL(string: "https://server.example.com/token")!
    let accessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
    
    // MARK: Mint
    
    @Test
    func mintProducesDPoPHeader() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        #expect(proof.header.type == .dpop)
        // The public key must be embedded in the protected header.
        #expect(proof.header.key != nil)
        #expect(proof.header.algorithm?.rawValue == "ES256")
    }
    
    @Test
    func mintPopulatesClaims() throws {
        let issuedAt = Date(timeIntervalSince1970: 1_562_262_616)
        let proof = try DPoPProof(
            method: method,
            url: url,
            issuedAt: issuedAt,
            using: ExampleKeys.privateEC256
        )
        #expect(proof.payload.httpMethod == "POST")
        #expect(proof.payload.httpURL == url)
        #expect(proof.payload.issuedAt == issuedAt)
        #expect(proof.payload.jwtId?.isEmpty == false)
    }
    
    @Test
    func jwtUUIDAccessorReadsJtiClaim() throws {
        let id = UUID()
        let proof = try DPoPProof(method: method, url: url, jwtId: id.uuidString, using: ExampleKeys.privateEC256)
        // jwtUUID is a UUID-typed view over the same `jti` claim as jwtId.
        #expect(proof.payload.jwtUUID == id)
        #expect(proof.payload.jwtId == id.uuidString)
    }
    
    @Test
    func mintWithAccessTokenSetsAth() throws {
        let proof = try DPoPProof(method: method, url: url, accessToken: accessToken, using: ExampleKeys.privateEC256)
        let expected = Data(SHA256.hash(data: Data(accessToken.utf8)))
        #expect(proof.payload.accessTokenHash == expected)
    }
    
    // MARK: Round-trip verify
    
    @Test
    func verifyRoundTripSucceeds() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        #expect(throws: Never.self) {
            try proof.verify(method: method, url: url)
        }
    }
    
    @Test
    func verifyRejectsDifferentlyCasedMethod() throws {
        // HTTP methods are case-sensitive tokens (RFC 7231); htm must match exactly.
        let proof = try DPoPProof(method: "POST", url: url, using: ExampleKeys.privateEC256)
        #expect(throws: (any Error).self) {
            try proof.verify(method: "post", url: url)
        }
    }
    
    @Test
    func verifyRejectsWrongMethod() throws {
        let proof = try DPoPProof(method: "POST", url: url, using: ExampleKeys.privateEC256)
        #expect(throws: (any Error).self) {
            try proof.verify(method: "GET", url: url)
        }
    }
    
    @Test
    func verifyNormalizesHtuIgnoringQueryAndFragment() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let requestURL = try #require(URL(string: "https://server.example.com/token?foo=bar#frag"))
        #expect(throws: Never.self) {
            try proof.verify(method: method, url: requestURL)
        }
    }
    
    @Test
    func verifyRejectsDifferentHtu() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let other = try #require(URL(string: "https://evil.example.com/token"))
        #expect(throws: (any Error).self) {
            try proof.verify(method: method, url: other)
        }
    }
    
    @Test
    func verifyRejectsFutureDatedProof() throws {
        let future = Date(timeIntervalSinceNow: 3600)
        let proof = try DPoPProof(method: method, url: url, issuedAt: future, using: ExampleKeys.privateEC256)
        #expect(throws: (any Error).self) {
            try proof.verify(method: method, url: url, currentDate: .init())
        }
    }
    
    @Test
    func verifyWithAccessTokenSucceeds() throws {
        let proof = try DPoPProof(method: method, url: url, accessToken: accessToken, using: ExampleKeys.privateEC256)
        #expect(throws: Never.self) {
            try proof.verify(method: method, url: url, accessToken: accessToken)
        }
    }
    
    @Test
    func verifyWithWrongAccessTokenFails() throws {
        let proof = try DPoPProof(method: method, url: url, accessToken: accessToken, using: ExampleKeys.privateEC256)
        #expect(throws: (any Error).self) {
            try proof.verify(method: method, url: url, accessToken: "different-token")
        }
    }
    
    @Test
    func verifyWithExpectedNonceSucceedsAndMismatchFails() throws {
        let proof = try DPoPProof(method: method, url: url, nonce: "server-nonce", using: ExampleKeys.privateEC256)
        #expect(throws: Never.self) {
            try proof.verify(method: method, url: url, nonce: "server-nonce")
        }
        #expect(throws: (any Error).self) {
            try proof.verify(method: method, url: url, nonce: "wrong-nonce")
        }
    }
    
    // MARK: Binding (§6.1)
    
    @Test
    func verifyBindingMatchesAccessTokenConfirmation() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let bound = try JSONWebToken(payload: .init {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC256)
        }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        #expect(throws: Never.self) {
            try proof.verifyBinding(accessToken: bound)
        }
    }
    
    @Test
    func verifyBindingFailsForUnboundKey() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let bound = try JSONWebToken(payload: .init {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC384)
        }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        #expect(throws: (any Error).self) {
            try proof.verifyBinding(accessToken: bound)
        }
    }
    
    @Test
    func verifyBindingFailsWhenNoConfirmation() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let unbound = try JSONWebToken(payload: .init { $0.subject = "u" }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        #expect(throws: (any Error).self) {
            try proof.verifyBinding(accessToken: unbound)
        }
    }
    
    @Test
    func verifyBindingMatchesAfterTokenRoundTrip() throws {
        // A real access token arrives as a compact string and is decoded; its `cnf.jkt`
        // must decode back to a JWK-thumbprint confirmation that verifyBinding accepts.
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let issued = try JSONWebToken(payload: .init {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC256)
        }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        
        // Round-trip through compact serialization + parsing (the production path).
        let decoded = try JSONWebToken(from: String(issued))
        #expect(throws: Never.self) {
            try proof.verifyBinding(accessToken: decoded)
        }
    }
    
    @Test
    func verifyBindingRejectsMismatchAfterTokenRoundTrip() throws {
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let issued = try JSONWebToken(payload: .init {
            $0.confirmation = try .keyThumbprint(ExampleKeys.publicEC384)
        }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        let decoded = try JSONWebToken(from: String(issued))
        #expect(throws: (any Error).self) {
            try proof.verifyBinding(accessToken: decoded)
        }
    }
    
    @Test
    func verifyBindingRejectsEmbeddedJWKThatDoesNotMatch() throws {
        // A `cnf.jwk` carrying a different key must NOT pass binding (no false-accept).
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let bound = try JSONWebToken(payload: .init {
            $0.confirmation = .key(ExampleKeys.publicEC384)
        }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        #expect(throws: (any Error).self) {
            try proof.verifyBinding(accessToken: bound)
        }
    }
    
    @Test
    func verifyBindingMatchesEmbeddedJWK() throws {
        // A `cnf.jwk` carrying the proof's own key passes binding.
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let bound = try JSONWebToken(payload: .init {
            $0.confirmation = .key(ExampleKeys.publicEC256)
        }, algorithm: .hmacSHA256, using: ExampleKeys.symmetric)
        #expect(throws: Never.self) {
            try proof.verifyBinding(accessToken: bound)
        }
    }
    
    // MARK: Required claims & key hygiene
    
    @Test
    func verifyRejectsProofMissingIssuedAt() throws {
        var proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        proof.payload.issuedAt = nil
        try proof.updateSignature(using: ExampleKeys.privateEC256)
        #expect(throws: (any Error).self) {
            try proof.verify(method: method, url: url)
        }
    }
    
    @Test
    func verifyRejectsProofMissingJWTID() throws {
        var proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        proof.payload.jwtId = nil
        try proof.updateSignature(using: ExampleKeys.privateEC256)
        #expect(throws: (any Error).self) {
            try proof.verify(method: method, url: url)
        }
    }
    
    @Test
    func claimsValidateRequiresAllMandatoryClaims() throws {
        // A complete set of required claims validates.
        var claims = DPoPClaims(storage: .init())
        claims.jwtId = UUID().uuidString
        claims.httpMethod = "POST"
        claims.httpURL = url
        claims.issuedAt = .init()
        #expect(throws: Never.self) { try claims.validate() }
        
        // Removing any one required claim fails validation.
        for removed in ["jti", "htm", "htu", "iat"] {
            var partial = claims
            partial.storage.remove(key: removed)
            #expect(throws: (any Error).self) { try partial.validate() }
        }
    }
    
    // MARK: htu normalization
    
    @Test
    func verifyAcceptsDefaultPortMismatch() throws {
        // Proof minted for the bare URL must verify against an explicit :443.
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        let withPort = try #require(URL(string: "https://server.example.com:443/token"))
        #expect(throws: Never.self) {
            try proof.verify(method: method, url: withPort)
        }
    }
    
    // MARK: ath scheme handling
    
    @Test
    func athIsComputedOverSchemeStrippedToken() throws {
        // The proof binds `ath` over the bare token even when a Bearer scheme is supplied.
        let proof = try DPoPProof(method: method, url: url, accessToken: "Bearer \(accessToken)", using: ExampleKeys.privateEC256)
        let expected = Data(SHA256.hash(data: Data(accessToken.utf8)))
        #expect(proof.payload.accessTokenHash == expected)
        #expect(throws: Never.self) {
            try proof.verify(method: method, url: url, accessToken: accessToken)
        }
    }
    
    // MARK: URLRequest convenience
    
#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking)
    @Test
    func setDPoPProofOnURLRequest() throws {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        try request.setDPoPProof(using: ExampleKeys.privateEC256)
        
        let proof = try #require(request.dpopProof)
        #expect(proof.payload.httpMethod == "POST")
        #expect(proof.payload.httpURL == url)
        #expect(throws: Never.self) {
            try proof.verify(method: "POST", url: url)
        }
    }
    
    @Test
    func setDPoPProofOnURLRequestDefaultsToGET() throws {
        var request = URLRequest(url: url) // httpMethod defaults to "GET"
        try request.setDPoPProof(using: ExampleKeys.privateEC256)
        #expect(request.dpopProof?.payload.httpMethod == "GET")
    }
    
    @Test
    func setDPoPProofOnURLRequestSwitchesAuthorizationToDPoPScheme() throws {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        try request.setDPoPProof(using: ExampleKeys.privateEC256)
        
        // Authorization scheme is rewritten from Bearer to DPoP (RFC 9449 §7.1).
        #expect(request.value(forHTTPHeaderField: "Authorization") == "DPoP \(accessToken)")
        // The proof binds the same access token via ath, with the scheme stripped.
        let expected = Data(SHA256.hash(data: Data(accessToken.utf8)))
        #expect(request.dpopProof?.payload.accessTokenHash == expected)
        let proof = try #require(request.dpopProof)
        #expect(throws: Never.self) {
            try proof.verify(method: "POST", url: url, accessToken: accessToken)
        }
    }
#endif
    
    // MARK: HTTPTypes (HTTPRequest / HTTPFields)
    
#if canImport(HTTPTypes)
    @Test
    func mintFromHTTPRequestReconstructsHTU() throws {
        var request = HTTPRequest(method: .post, scheme: "https", authority: "server.example.com", path: "/token")
        try request.setDPoPProof(using: ExampleKeys.privateEC256)
        let proof = try #require(request.headerFields.dpopProof)
        #expect(proof.payload.httpMethod == "POST")
        #expect(proof.payload.httpURL == url)
        #expect(throws: Never.self) {
            try proof.verify(method: "POST", url: url)
        }
    }
    
    @Test
    func mintFromHTTPRequestThrowsWithoutAuthority() throws {
        // No scheme/authority -> cannot reconstruct an absolute htu.
        var request = HTTPRequest(method: .post, scheme: nil, authority: nil, path: "/token")
        #expect(throws: (any Error).self) {
            try request.setDPoPProof(using: ExampleKeys.privateEC256)
        }
    }
    
    @Test
    func setDPoPProofOnHTTPRequestSwitchesSchemeAndVerifies() throws {
        var request = HTTPRequest(method: .post, scheme: "https", authority: "server.example.com", path: "/token")
        request.headerFields[.authorization] = "Bearer \(accessToken)"
        try request.setDPoPProof(using: ExampleKeys.privateEC256)
        
        #expect(request.headerFields[.authorization] == "DPoP \(accessToken)")
        #expect(request.headerFields[.dpop] != nil)
        #expect(throws: Never.self) {
            try request.verifyDPoPProof()
        }
    }
    
    @Test
    func httpFieldsVerifyThrowsWhenHeaderMissing() throws {
        let fields = HTTPFields()
        #expect(throws: (any Error).self) {
            try fields.verifyDPoPProof(method: .post, url: url)
        }
    }
    
    @Test
    func setDPoPProofOnHTTPFields() throws {
        var fields = HTTPFields()
        fields[.authorization] = "Bearer \(accessToken)"
        try fields.setDPoPProof(method: .post, url: url, using: ExampleKeys.privateEC256)
        
        #expect(fields[.authorization] == "DPoP \(accessToken)")
        #expect(fields.dpopProof != nil)
        #expect(throws: Never.self) {
            try fields.verifyDPoPProof(method: .post, url: url)
        }
    }

    @Test
    func httpFieldsVerifyRejectsMultipleDPoPHeaders() throws {
        // RFC 9449 §4.3 #1: there must not be more than one DPoP header field.
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        var fields = HTTPFields()
        fields.append(HTTPField(name: .dpop, value: proof.description))
        fields.append(HTTPField(name: .dpop, value: proof.description))

        #expect(throws: (any Error).self) {
            try fields.verifyDPoPProof(method: .post, url: url)
        }
    }
#endif
    
    // MARK: NIO HTTPHeaders
    
#if canImport(NIOHTTP1)
    @Test
    func httpHeadersVerifyThrowsWhenHeaderMissing() throws {
        let headers = HTTPHeaders()
        #expect(throws: (any Error).self) {
            try headers.verifyDPoPProof(method: .POST, url: url)
        }
    }
    
    @Test
    func setDPoPProofOnHTTPHeaders() throws {
        var headers = HTTPHeaders()
        headers.add(name: "authorization", value: "Bearer \(accessToken)")
        try headers.setDPoPProof(method: .POST, url: url, using: ExampleKeys.privateEC256)
        
        #expect(headers.first(name: "authorization") == "DPoP \(accessToken)")
        #expect(headers.dpopProof != nil)
        #expect(throws: Never.self) {
            try headers.verifyDPoPProof(method: .POST, url: url)
        }
    }

    @Test
    func httpHeadersVerifyRejectsMultipleDPoPHeaders() throws {
        // RFC 9449 §4.3 #1: there must not be more than one DPoP header field.
        let proof = try DPoPProof(method: method, url: url, using: ExampleKeys.privateEC256)
        var headers = HTTPHeaders()
        headers.add(name: "dpop", value: proof.description)
        headers.add(name: "dpop", value: proof.description)

        #expect(throws: (any Error).self) {
            try headers.verifyDPoPProof(method: .POST, url: url)
        }
    }
#endif
    
    // MARK: AsyncHTTPClient HTTPClientRequest
    
#if canImport(AsyncHTTPClient)
    @Test
    func setDPoPProofOnHTTPClientRequest() throws {
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .POST
        request.headers.add(name: "authorization", value: "Bearer \(accessToken)")
        try request.setDPoPProof(using: ExampleKeys.privateEC256)
        
        #expect(request.headers.first(name: "authorization") == "DPoP \(accessToken)")
        let proof = try #require(request.headers.dpopProof)
        #expect(proof.payload.httpMethod == "POST")
        #expect(proof.payload.httpURL == url)
        #expect(throws: Never.self) {
            try proof.verify(method: "POST", url: url, accessToken: accessToken)
        }
    }
#endif
}
