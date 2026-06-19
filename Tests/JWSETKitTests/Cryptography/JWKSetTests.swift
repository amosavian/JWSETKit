//
//  JWKSetTests.swift
//
//
//  Created by Amir Abbas Mousavian on 12/30/23.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

struct JWKSetTests {
    let jwksData: Data = .init("""
         {"keys":
           [
             {"kty":"EC",
              "crv":"P-256",
              "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "use":"enc",
              "kid":"1"},
             {"kty":"RSA",
              "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\
    4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\
    tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\
    QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\
    SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\
    w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e":"AQAB",
              "alg":"RS256",
              "kid":"2011-04-29"},
             {"kty":"EC",
              "crv":"P-256",
              "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
              "use":"enc",
              "kid":"1"},
             {"kty":"RSA",
              "iat": 123972394872,
              "exp": 123974394972,
              "revoked": {
                "revoked_at": 123972495172,
                "reason": "compromised",
              },
              "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\
    cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst\
    n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q\
    vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS\
    D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw\
    0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e":"AQAB",
              "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9\
    M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij\
    wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d\
    _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz\
    nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz\
    me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
              "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV\
    nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV\
    WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
              "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum\
    qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx\
    kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
              "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim\
    YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu\
    YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
              "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU\
    vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9\
    GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
              "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg\
    UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx\
    yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
              "alg":"RS256",
              "kid":"2011-04-29"}
           ]
         }
    """.utf8)
    
    let jwksPublicData: Data = .init("""
         {"keys":
           [
             {"kty":"RSA",
              "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\
    4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\
    tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\
    QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\
    SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\
    w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e":"AQAB",
              "alg":"RS256",
              "kid":"2011-04-29"},
             {"kty":"EC",
              "crv":"P-256",
              "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "use":"enc",
              "kid":"1"}
           ]
         }
    """.utf8)
    
    @Test
    func decode() throws {
        let jwks = try JSONDecoder().decode(JSONWebKeySet.self, from: jwksData)
        try #require(jwks.count == 2)
        #expect(jwks.publicKeyset[0] is (any JSONWebValidatingKey))
        #expect(jwks.publicKeyset[0] is JSONWebECPublicKey)
        
        #expect(jwks.publicKeyset[1] is (any JSONWebValidatingKey))
        #expect(jwks.publicKeyset[1] is JSONWebRSAPublicKey)
        
        #expect(jwks[0] is (any JSONWebValidatingKey))
        #expect(jwks[0] is (any JSONWebSigningKey))
        #expect(jwks[0] is JSONWebECPrivateKey)
        #expect(!(jwks[0] is JSONWebECPublicKey))
        
        #expect(jwks[1] is (any JSONWebValidatingKey))
        #expect(jwks[1] is (any JSONWebSigningKey))
        #expect(jwks[1] is JSONWebRSAPrivateKey)
        #expect(!(jwks[1] is JSONWebRSAPublicKey))
        #expect(jwks[1].issuedAt == .init(timeIntervalSince1970: 123_972_394_872))
        #expect(jwks[1].revoked == JSONWebKeyRevocation(at: .init(timeIntervalSince1970: 123_972_495_172), for: .compromised))
    }
    
    @Test
    func encode() throws {
        let jwks = try JSONDecoder().decode(JSONWebKeySet.self, from: jwksData)
        _ = try JSONEncoder().encode(jwks)
    }
    
    /// Guards the lazy-thumbprint optimization: a `kid`-identified key no longer stores its
    /// thumbprint in the set's identity, so thumbprint-based lookup/removal must still find it
    /// by computing the thumbprint on demand.
    @Test
    func thumbprintLookupForKeyWithKeyId() throws {
        var key = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        key.keyId = "kid-1"
        let thumbprint = try key.thumbprint(format: .jwk, using: SHA256.self).data
        let set = JSONWebKeySet(keys: [key])
        
        // Direct thumbprint subscript on a kid-identified key.
        #expect(set[thumbprint: thumbprint] != nil)
        #expect(set[thumbprint: thumbprint]?.keyId == "kid-1")
        
        // The `urn:ietf:params:oauth:jwk-thumbprint:` keyId path routes through the same
        // thumbprint lookup.
        let uri = try key.thumbprintUri(format: .jwk, using: SHA256.self)
        #expect(set[keyId: uri] != nil)
        
        // A non-matching thumbprint must not match.
        #expect(set[thumbprint: Data(repeating: 0, count: 32)] == nil)
        
        // remove(thumbprint:) must also locate the kid-identified key.
        var mutableSet = set
        #expect(mutableSet.remove(thumbprint: thumbprint) != nil)
        #expect(mutableSet.isEmpty)
    }
    
    /// Scenario: a single keyless key. Identity is its thumbprint; lookup by keyId fails,
    /// lookup by thumbprint succeeds.
    @Test
    func keylessKeyIdentity() throws {
        let key = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        #expect(key.keyId == nil)
        let thumbprint = try key.thumbprint(format: .jwk, using: SHA256.self).data
        let set = JSONWebKeySet(keys: [key])
        #expect(set.count == 1)
        #expect(set[thumbprint: thumbprint] != nil)
        #expect(set[keyId: "nonexistent"] == nil)
    }
    
    /// Scenario: lookup by `kid` for a kid-identified key (the `matches(for:)` signing path).
    @Test
    func keyIdLookup() throws {
        var key = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        key.keyId = "my-kid"
        let set = JSONWebKeySet(keys: [key])
        #expect(set[keyId: "my-kid"] != nil)
        #expect(set[keyId: "my-kid"]?.keyId == "my-kid")
        #expect(set[keyId: "other"] == nil)
    }
    
    /// Scenario: two DISTINCT keys with DIFFERENT kids both coexist (no false dedup).
    @Test
    func twoKeysDistinctKeyIds() throws {
        var k1 = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        k1.keyId = "kid-a"
        var k2 = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        k2.keyId = "kid-b"
        let set = JSONWebKeySet(keys: [k1, k2])
        #expect(set.count == 2)
        #expect(set[keyId: "kid-a"] != nil)
        #expect(set[keyId: "kid-b"] != nil)
    }
    
    /// Scenario: two keyless keys with different material both coexist (distinct thumbprints).
    @Test
    func twoKeylessKeysDistinctMaterial() throws {
        let k1 = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        let k2 = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        let set = JSONWebKeySet(keys: [k1, k2])
        #expect(set.count == 2)
    }
    
    /// Behavior boundary: two keys sharing the same `kid` (and key type) collapse to one entry,
    /// last-wins. Identity is `(kid, kty, curve, use)` — the JWK thumbprint is not part of it —
    /// so a reused `kid` deduplicates. (A misconfiguration in practice; locked here.)
    @Test
    func sameKeyIdDeduplicates() throws {
        var k1 = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        k1.keyId = "shared-kid"
        var k2 = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        k2.keyId = "shared-kid"
        let set = JSONWebKeySet(keys: [k1, k2])
        #expect(set.count == 1)
        #expect(set[keyId: "shared-kid"] != nil)
    }
    
    /// `matches(for:)` resolves by `kid` in a multi-key set.
    @Test
    func matchesResolvesByKeyId() throws {
        var a = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        a.keyId = "A"
        var b = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        b.keyId = "B"
        let set = JSONWebKeySet(keys: [a, b])
        var hdrB = JOSEHeader(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256, type: .jwt)
        hdrB.keyId = "B"
        #expect(set.matches(for: hdrB).first?.keyId == "B")
    }

    /// The kid-first short-circuit must only accept an **algorithm-compatible** match: a header that
    /// names a `kid` but with an incompatible algorithm (RSA vs the EC key) must NOT return that key.
    @Test
    func matchesRejectsKeyIdWithIncompatibleAlgorithm() throws {
        var a = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        a.keyId = "A"
        var b = try JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        b.keyId = "B"
        let set = JSONWebKeySet(keys: [a, b])
        var hdr = JOSEHeader(algorithm: JSONWebSignatureAlgorithm.rsaSignaturePKCS1v15SHA256, type: .jwt)
        hdr.keyId = "B"
        // EC key "B" is not RSA-compatible, so it must not be returned as the match.
        #expect(set.matches(for: hdr).first?.keyId != "B")
    }
}
