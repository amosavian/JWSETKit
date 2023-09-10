//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

// Claims registered in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2)
public struct JSONWebTokenClaimsPublicOIDCAuthParameters {
    /// Time when the End-User authentication occurred.
    ///
    /// Its value is a JSON number representing the number of seconds from
    /// 1970-01-01T0:0:0Z as measured in UTC until the date/time.
    /// When a `max_age` request is made or when `auth_time` is requested
    /// as an Essential Claim, then this Claim is REQUIRED;
    /// otherwise, its inclusion is OPTIONAL.
    /// (The `auth_time` Claim semantically corresponds to the
    /// OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
    public var authTime: Date?
    
    /// Authentication Context Class Reference.
    ///
    /// `String` specifying an Authentication Context Class Reference value
    /// that identifies the Authentication Context Class that the authentication performed satisfied.
    ///
    /// The value "`0`" indicates the End-User authentication did not meet
    /// the requirements of ISO/IEC 29115 [ISO29115] level 1.
    /// Authentication using a long-lived browser cookie,
    /// for instance, is one example where the use of "level 0" is appropriate.
    /// Authentications with level `0` SHOULD NOT be used to authorize access to any resource of any monetary value.
    /// (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level `0`.)
    /// An absolute `URI` or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value;
    /// registered names MUST NOT be used with a different meaning than that which is registered.
    /// Parties using this claim will need to agree upon the meanings of the values used,
    /// which may be context-specific. The acr value is a case sensitive string.
    public var authenticationContextClassReference: String?
    
    /// Authentication Methods References.
    ///
    /// JSON array of strings that are identifiers for authentication methods used in the authentication.
    /// For instance, values might indicate that both password and OTP authentication methods were used.
    /// The definition of particular values to be used in the `amr` Claim is beyond the scope of this specification.
    /// Parties using this claim will need to agree upon the meanings of the values used,
    /// which may be context-specific.
    /// The `amr` value is an array of case sensitive strings.
    public var authenticationMethodsReferences: [String]
    
    /// Authorized party - the party to which the ID Token was issued.
    ///
    /// If present, it MUST contain the OAuth 2.0 Client ID of this party.
    /// This Claim is only needed when the ID Token has a single audience value
    /// and that audience is different than the authorized party.
    /// It MAY be included even when the authorized party is the same as the sole audience.
    /// The azp value is a case sensitive string containing a `StringOrURI` value.
    public var authorizedParty: String?
    
    /// Authorized party - the party to which the ID Token was issued.
    ///
    /// If present, it MUST contain the OAuth 2.0 Client ID of this party.
    /// This Claim is only needed when the ID Token has a single audience value
    /// and that audience is different than the authorized party.
    /// It MAY be included even when the authorized party is the same as the sole audience.
    /// The azp value is a case sensitive string containing a `StringOrURI` value.
    public var authorizedPartyURL: URL?
    
    /// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
    ///
    /// The value is passed through unmodified from the Authentication Request to the ID Token.
    /// If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to
    /// the value of the nonce parameter sent in the Authentication Request.
    /// If present in the Authentication Request, Authorization Servers MUST include
    /// a nonce Claim in the ID Token with the Claim Value being the nonce value
    /// sent in the Authentication Request.
    ///
    /// Authorization Servers SHOULD perform no other processing on nonce values used.
    /// The nonce value is a case sensitive string.
    public var nonce: String?
    
    /// Access Token hash value.
    ///
    /// Its value is the `base64url` encoding of the left-most half of the hash
    /// of the octets of the ASCII representation of the `access_token` value,
    /// where the hash algorithm used is the hash algorithm used in the `alg`
    /// Header Parameter of the ID Token's JOSE Header.
    /// For instance, if the alg is RS256, hash the `access_token` value with SHA-256,
    /// then take the left-most 128 bits and `base64url` encode them.
    /// The `at_hash` value is a case sensitive string.
    ///
    /// If the ID Token is issued from the Authorization Endpoint with an `access_token` value,
    /// which is the case for the `response_type` value code `id_token` token,
    /// this is REQUIRED; otherwise, its inclusion is OPTIONAL.
    public var accessTokenHash: Data?
    
    /// Code hash value.
    ///
    /// Its value is the `base64url` encoding of the left-most half of the hash
    /// of the octets of the ASCII representation of the code value,
    /// where the hash algorithm used is the hash algorithm used in the `alg`
    /// Header Parameter of the ID Token's JOSE Header.
    /// For instance, if the alg is HS512, hash the code value with SHA-512,
    /// then take the left-most 256 bits and base64url encode them.
    /// The `c_hash` value is a case sensitive string.
    ///
    /// If the ID Token is issued from the Authorization Endpoint with a code,
    /// which is the case for the `response_type` values code `id_token` and code `id_token` token,
    /// this is REQUIRED; otherwise, its inclusion is OPTIONAL.
    public var codeHash: Data?
    
    fileprivate static let keys: [PartialKeyPath<Self>: String] = [
        \.authenticationContextClassReference: "acr",
         \.authenticationMethodsReferences: "amr",
         \.authorizedParty: "azp", \.authorizedPartyURL: "azp",
         \.accessTokenHash: "at_hash", \.codeHash: "c_hash"
    ]
}

extension JSONWebTokenClaims {
    private func stringKey<T>(_ keyPath: KeyPath<JSONWebTokenClaimsPublicOIDCAuthParameters, T>) -> String {
        if let key = JSONWebTokenClaimsPublicOIDCAuthParameters.keys[keyPath] {
            return key
        }
        return String(reflecting: keyPath).components(separatedBy: ".").last!.jsonWebKey
    }
    
    public subscript<T>(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsPublicOIDCAuthParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    public subscript(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsPublicOIDCAuthParameters, Data?>) -> Data? {
        get {
            storage[stringKey(keyPath), true]
        }
        set {
            storage[stringKey(keyPath), true] = newValue
        }
    }
    
    public subscript(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsPublicOIDCAuthParameters, [String]>) -> [String] {
        get {
            return storage[stringKey(keyPath)]
        }
        set {
            let key = stringKey(keyPath)
            storage[key] = newValue
        }
    }
}
