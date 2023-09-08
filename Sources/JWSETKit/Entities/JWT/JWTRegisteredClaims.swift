//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/6/23.
//

import Foundation

/// JWT Registered Claims Regarding [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)
public struct JSONWebTokenClaimsRegisteredParameters {
    /// The "`aud`" (audience) claim identifies the recipients that the JWT is intended for.
    ///
    /// Each principal intended to process the JWT MUST identify itself with a value in the audience claim.
    /// If the principal processing the claim does not identify itself with a value in the "`aud`" claim when this claim is present,
    /// then the JWT MUST be rejected.
    ///
    /// In the general case, the "aud" value is an array of case-sensitive strings,
    /// each containing a `StringOrURI` value.
    ///
    /// In the special case when the JWT has one audience,
    /// the "`aud`" value MAY be a single case-sensitive string containing a `StringOrURI` value.
    /// The interpretation of audience values is generally application specific.
    ///
    /// Use of this claim is OPTIONAL.
    public var audience: [String]
    
    /// The "`aud`" (audience) claim identifies the recipients that the JWT is intended for.
    ///
    /// Each principal intended to process the JWT MUST identify itself with a value in the audience claim.
    /// If the principal processing the claim does not identify itself with a value in the "`aud`" claim when this claim is present,
    /// then the JWT MUST be rejected.
    ///
    /// In the general case, the "aud" value is an array of case-sensitive strings,
    /// each containing a `StringOrURI` value.
    ///
    /// In the special case when the JWT has one audience,
    /// the "`aud`" value MAY be a single case-sensitive string containing a `StringOrURI` value.
    /// The interpretation of audience values is generally application specific.
    ///
    /// Use of this claim is OPTIONAL.
    public var audienceURL: [URL] { fatalError() }
    
    /// The "`exp`" (expiration time) claim identifies the expiration time on or
    /// after which the JWT MUST NOT be accepted for processing.
    ///
    /// The processing of the "`exp`" claim requires that the current date/time MUST
    /// be before the expiration date/time listed in the "`exp`" claim.
    ///
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes,
    /// to account for clock skew.
    ///
    /// Its value MUST be a number containing a `NumericDate` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var expiry: Date? { fatalError() }
    
    /// The "`iat`" (issued at) claim identifies the time at which the JWT was issued.
    ///
    /// This claim can be used to determine the age of the JWT.
    /// Its value MUST be a number containing a `NumericDate` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var issuedAt: Date? { fatalError() }
    
    /// The "`iss`" (issuer) claim identifies the principal that issued the JWT.
    ///
    /// The processing of this claim is generally application specific.
    /// The "iss" value is a case-sensitive string containing a `StringOrURI` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var issuer: String? { fatalError() }
    
    /// The "`iss`" (issuer) claim identifies the principal that issued the JWT.
    ///
    /// The processing of this claim is generally application specific.
    /// The "iss" value is a case-sensitive string containing a `StringOrURI` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var issuerURL: URL? { fatalError() }
    
    /// The "`jti`" (JWT ID) claim provides a unique identifier for the JWT.
    ///
    /// The identifier value MUST be assigned in a manner that ensures that
    /// there is a negligible probability that the same value will be accidentally
    /// assigned to a different data object; if the application uses multiple issuers,
    /// collisions MUST be prevented among values produced by different issuers as well.
    /// The "`jti`" claim can be used to prevent the JWT from being replayed.
    ///
    /// The "`jti`" value is a case-sensitive string.
    ///
    /// Use of this claim is OPTIONAL.
    public var jwtId: String? { fatalError() }
    
    /// The "`jti`" (JWT ID) claim provides a unique identifier for the JWT.
    ///
    /// The identifier value MUST be assigned in a manner that ensures that
    /// there is a negligible probability that the same value will be accidentally
    /// assigned to a different data object; if the application uses multiple issuers,
    /// collisions MUST be prevented among values produced by different issuers as well.
    /// The "`jti`" claim can be used to prevent the JWT from being replayed.
    ///
    /// The "`jti`" value is a case-sensitive string.
    ///
    /// Use of this claim is OPTIONAL.
    public var jwtUUID: UUID? { fatalError() }
    
    /// The "`nbf`" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
    ///
    /// The processing of the "`nbf`" claim requires that the current date/time MUST be after or equal to
    /// the not-before date/time listed in the "`nbf`" claim.
    ///
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes,
    /// to account for clock skew.
    ///
    /// Its value MUST be a number containing a `NumericDate` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var notBefore: Date? { fatalError() }
    
    /// The "`sub`" (subject) claim identifies the principal that is the subject of the JWT.
    ///
    /// The claims in a JWT are normally statements about the subject.
    /// The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique.
    /// The processing of this claim is generally application specific.
    ///
    /// The "`sub`" value is a case-sensitive string containing a `StringOrURI` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var subject: String? { fatalError() }
    
    /// The "`sub`" (subject) claim identifies the principal that is the subject of the JWT.
    ///
    /// The claims in a JWT are normally statements about the subject.
    /// The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique.
    /// The processing of this claim is generally application specific.
    ///
    /// The "`sub`" value is a case-sensitive string containing a `StringOrURI` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var subjectURL: URL? { fatalError() }
    
    fileprivate static let keys: [PartialKeyPath<Self>: String] = [
        \.audience: "aud", \.audienceURL: "aud", \.expiry: "exp",
         \.issuedAt: "iat", \.issuer: "iss", \.issuerURL: "iss",
         \.jwtId: "jti", \.jwtUUID: "jti", \.notBefore: "nbf",
         \.subject: "sub", \.subjectURL: "sub",
    ]
}

extension JSONWebTokenClaims {
    private func stringKey<T>(_ keyPath: KeyPath<JSONWebTokenClaimsRegisteredParameters, T>) -> String {
        if let key = JSONWebTokenClaimsRegisteredParameters.keys[keyPath] {
            return key
        }
        return String(reflecting: keyPath).components(separatedBy: ".").last!.jsonWebKey
    }
    
    public subscript(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsRegisteredParameters, [String]>) -> [String] {
        get {
            let key = stringKey(keyPath)
            if let string = storage[key] as String? {
                return [string]
            }
            return storage[key]
        }
        set {
            let key = stringKey(keyPath)
            switch newValue.count {
            case 1:
                storage[key] = newValue.first
            default:
                storage[key] = newValue
            }
        }
    }
    
    public subscript(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsRegisteredParameters, [URL]>) -> [URL] {
        get {
            let key = stringKey(keyPath)
            if let url = storage[key].flatMap(URL.init(string:)) {
                return [url]
            } else {
                return storage[key].compactMap(URL.init(string:))
            }
        }
        set {
            let key = stringKey(keyPath)
            switch newValue.count {
            case 0:
                storage.remove(key: key)
            case 1:
                storage[key] = newValue.first
            default:
                storage[key] = newValue
            }
        }
    }
    
    public subscript<T>(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsRegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
