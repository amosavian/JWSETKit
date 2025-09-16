//
//  JWTPayload.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Claims and payload in a JWT.
public struct JSONWebTokenClaims: MutableJSONWebContainer, Sendable {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
}

/// A JWS object that contains JWT registered tokens.
public typealias JSONWebToken = JSONWebSignature<ProtectedJSONWebContainer<JSONWebTokenClaims>>

extension JSONWebTokenClaims {
    /// Verify that the given audience is included as one of the claim's intended audiences.
    ///
    /// - Parameter audience: The exact intended audience.
    public func verifyAudience(includes audience: String) throws {
        // swiftformat:disable:next redundantSelf
        guard self.audience.contains(audience) else {
            throw JSONWebValidationError.audienceNotIntended(audience)
        }
    }
}

extension JSONWebToken {
    /// Verify that the given audience is included as one of the claim's intended audiences.
    ///
    /// - Parameter audience: The exact intended audience.
    public func verifyAudience(includes audience: String) throws {
        try payload.value.verifyAudience(includes: audience)
    }
}

extension JSONWebTokenClaims: Expirable {
    /// Verifies the `exp` and `nbf` headers using current date.
    ///
    /// - Parameters:
    ///   - currentDate: The date that headers will be check against. Default is current system date.
    public func verifyDate(_ currentDate: Date) throws {
        // swiftformat:disable:next redundantSelf
        if let expiry = self.expiry, currentDate > expiry {
            throw JSONWebValidationError.tokenExpired(expiry: expiry)
        }
        // swiftformat:disable:next redundantSelf
        if let notBefore = self.notBefore, currentDate < notBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notBefore)
        }
    }
}

extension JSONWebToken: Expirable {
    /// Verifies the `exp` and `nbf` headers using current date.
    ///
    /// - Parameters:
    ///   - currentDate: The date that headers will be check against. Default is current system date.
    public func verifyDate(_ currentDate: Date) throws {
        try payload.value.verifyDate(currentDate)
    }
}

extension JSONWebToken {
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - keySet: A `JSONWebKeySet` object contains keys that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify(using keySet: JSONWebKeySet, for audience: String? = nil) throws {
        try verifySignature(using: keySet)
        try verifyDate()
        if let audience {
            try verifyAudience(includes: audience)
        }
    }
    
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify<S>(using keys: S, for audience: String? = nil) throws where S: Sequence, S.Element: JSONWebValidatingKey {
        try verify(using: JSONWebKeySet(keys: keys), for: audience)
    }
    
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify<S>(using keys: S, for audience: String? = nil) throws where S: Sequence<any JSONWebValidatingKey> {
        try verify(using: JSONWebKeySet(keys: .init(keys)), for: audience)
    }
    
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify(using key: some JSONWebValidatingKey, for audience: String? = nil) throws {
        try verify(using: JSONWebKeySet(keys: [key]), for: audience)
    }
}

#if canImport(Foundation.NSURLSession)
extension URLRequest {
    /// The `Authorization` http header in `Bearer` with given JSON Web Token (JWT).
    public var authorizationToken: JSONWebToken? {
        get {
            (value(forHTTPHeaderField: "Authorization")?
                .replacingOccurrences(of: "Bearer ", with: "", options: [.anchored]))
                .flatMap(JSONWebToken.init)
        }
        set {
            setValue((newValue.map { "Bearer \($0.description)" }), forHTTPHeaderField: "Authorization")
        }
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - keySet: A `JSONWebKeySet` object contains keys that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verifyAuthorizationToken(using keySet: JSONWebKeySet, for audience: String? = nil) throws {
        guard let authorizationToken = authorizationToken else {
            throw CryptoKitError.authenticationFailure
        }
        try authorizationToken.verify(using: keySet, for: audience)
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verifyAuthorizationToken<S>(using keys: S, for audience: String? = nil) throws where S: Sequence, S.Element: JSONWebValidatingKey {
        try verifyAuthorizationToken(using: JSONWebKeySet(keys: keys), for: audience)
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify<S>(using keys: S, for audience: String? = nil) throws where S: Sequence<any JSONWebValidatingKey> {
        try verifyAuthorizationToken(using: JSONWebKeySet(keys: .init(keys)), for: audience)
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify(using key: some JSONWebValidatingKey, for audience: String? = nil) throws {
        try verifyAuthorizationToken(using: JSONWebKeySet(keys: [key]), for: audience)
    }
}
#endif
