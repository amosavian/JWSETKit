//
//  HTTPTypes.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

#if canImport(HTTPTypes)
import HTTPTypes

extension HTTPFields {
    /// The `Authorization` http header in `Bearer` with given JSON Web Token (JWT).
    public var authorizationToken: JSONWebToken? {
        get {
            (self[.authorization]?.strippingAuthScheme())
                .flatMap(JSONWebToken.init)
        }
        set {
            self[.authorization] = newValue.map { "Bearer \($0.description)" }
        }
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - keySet: A `JSONWebKeySet` object contains keys that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verifyAuthorizationToken(using keySet: JSONWebKeySet, for audience: String? = nil) throws {
        guard let authorizationToken else {
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
    public func verifyAuthorizationToken<S>(using keys: S, for audience: String? = nil) throws where S: Sequence<any JSONWebValidatingKey> {
        try verifyAuthorizationToken(using: JSONWebKeySet(keys: .init(keys)), for: audience)
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verifyAuthorizationToken(using key: some JSONWebValidatingKey, for audience: String? = nil) throws {
        try verifyAuthorizationToken(using: JSONWebKeySet(key: key), for: audience)
    }
}
#endif
