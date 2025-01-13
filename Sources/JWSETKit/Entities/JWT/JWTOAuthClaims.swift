//
//  JWTOAuthClaims.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Claims registered in [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)
public struct JSONWebTokenClaimsOAuthParameters: JSONWebContainerParameters {
    public typealias Container = JSONWebTokenClaims
    
    /// The authorization and token endpoints allow the client to specify the scope
    /// of the access request using the "scope" request parameter.
    ///
    /// In turn, the authorization server uses the "scope" response parameter
    /// to inform the client of the scope of the access token issued.
    public var scope: String?
    
    /// The authorization and token endpoints allow the client to specify the scope
    /// of the access request using the "scope" request parameter.
    ///
    /// In turn, the authorization server uses the "scope" response parameter
    /// to inform the client of the scope of the access token issued.
    public var scopes: [String]
    
    /// The authorization server issues the registered client a client identifier
    /// -- a unique string representing the registration information provided by the client.
    ///
    /// The client identifier is not a secret; it is exposed to the resource owner and MUST NOT
    /// be used alone for client authentication.
    /// The client identifier is unique to the authorization server.
    ///
    /// The client identifier string size is left undefined by this specification.
    /// The client should avoid making assumptions about the identifier size.
    /// The authorization server SHOULD document the size of any identifier it issues.
    public var clientID: String?
    
    @_documentation(visibility: private)
    public static let keys: [PartialKeyPath<Self>: String] = [
        \.scope: "scope", \.scopes: "scope", \.clientID: "client_id",
    ]
}

extension JSONWebTokenClaims {
    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsOAuthParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsOAuthParameters, [String]>) -> [String] {
        get {
            (storage[stringKey(keyPath)] as String?)?.components(separatedBy: " ") ?? []
        }
        set {
            storage[stringKey(keyPath)] = newValue.joined(separator: " ")
        }
    }
}
