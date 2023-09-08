//
//  File.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

// Claims registered in [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)
public struct JSONWebTokenClaimsOAuthParameters {
    /// The authorization and token endpoints allow the client to specify the scope
    /// of the access request using the "scope" request parameter.
    ///
    /// In turn, the authorization server uses the "scope" response parameter
    /// to inform the client of the scope of the access token issued.
    public var scope: String? { fatalError() }
    
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
    public var clientID: String? { fatalError() }
    
    fileprivate static let keys: [PartialKeyPath<Self>: String] = [:]
}

extension JSONWebTokenClaims {
    private func stringKey<T>(_ keyPath: KeyPath<JSONWebTokenClaimsOAuthParameters, T>) -> String {
        if let key = JSONWebTokenClaimsOAuthParameters.keys[keyPath] {
            return key
        }
        return String(reflecting: keyPath).components(separatedBy: ".").last!.jsonWebKey
    }
    
    public subscript<T>(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsOAuthParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
