//
//  JWTPayload.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation

@dynamicMemberLookup
public struct JSONWebTokenClaims: JSONWebContainer {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebTokenClaims {
        .init(storage: storage)
    }
}

/// A JWS object that contains JWT registered tokens.
public typealias JSONWebToken = JSONWebSignature<JSONWebTokenClaims>

extension JSONWebToken {
    /// Verifies the `exp` and `nbf` headers using current date.
    ///
    /// - Parameters:
    ///   - currentDate: The date that headers will be check against. Default is current system date.
    public func verifyDate(_ currentDate: Date = .init()) throws {
        let claims = payload.value
        if let expiry = claims.expiry, currentDate > expiry {
            throw JSONWebTokenError.tokenExpired(expiry: expiry)
        }
        if let notBefore = claims.notBefore, currentDate < notBefore {
            throw JSONWebTokenError.tokenInvalidBefore(notBefore: notBefore)
        }
    }
}
