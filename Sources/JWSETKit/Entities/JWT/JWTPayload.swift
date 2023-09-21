//
//  JWTPayload.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation

/// Claims and payload in a JWT.
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
public typealias JSONWebToken = JSONWebSignature<ProtectedJSONWebContainer<JSONWebTokenClaims>>

#if canImport(Foundation.NSURLSession)
extension URLRequest {
    public var authorizationJWT: JSONWebToken? {
        get {
            (value(forHTTPHeaderField: "Authorization")?
                .replacingOccurrences(of: "Bearer ", with: "", options: [.anchored]))
            .flatMap(JSONWebToken.init)
        }
        set {
            setValue("Bearer \(description)", forHTTPHeaderField: "Authorization")
        }
    }
}
#endif

extension JSONWebToken: Expirable {
    /// Verifies the `exp` and `nbf` headers using current date.
    ///
    /// - Parameters:
    ///   - currentDate: The date that headers will be check against. Default is current system date.
    public func verifyDate(_ currentDate: Date) throws {
        let claims = payload.value
        if let expiry = claims.expiry, currentDate > expiry {
            throw JSONWebValidationError.tokenExpired(expiry: expiry)
        }
        if let notBefore = claims.notBefore, currentDate < notBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notBefore)
        }
    }
}
