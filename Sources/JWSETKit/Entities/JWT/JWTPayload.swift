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

/// Claims and payload in a JWT.
public struct JSONWebTokenClaims: MutableJSONWebContainer, Sendable {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
}

/// A JWS object that contains JWT registered tokens.
public typealias JSONWebToken = JSONWebSignature<ProtectedJSONWebContainer<JSONWebTokenClaims>>

extension JSONWebToken {
    /// Creates a new JWT with given payload then signs with given key.
    /// - Parameters:
    ///   - payload: JWT payload.
    ///   - algorithm: Sign and hash algorithm.
    ///   - signingKey: The key to sign the payload.
    public init<SK>(
        payload: JSONWebTokenClaims,
        algorithm: JSONWebSignatureAlgorithm,
        using signingKey: SK
    ) throws where SK: JSONWebSigningKey {
        guard algorithm.keyType == signingKey.keyType else {
            throw JSONWebKeyError.operationNotAllowed
        }
        self.signatures = try [
            .init(
                protected: JOSEHeader(
                    algorithm: algorithm,
                    type: .jwt,
                    keyId: signingKey.keyId
                ),
                signature: .init()
            ),
        ]
        self.payload = try .init(value: payload)
        try updateSignature(using: signingKey)
    }
}

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
}
#endif
