//
//  NIOHTTP1.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/12/16.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

#if canImport(NIOHTTP1)
import NIOHTTP1

extension HTTPHeaders {
    /// The `Authorization` http header in `Bearer` with given JSON Web Token (JWT).
    public var authorizationToken: JSONWebToken? {
        get {
            let value = (self["Authorization"].first)?
                .replacingOccurrences(of: "Bearer ", with: "", options: [.anchored])
            return value.flatMap(JSONWebToken.init)
        }
        set {
            if let token = newValue.map({ "Bearer \($0.description)" }) {
                replaceOrAdd(name: "Authorization", value: token)
            } else {
                remove(name: "Authorization")
            }
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
    public func verifyAuthorizationToken<S>(using keys: S, for audience: String? = nil) throws where S: Sequence<any JSONWebValidatingKey> {
        try verifyAuthorizationToken(using: JSONWebKeySet(keys: .init(keys)), for: audience)
    }
    
    /// Verifies `Authorization`'s header token validity and signature.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verifyAuthorizationToken(using key: some JSONWebValidatingKey, for audience: String? = nil) throws {
        try verifyAuthorizationToken(using: JSONWebKeySet(keys: [key]), for: audience)
    }
}
#endif

#if canImport(AsyncHTTPClient)
import AsyncHTTPClient

enum HTTPClientFetch: HTTPFetch {
    static func fetch(url: URL) async throws -> Data {
        let request = HTTPClientRequest(url: url.absoluteString)
        let response = try await HTTPClient.shared.execute(request, timeout: .seconds(30))
        if (200 ..< 300).contains(response.status.code) {
            var body = try await response.body.collect(upTo: 64 * 1024 * 1024) // 64 MB
            return Data(body.readBytes(length: body.readableBytes) ?? .init())
        } else {
            throw HTTPError.fromStatus(response.status.code)
        }
    }
}
#endif
