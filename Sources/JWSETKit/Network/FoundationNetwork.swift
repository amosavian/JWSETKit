//
//  FoundationNetwork.swift
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

protocol HTTPFetch {
    static func fetch(url: URL) async throws -> Data
}

var httpClient: any HTTPFetch.Type {
#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking)
    return URLSessionHTTPFetch.self
#elseif canImport(AsyncHTTPClient)
    return HTTPClientFetch.self
#endif
}

#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking)
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum URLSessionHTTPFetch: HTTPFetch {
    static func fetch(url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let response = response as? HTTPURLResponse else {
            throw HTTPError.connectionError
        }
        switch response.statusCode {
        case 200 ..< 300:
            return data
        default:
            throw HTTPError.fromStatus(response.statusCode)
        }
    }
}

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
