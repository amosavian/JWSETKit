//
//  KeysetURL.swift
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

#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking) || canImport(AsyncHTTPClient)
/// Predefined JWKS providers for major identity platforms.
public struct JSONWebKeySetProvider: Hashable, Sendable {
    /// The URL of the JWKS endpoint.
    public let url: URL
    
    /// Creates a custom JWKS provider with the given URL.
    ///
    /// - Parameter url: The URL of the JWKS endpoint.
    public init(url: URL) {
        self.url = url
    }
    
    init(_ string: String) {
        self.init(url: URL(string: string).unsafelyUnwrapped)
    }
    
    /// Apple Sign-In JWKS endpoint.
    ///
    /// Used for verifying tokens from Sign in with Apple.
    public static let apple = JSONWebKeySetProvider("https://appleid.apple.com/auth/keys")
    
    /// Google Identity JWKS endpoint.
    ///
    /// Used for verifying Google OAuth2 and Google Identity tokens.
    public static let google = JSONWebKeySetProvider("https://www.googleapis.com/oauth2/v3/certs")
    
    /// Firebase Authentication JWKS endpoint.
    ///
    /// Used for verifying Firebase Auth ID tokens.
    public static let firebase = JSONWebKeySetProvider(
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
    )
    
    /// Microsoft/Azure AD JWKS endpoint.
    ///
    /// Used for verifying Microsoft identity platform tokens.
    public static let microsoft = JSONWebKeySetProvider("https://login.microsoftonline.com/common/discovery/keys")
    
    private struct OpenIDDiscovery: Codable, Hashable {
        private enum CodingKeys: String, CodingKey {
            case jwksURI = "jwks_uri"
        }

        var jwksURI: URL
    }
    
    /// Fetches JWKS URL from OpenID configuration from given URL
    ///
    /// - Parameter url: Base URL of OpenID IAM provider
    /// - Returns: Provider from `jwks_uri` of OpenID configuration
    public static func openID(_ url: URL) async throws -> Self {
        guard let configurationURL = URL(string: "/.well-known/openid-configuration", relativeTo: url) else {
            throw HTTPError.unknownError
        }
        
        let data = try await httpClient.fetch(url: configurationURL)
        let jwksURL = try JSONDecoder().decode(OpenIDDiscovery.self, from: data).jwksURI
        return .init(url: jwksURL)
    }
}

extension JSONWebKeySet {
    /// Initializes JWKSet using given contents of given URL.
    ///
    /// - Parameter url: The URL of the JWKSet (`jku`)..
    ///
    /// - Throws: `DecodingError` if the data is not valid JSON or not a JWKSet.
    /// - Throws: `URLError` if the URL is not reachable.
    public init(url: URL) async throws {
        let data = try await httpClient.fetch(url: url)
        self = try JSONDecoder().decode(Self.self, from: data)
    }
    
    /// Initializes JWKSet by fetching from a predefined identity provider.
    ///
    /// - Parameter provider: The identity provider to fetch JWKS from.
    ///
    /// - Throws: `DecodingError` if the data is not valid JSON or not a JWKSet.
    /// - Throws: `URLError` if the URL is not reachable.
    ///
    /// Example usage:
    /// ```swift
    /// // Fetch Apple Sign-In keys
    /// let appleKeys = try await JSONWebKeySet(provider: .apple)
    ///
    /// // Fetch Google Identity keys
    /// let googleKeys = try await JSONWebKeySet(provider: .google)
    /// ```
    public init(provider: JSONWebKeySetProvider) async throws {
        try await self.init(url: provider.url)
    }
}

extension JSONWebTokenConfirmation {
    /// Attempts to resolve and return a validating key based on the proof-of-possession claim.
    ///
    /// This method inspects the current confirmation (`cnf`) claim and tries to find a matching
    /// validating key from the provided key sets and tries to download if key set url is provided.
    /// It supports all confirmation types, including
    /// direct key, encrypted key, key set URL, key ID, and thumbprints.
    ///
    /// - Parameters:
    ///   - keySet: An optional `JSONWebKeySet` containing candidate keys for matching by key ID, or thumbprint.
    ///   - decryptingKeyset: An optional `JSONWebKeySet` containing private keys for decrypting an encrypted key.
    /// - Returns: A matching key conforming to `JSONWebValidatingKey` if found.
    /// - Throws: `JSONWebKeyError.keyNotFound` if no matching key is found, or errors from decryption or decoding.
    public func resolveKey(using keySet: JSONWebKeySet = .init(), decryptingKeyset: JSONWebKeySet? = nil) async throws -> any JSONWebValidatingKey {
        let result: any JSONWebValidatingKey
        switch self {
        case .url(let url, _):
            if let result = try? matchKey(from: keySet, decryptingKeyset: decryptingKeyset) {
                return result
            }
            let fetchedKeySet = try await JSONWebKeySet(url: url)
            result = try matchKey(from: fetchedKeySet, decryptingKeyset: decryptingKeyset)
        default:
            result = try matchKey(from: keySet, decryptingKeyset: decryptingKeyset)
        }
        try result.verifyDate()
        return result
    }
}
#endif
