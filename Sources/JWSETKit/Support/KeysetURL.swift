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

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(AsyncHTTPClient)
import AsyncHTTPClient
#endif

#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking) || canImport(AsyncHTTPClient)
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
