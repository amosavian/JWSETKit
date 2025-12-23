//
//  CertificateURL.swift
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
import SwiftASN1

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(AsyncHTTPClient)
import AsyncHTTPClient
#endif

#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking) || canImport(AsyncHTTPClient)
extension MutableJSONWebContainer {
    fileprivate func loadCertificateFromURL() async throws -> [String] {
        guard let url: URL = self["x5u"] else {
            throw JSONWebValidationError.missingRequiredField(key: "x5u")
        }
        let data = try await httpClient.fetch(url: url)
        return try PEMDocument.parseMultiple(pemString: .init(decoding: data, as: UTF8.self))
            .map(\.derBytes).map { Data($0).base64EncodedString() }
    }
    
    fileprivate var _resolvedCertificateChain: JSONWebCertificateChain {
        get async throws {
            let chain: [String]
            if storage.contains(key: "x5c") {
                chain = self["x5c"] ?? []
            } else {
                chain = try await loadCertificateFromURL()
            }
            return try .init { container in
                container["x5c"] = chain
                container["x5u"] = self.storage["x5u"]
            }
        }
    }
}

extension MutableJSONWebKey {
    /// Returns certificate chain from embedded chain in `x5c` or fetched certificates from url (`x5u`).
    public var resolvedCertificateChain: JSONWebCertificateChain {
        get async throws {
            try await _resolvedCertificateChain
        }
    }
}

extension JOSEHeader {
    public var resolvedCertificateChain: JSONWebCertificateChain {
        get async throws {
            try await _resolvedCertificateChain
        }
    }
}
#endif
