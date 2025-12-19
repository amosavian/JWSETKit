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
extension MutableJSONWebKey {
#if canImport(X509) || canImport(CommonCrypto)
    /// Returns certificate chain from embedded chain in `x5c` or fetched certificates from url (`x5u`).
    public var resolvedCertificateChain: JSONWebCertificateChain {
        get async throws {
            // swiftformat:disable:next redundantSelf
            if !self.certificateChain.isEmpty {
                // swiftformat:disable:next redundantSelf
                return .init(self.certificateChain)
            }
            return try await .init(fetchedCertificatesFromURL().certificateChain)
        }
    }
#endif
    
    mutating func fetchCertificatesFromURL() async throws {
        // swiftformat:disable:next redundantSelf
        guard let url = self.certificateURL else {
            throw JSONWebKeyError.operationNotAllowed
        }
        let data = try await httpClient.fetch(url: url)
        let certificates = try PEMDocument.parseMultiple(pemString: .init(decoding: data, as: UTF8.self))
            .map(\.derBytes).map { $0.urlBase64EncodedString() }
        self["x5c"] = certificates
    }
    
    func fetchedCertificatesFromURL() async throws -> Self {
        var result = self
        try await result.fetchCertificatesFromURL()
        return result
    }
}

extension JOSEHeader {
#if canImport(X509) || canImport(CommonCrypto)
    public var resolvedCertificateChain: JSONWebCertificateChain {
        get async throws {
            // swiftformat:disable:next redundantSelf
            if !self.certificateChain.isEmpty {
                // swiftformat:disable:next redundantSelf
                return .init(self.certificateChain)
            }
            return try await .init(fetchedCertificatesFromURL().certificateChain)
        }
    }
#endif
    
    mutating func fetchCertificatesFromURL() async throws {
        // swiftformat:disable:next redundantSelf
        guard let url = self.certificateURL else {
            throw JSONWebKeyError.operationNotAllowed
        }
        let data = try await httpClient.fetch(url: url)
        let certificates = try PEMDocument.parseMultiple(pemString: .init(decoding: data, as: UTF8.self))
            .map(\.derBytes).map { $0.urlBase64EncodedString() }
        self["x5c"] = certificates
    }
    
    func fetchedCertificatesFromURL() async throws -> Self {
        var result = self
        try await result.fetchCertificatesFromURL()
        return result
    }
}
#endif
