//
//  DPoP+HTTPTypes.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

#if canImport(HTTPTypes)
import HTTPTypes

extension HTTPField.Name {
    /// The `DPoP` http header field carrying a DPoP proof JWT, per RFC 9449.
    public static let dpop = HTTPField.Name("DPoP")!
}

extension HTTPFields {
    /// The DPoP proof JWT carried in the `DPoP` http header, per RFC 9449.
    ///
    /// Returns `nil` when the header is absent or not a parseable proof. To attach a proof,
    /// use ``setDPoPProof(method:url:nonce:algorithm:issuedAt:jwtId:using:)``.
    public var dpopProof: DPoPProof? {
        self[.dpop].flatMap { try? DPoPProof(from: $0) }
    }
    
    /// Verifies the `DPoP` header proof against the given request, per
    /// [RFC 9449 §4.3](https://datatracker.ietf.org/doc/html/rfc9449#section-4.3).
    ///
    /// The caller supplies the request's method and absolute target URI. The access token
    /// for the `ath` binding is read from this collection's `Authorization` header.
    ///
    /// - Parameters:
    ///   - method: The HTTP method of the request, compared to `htm`.
    ///   - url: The absolute target URI, compared to `htu` after normalization.
    ///   - nonce: When provided, the proof's `nonce` must equal it.
    ///   - currentDate: The reference time used to reject future-dated proofs.
    /// - Throws: `CryptoKitError.authenticationFailure` if the `DPoP` header is absent or
    ///   appears more than once, or a validation/crypto error when any check fails.
    public func verifyDPoPProof(
        method: HTTPRequest.Method,
        url: URL,
        nonce: String? = nil,
        currentDate: Date = .init()
    ) throws {
        // RFC 9449 §4.3 #1: there is not more than one `DPoP` HTTP request header field.
        guard self[fields: .dpop].count == 1, let dpopProof else {
            throw CryptoKitError.authenticationFailure
        }
        try dpopProof.verify(method: method.rawValue, url: url, accessToken: self[.authorization], nonce: nonce, currentDate: currentDate)
    }

    /// Mints a DPoP proof for the given request and attaches it, switching the access token
    /// to the `DPoP` authentication scheme, per RFC 9449.
    ///
    /// The access token bound via the `ath` claim is read from this collection's
    /// `Authorization` header.
    ///
    /// - Parameters:
    ///   - method: The HTTP method of the request (`htm`).
    ///   - url: The absolute target URI of the request (`htu`).
    ///   - nonce: An optional server-provided `nonce`.
    ///   - algorithm: The asymmetric signature algorithm. If `nil`, it is inferred from the key.
    ///   - issuedAt: The proof creation time (`iat`). Defaults to now.
    ///   - jwtId: The unique proof identifier (`jti`). Defaults to a random value.
    ///   - signingKey: The asymmetric key used to sign the proof.
    /// - Throws: `JSONWebKeyError.unknownAlgorithm` if the key's algorithm cannot be resolved.
    public mutating func setDPoPProof(
        method: HTTPRequest.Method,
        url: URL,
        nonce: String? = nil,
        algorithm: JSONWebSignatureAlgorithm? = nil,
        issuedAt: Date = .init(),
        jwtId: String = UUID().uuidString,
        using signingKey: some JSONWebSigningKey
    ) throws {
        let proof = try DPoPProof(
            method: method.rawValue,
            url: url,
            accessToken: self[.authorization],
            nonce: nonce,
            algorithm: algorithm,
            issuedAt: issuedAt,
            jwtId: jwtId,
            using: signingKey
        )
        self[.dpop] = proof.description

        // When an access token is present, it must be presented with the `DPoP`
        // authentication scheme rather than `Bearer` (RFC 9449 §7.1).
        if let authorization = self[.authorization] {
            self[.authorization] = "DPoP \(authorization.strippingAuthScheme())"
        }
    }
}

extension HTTPRequest {
    /// Verifies the `DPoP` header proof carried in this request, per
    /// [RFC 9449 §4.3](https://datatracker.ietf.org/doc/html/rfc9449#section-4.3).
    ///
    /// The `htm`/`htu` are taken from this request's method and ``url``, and the access
    /// token for the `ath` binding is read from the request's `Authorization` header.
    ///
    /// - Parameters:
    ///   - nonce: When provided, the proof's `nonce` must equal it.
    ///   - currentDate: The reference time used to reject future-dated proofs.
    /// - Throws: `JSONWebValidationError.missingRequiredField` if the request `url` is
    ///   unavailable (absent scheme or authority), or a validation/crypto error otherwise.
    public func verifyDPoPProof(
        nonce: String? = nil,
        currentDate: Date = .init()
    ) throws {
        guard let url else {
            throw JSONWebValidationError.missingRequiredField(key: "url")
        }
        try headerFields.verifyDPoPProof(
            method: method,
            url: url,
            nonce: nonce,
            currentDate: currentDate
        )
    }
    
    /// Mints a DPoP proof for this request and attaches it, switching the access token to
    /// the `DPoP` authentication scheme, per RFC 9449.
    ///
    /// The proof's `htm`/`htu` are taken from this request's method and reconstructed
    /// absolute URL. When the request carries an access token in its `Authorization`
    /// header, that token is bound via the proof's `ath` claim and the header's scheme is
    /// rewritten from `Bearer` to `DPoP`, as required by
    /// [RFC 9449 §7.1](https://datatracker.ietf.org/doc/html/rfc9449#section-7.1).
    ///
    /// - Parameters:
    ///   - nonce: An optional server-provided `nonce` (from a prior `DPoP-Nonce` response).
    ///   - algorithm: The asymmetric signature algorithm. If `nil`, it is inferred from the key.
    ///   - issuedAt: The proof creation time (`iat`). Defaults to now.
    ///   - jwtId: The unique proof identifier (`jti`). Defaults to a random value.
    ///   - signingKey: The asymmetric key used to sign the proof.
    /// - Throws: `JSONWebValidationError.missingRequiredField` if the request `url` is
    ///   unavailable (absent scheme or authority).
    public mutating func setDPoPProof(
        nonce: String? = nil,
        algorithm: JSONWebSignatureAlgorithm? = nil,
        issuedAt: Date = .init(),
        jwtId: String = UUID().uuidString,
        using signingKey: some JSONWebSigningKey
    ) throws {
        guard let url else {
            throw JSONWebValidationError.missingRequiredField(key: "url")
        }
        try headerFields.setDPoPProof(
            method: method,
            url: url,
            nonce: nonce,
            algorithm: algorithm,
            issuedAt: issuedAt,
            jwtId: jwtId,
            using: signingKey
        )
    }
}
#endif
