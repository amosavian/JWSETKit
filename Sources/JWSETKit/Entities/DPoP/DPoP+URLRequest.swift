//
//  DPoP+URLRequest.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto

#if canImport(Foundation.NSURLSession) || canImport(FoundationNetworking)
extension URLRequest {
    /// The DPoP proof JWT carried in the `DPoP` http header, per RFC 9449.
    ///
    /// Returns `nil` when the header is absent or not a parseable proof. To attach a proof,
    /// use ``setDPoPProof(nonce:algorithm:issuedAt:jwtId:using:)``.
    public var dpopProof: DPoPProof? {
        value(forHTTPHeaderField: "DPoP").flatMap { try? DPoPProof(from: $0) }
    }

    /// Mints a DPoP proof for this request and attaches it, switching the access token to
    /// the `DPoP` authentication scheme, per RFC 9449.
    ///
    /// The proof's `htm`/`htu` are taken from this request's method (defaulting to `"GET"`)
    /// and URL. When the request carries an access token in its `Authorization` header, that
    /// token is bound via the proof's `ath` claim and the header's scheme is rewritten from
    /// `Bearer` to `DPoP` (`Authorization: DPoP <token>`), per
    /// [RFC 9449 §7.1](https://datatracker.ietf.org/doc/html/rfc9449#section-7.1).
    ///
    /// - Parameters:
    ///   - nonce: An optional server-provided `nonce` (from a prior `DPoP-Nonce` response).
    ///   - algorithm: The asymmetric signature algorithm. If `nil`, it is inferred from the key.
    ///   - issuedAt: The proof creation time (`iat`). Defaults to now.
    ///   - jwtId: The unique proof identifier (`jti`). Defaults to a random value.
    ///   - signingKey: The asymmetric key used to sign the proof.
    /// - Throws: `JSONWebValidationError.missingRequiredField` if the request has no URL.
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
        let proof = try DPoPProof(
            method: httpMethod ?? "GET",
            url: url,
            accessToken: value(forHTTPHeaderField: "Authorization"),
            nonce: nonce,
            algorithm: algorithm,
            issuedAt: issuedAt,
            jwtId: jwtId,
            using: signingKey
        )
        setValue(proof.description, forHTTPHeaderField: "DPoP")

        // When an access token is present, it must be presented with the `DPoP`
        // authentication scheme rather than `Bearer` (RFC 9449 §7.1).
        if let authorization = value(forHTTPHeaderField: "Authorization") {
            setValue("DPoP \(authorization.strippingAuthScheme())", forHTTPHeaderField: "Authorization")
        }
    }
}
#endif
