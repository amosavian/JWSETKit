//
//  JSONWebCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 2/6/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1
#if canImport(X509)
import X509
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

#if canImport(X509)
public typealias CertificateType = Certificate
#elseif canImport(CommonCrypto)
public typealias CertificateType = SecCertificate
#else
public typealias CertificateType = Data
#endif

/// JSON Web Key (JWK) container for X509 Certificate chain.
///
/// - Important: To load certificate chain from `x5u`, use ``resolvedCertificateChain``.
@frozen
public struct JSONWebCertificateChain: MutableJSONWebKey, JSONWebValidatingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    /// Leaf certiticate of certificate chain which is first one in array.
    public var leaf: CertificateType {
#if canImport(X509) || canImport(CommonCrypto)
        // As we verify key when initializing, we shall assume key is valid
        (try? .init(from: self)).unsafelyUnwrapped
#else
        // swiftformat:disable:next redundantSelf
        self.certificateChain.first.unsafelyUnwrapped
#endif
    }
    
    var leafKey: any JSONWebValidatingKey {
        get throws {
#if canImport(X509)
            return leaf.publicKey
#elseif canImport(CommonCrypto)
            guard let publicKey = leaf.publicKey else {
                throw JSONWebKeyError.keyNotFound
            }
            return publicKey
#else
            return try InternalCertificate(derEncoded: [UInt8](leaf)).publicKey
#endif
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init(_ certificates: [CertificateType]) throws {
        guard let leaf = certificates.first else {
            throw JSONWebKeyError.keyNotFound
        }
#if canImport(X509)
        var key = AnyJSONWebKey(leaf.publicKey)
#elseif canImport(CommonCrypto)
        guard let publicKey = leaf.publicKey else {
            throw JSONWebKeyError.keyNotFound
        }
        var key = AnyJSONWebKey(publicKey)
#else
        var key = try AnyJSONWebKey(InternalCertificate(derEncoded: [UInt8](leaf)).publicKey)
#endif
        key.certificateChain = certificates
        self.storage = key.storage
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard !self.certificateChain.isEmpty else {
            throw JSONWebKeyError.keyNotFound
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try leafKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try leafKey.thumbprint(format: format, using: hashFunction)
    }
    
/// Verify validity of certificate chain with RFC 5280 policy.
#if !canImport(X509) && !canImport(CommonCrypto)
    @available(*, unavailable, message: "This function relies on swift-certificate or Apple's CommonCrypto framework.")
#endif
    public func verifyChain(currentDate: Date? = nil) async throws {
#if canImport(X509)
        // swiftformat:disable:next redundantSelf
        let chain = self.certificateChain
        _ = try await chain.verifyChain(currentDate: currentDate)
#elseif canImport(CommonCrypto)
        try await SecTrust(from: self).verifyChain(currentDate: currentDate)
#else
        throw JSONWebKeyError.operationNotAllowed
#endif
    }
}

extension JSONWebCertificateChain: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
#if canImport(X509) || canImport(CommonCrypto)
        try leaf.verifyDate(currentDate)
#else
        try InternalCertificate(derEncoded: [UInt8](leaf)).verifyDate(currentDate)
#endif
    }
}

#if canImport(X509)
extension Verifier {
    public mutating func validate(
        chain: JSONWebCertificateChain,
        diagnosticCallback: ((VerificationDiagnostic) -> Void)? = nil
    ) async -> CertificateValidationResult {
        await validate(
            leaf: chain.leaf,
            intermediates: .init(chain.certificateChain.dropFirst()),
            diagnosticCallback: diagnosticCallback
        )
    }
}
#endif

// MARK: - Certificate parser

private struct Time: DERParseable, Sendable {
    let value: Date
    
    init(value: Date) {
        self.value = value
    }
    
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case GeneralizedTime.defaultIdentifier:
            let time = try GeneralizedTime(derEncoded: node)
            self = .init(value: .init(time))
        case UTCTime.defaultIdentifier:
            let time = try UTCTime(derEncoded: node)
            self = .init(value: .init(time))
        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }
}

private struct Validity: DERParseable, Sendable {
    let notBefore: Date
    let notAfter: Date
    
    init(notBefore: Date, notAfter: Date) {
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
    
    init(derEncoded node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: .sequence) { nodes in
            let notBefore = try Time(derEncoded: &nodes)
            let notAfter = try Time(derEncoded: &nodes)
            return Validity(notBefore: notBefore.value, notAfter: notAfter.value)
        }
    }
}

private struct InternalTBSCertificate: DERParseable, Sendable {
    let validity: Validity
    let publicKeyInfo: SubjectPublicKeyInfo
    
    private init(validity: Validity, publicKeyInfo: SubjectPublicKeyInfo) {
        self.validity = validity
        self.publicKeyInfo = publicKeyInfo
    }
    
    init(derEncoded node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: .sequence) { nodes in
            let version = try DER.decodeDefaultExplicitlyTagged(
                &nodes,
                tagNumber: 0,
                tagClass: .contextSpecific,
                defaultValue: Int(0)
            )
            guard (0 ... 2).contains(version) else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid X.509 version \(version)")
            }
            
            _ /* serialNumber */ = nodes.next()
            _ /* signature */ = nodes.next()
            _ /* issuer */ = nodes.next()
            let validity = try Validity(derEncoded: &nodes)
            _ /* subject */ = nodes.next()
            let subjectPublicKeyInfo = try SubjectPublicKeyInfo(derEncoded: &nodes)
            while nodes.next() != nil {
                // Ignore remaining fields
            }
            return .init(validity: validity, publicKeyInfo: subjectPublicKeyInfo)
        }
    }
}

struct InternalCertificate: DERParseable, Sendable, Expirable {
    private let tbsCertificate: InternalTBSCertificate
    
    var notValidBefore: Date {
        tbsCertificate.validity.notBefore
    }
    
    var notValidAfter: Date {
        tbsCertificate.validity.notAfter
    }
    
    var publicKeyInfo: SubjectPublicKeyInfo {
        tbsCertificate.publicKeyInfo
    }
    
    var publicKey: any JSONWebValidatingKey {
        get throws {
            let key = try AnyJSONWebKey(importing: publicKeyInfo.derRepresentation, format: .spki).specialized()
            guard let publicKey = key as? (any JSONWebValidatingKey) else {
                throw CryptoKitASN1Error.invalidASN1Object
            }
            return publicKey
        }
    }
    
    private init(tbsCertificate: InternalTBSCertificate) {
        self.tbsCertificate = tbsCertificate
    }
    
    init(derEncoded node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: .sequence) { nodes in
            guard let tbsCertificateNode = nodes.next() else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid certificate object, insufficient ASN.1 nodes")
            }
            let tbsCertificate = try InternalTBSCertificate(derEncoded: tbsCertificateNode)
            while nodes.next() != nil {
                // Ignore remaining fields
            }
            return .init(tbsCertificate: tbsCertificate)
        }
    }
    
    func verifyDate(_ currentDate: Date) throws {
        if currentDate > notValidAfter {
            throw JSONWebValidationError.tokenExpired(expiry: notValidAfter)
        }
        if currentDate < notValidBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notValidAfter)
        }
    }
}

extension Date {
    @inlinable
    init(fromUTCDate date: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) {
        self = Calendar(identifier: .gregorian)
            .date(from: .init(
                timeZone: .init(secondsFromGMT: 0).unsafelyUnwrapped,
                year: date.year, month: date.month, day: date.day,
                hour: date.hours, minute: date.minutes, second: date.seconds
            )).unsafelyUnwrapped
    }
    
    @inlinable
    var utcDate: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int) {
        let date = Calendar(identifier: .gregorian).dateComponents(in: .init(secondsFromGMT: 0).unsafelyUnwrapped, from: self)
        return (
            date.year.unsafelyUnwrapped,
            date.month.unsafelyUnwrapped,
            date.day.unsafelyUnwrapped,
            date.hour.unsafelyUnwrapped,
            date.minute.unsafelyUnwrapped,
            date.second.unsafelyUnwrapped
        )
    }
    
    @inlinable
    public init(_ time: GeneralizedTime) {
        self.init(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day,
                hours: time.hours, minutes: time.minutes, seconds: time.seconds
            )
        )
    }
    
    @inlinable
    public init(_ time: UTCTime) {
        self.init(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day,
                hours: time.hours, minutes: time.minutes, seconds: time.seconds
            )
        )
    }
}
