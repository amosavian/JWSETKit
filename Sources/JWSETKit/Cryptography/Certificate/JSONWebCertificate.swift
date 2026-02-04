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
typealias InternalCertificateType = CertificateType
#elseif canImport(CommonCrypto)
public typealias CertificateType = SecCertificate
typealias InternalCertificateType = CertificateType
#else
public typealias CertificateType = Data
typealias InternalCertificateType = InternalCertificate
#endif

/// JSON Web Key (JWK) container for X509 Certificate chain.
///
/// - Important: To load certificate chain from `x5u`, use ``resolvedCertificateChain``.
@frozen
public struct JSONWebCertificateChain: MutableJSONWebKey, JSONWebValidatingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    /// Leaf certiticate of certificate chain which is first one in array.
    public var leaf: CertificateType {
        // As we verify key when initializing, we shall assume key is valid
        // swiftformat:disable:next redundantSelf
        self.certificateChain.first.unsafelyUnwrapped
    }
    
    var leafCertificate: InternalCertificateType {
        get throws {
#if canImport(X509) || canImport(CommonCrypto)
            return leaf
#else
            return try InternalCertificate(leaf)
#endif
        }
    }
    
    var leafKey: any JSONWebValidatingKey {
        get throws {
            try leafCertificate.publicKey
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init<T>(_ certificates: T) throws where T: Collection, T.Element: DataProtocol {
        guard let leaf = certificates.first else {
            throw JSONWebKeyError.keyNotFound
        }
        var key = try AnyJSONWebKey(InternalCertificate(leaf).publicKey)
        key.certificateChainData = certificates.map { Data($0) }
        self.storage = key.storage
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard let leaf = self.certificateChainData.first else {
            throw JSONWebKeyError.keyNotFound
        }
        _ = try InternalCertificate(leaf).publicKey
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try leafKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try leafKey.thumbprint(format: format, using: hashFunction)
    }
    
#if !canImport(X509) && !canImport(CommonCrypto)
    @available(*, unavailable, message: "This function relies on swift-certificate or Apple's CommonCrypto framework.")
#endif
    /// Verify validity of certificate chain with RFC 5280 policy and validate the leaf certificate
    /// presented by a server during a TLS handshake, if hostname is provided.
    ///
    /// - Parameters:
    ///   - currentDate: The fixed time to compare against when determining if the certificates in the chain have expired.
    ///   - hostName: The hostname used to connect to the server.
    public func verifyChain(currentDate: Date? = nil, hostName: String? = nil) async throws {
#if canImport(X509)
        // swiftformat:disable:next redundantSelf
        let chain = self.certificateChain
        _ = try await chain.verifyChain(currentDate: currentDate, hostName: hostName)
#elseif canImport(CommonCrypto)
        try await SecTrust(from: self).verifyChain(currentDate: currentDate, hostName: hostName)
#else
        throw JSONWebKeyError.operationNotAllowed
#endif
    }
}

extension JSONWebCertificateChain: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try leafCertificate.verifyDate(currentDate)
    }
}

// MARK: - Certificate parser

private struct Time: RawRepresentable, DERParseable, DERImplicitlyTaggable, Sendable {
    static var defaultIdentifier: ASN1Identifier {
        .generalizedTime
    }
    
    let rawValue: Date
    
    init(rawValue: Date) {
        self.rawValue = rawValue
    }
    
    init(derEncoded: ASN1Node, withIdentifier _: ASN1Identifier) throws {
        try self.init(derEncoded: derEncoded)
    }
    
    init(derEncoded node: ASN1Node) throws {
        let components: DateComponents
        switch node.identifier {
        case GeneralizedTime.defaultIdentifier:
            components = try DateComponents(GeneralizedTime(derEncoded: node))
        case UTCTime.defaultIdentifier:
            components = try DateComponents(UTCTime(derEncoded: node))
        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
        guard let date = Calendar(identifier: .gregorian).date(from: components) else {
            throw ASN1Error.invalidASN1Object(
                reason: "Invalid Date"
            )
        }
        self = .init(rawValue: date)
    }
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let components = Calendar(identifier: .gregorian).dateComponents(in: .utc, from: rawValue)
        switch identifier {
        case GeneralizedTime.defaultIdentifier:
            try GeneralizedTime(components).serialize(into: &coder)
        case UTCTime.defaultIdentifier:
            try UTCTime(components).serialize(into: &coder)
        default:
            throw ASN1Error.unexpectedFieldType(identifier)
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
            return Validity(notBefore: notBefore.rawValue, notAfter: notAfter.rawValue)
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
    
    init<D>(_ data: D) throws where D: DataProtocol {
        try self.init(derEncoded: [UInt8](data))
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

extension TimeZone {
    @inlinable
    static var utc: TimeZone { .init(secondsFromGMT: 0).unsafelyUnwrapped }
}

extension DateComponents {
    /// Initializes from components of `GeneralizedTime`.
    @inlinable
    public init(_ date: GeneralizedTime) {
        self.init(
            timeZone: .utc,
            year: date.year, month: date.month, day: date.day,
            hour: date.hours, minute: date.minutes, second: date.seconds
        )
    }
    
    /// Initializes from components of `UTCTime`.
    @inlinable
    public init(_ date: UTCTime) {
        self.init(
            timeZone: .utc,
            year: date.year, month: date.month, day: date.day,
            hour: date.hours, minute: date.minutes, second: date.seconds
        )
    }
}

extension GeneralizedTime {
    /// Initializes from components of `DateComponents`.
    @inlinable
    public init(_ components: DateComponents) throws {
        try self.init(
            year: components.year ?? 0,
            month: components.month ?? 0,
            day: components.day ?? 0,
            hours: components.hour ?? 0,
            minutes: components.minute ?? 0,
            seconds: components.second ?? 0,
            fractionalSeconds: 0
        )
    }
}

extension UTCTime {
    /// Initializes from components of `DateComponents`.
    @inlinable
    public init(_ components: DateComponents) throws {
        try self.init(
            year: components.year ?? 0,
            month: components.month ?? 0,
            day: components.day ?? 0,
            hours: components.hour ?? 0,
            minutes: components.minute ?? 0,
            seconds: components.second ?? 0
        )
    }
}
