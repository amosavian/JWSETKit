//
//  SecCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#if canImport(CommonCrypto)
import CommonCrypto
import CryptoKit
#if canImport(X509)
import X509
#endif
import SwiftASN1

extension Security.SecCertificate: Swift.Hashable, Swift.Codable, @unchecked Swift.Sendable {}

extension SecCertificate: JSONWebValidatingKey {
#if canImport(X509)
    @usableFromInline
    var x509: Certificate {
        (try? Certificate(self)).unsafelyUnwrapped
    }
#endif
    
    public var storage: JSONWebValueStorage {
        var key = (try? AnyJSONWebKey(publicKey)) ?? .init()
#if canImport(X509)
        key.certificateChain = [x509]
#else
        key.certificateChain = [self]
#endif
        return key.storage
    }
    
    /// Returns a DER representation of a certificate given a certificate object.
    @inlinable
    public var derRepresentation: Data {
        SecCertificateCopyData(self) as Data
    }
    
    /// Retrieves the public key for certificate.
    public var publicKey: SecKey {
        get throws {
            guard let key = SecCertificateCopyKey(self) else {
                throw JSONWebKeyError.keyNotFound
            }
            return key
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try publicKey.thumbprint(format: format, using: hashFunction)
    }
}

extension JSONWebContainer where Self: SecCertificate {
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first, let result = try SecCertificate.makeWithCertificate(certificate) as? Self else {
            throw JSONWebKeyError.keyNotFound
        }
        self = result
    }
    
    public init<D>(derEncoded: D) throws where D: DataProtocol {
        guard let value = SecCertificateCreateWithData(kCFAllocatorDefault, Data(derEncoded) as CFData) as? Self else {
            throw CryptoKitASN1Error.invalidASN1Object
        }
        self = value
    }
}

extension SecCertificate: Expirable {
    /// The date before which this certificate is not valid.
    public var notValidBefore: Date {
        guard let certificate = try? InternalCertificate(derEncoded: [UInt8](derRepresentation)[...]) else {
            return .distantPast
        }
        return certificate.tbsCertificate.validity.notBefore
    }

    /// The date after which this certificate is not valid.
    public var notValidAfter: Date {
        guard let certificate = try? InternalCertificate(derEncoded: [UInt8](derRepresentation)[...]) else {
            return .distantFuture
        }
        return certificate.tbsCertificate.validity.notAfter
    }
    
    public func verifyDate(_ currentDate: Date) throws {
        if currentDate > notValidAfter {
            throw JSONWebValidationError.tokenExpired(expiry: notValidAfter)
        }
        if currentDate < notValidBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notValidBefore)
        }
    }
}

extension Security.SecTrust: Swift.Codable {}

extension SecTrust: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        guard var key = (try? certificateChain.first?.publicKey).map(AnyJSONWebKey.init) else {
            return .init()
        }
#if canImport(X509)
        key.certificateChain = certificateChain.map { $0.x509 }
#else
        key.certificateChain = certificateChain
#endif
        return key.storage
    }
    
    /// Certificate chain
    public var certificateChain: [SecCertificate] {
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return (SecTrustCopyCertificateChain(self) as? [SecCertificate]) ?? []
        } else {
            let count = SecTrustGetCertificateCount(self)
            guard count > 0 else {
                return []
            }
            return (0 ..< count).compactMap {
                SecTrustGetCertificateAtIndex(self, $0)
            }
        }
    }
    
    /// Return the public key for a leaf certificate after it has been evaluated.
    public var publicKey: SecKey? {
        SecTrustCopyKey(self)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey?.verifySignature(signature, for: data, using: algorithm)
    }
}

extension SecCertificate {
    static func makeWithCertificate(_ certificate: SecCertificate) throws -> SecCertificate {
        certificate
    }
}

extension JSONWebContainer where Self: SecTrust {
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        let certificates: [SecCertificate] = try key.certificateChain.map(SecCertificate.makeWithCertificate)
        var result: SecTrust?
        SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &result)
        guard let result = result as? Self else {
            throw JSONWebKeyError.keyNotFound
        }
        self = result
    }
}

extension SecTrust: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try certificateChain.forEach { try $0.verifyDate(currentDate) }
    }
}

#if canImport(X509)
public func == (lhs: Certificate, rhs: SecCertificate) -> Bool {
    lhs == rhs.x509
}

public func == (lhs: SecCertificate, rhs: Certificate) -> Bool {
    lhs.x509 == rhs
}
#endif

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
    
    init(validity: Validity) {
        self.validity = validity
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
            while nodes.next() != nil {
                // Ignore remaining fields
            }
            return .init(validity: validity)
        }
    }
}

private struct InternalCertificate: DERParseable, Sendable {
    let tbsCertificate: InternalTBSCertificate
    
    init(tbsCertificate: InternalTBSCertificate) {
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
#endif
