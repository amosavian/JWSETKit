//
//  SecCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(CommonCrypto)
import CommonCrypto
import CryptoKit
import Foundation
@preconcurrency import Security
#if canImport(X509)
import X509
#endif

extension Security.SecCertificate: Swift.Hashable, Swift.Equatable, Swift.Decodable, Swift.Encodable, @unchecked Swift.Sendable {}

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
        if #available(iOS 18.0, macOS 15.0, watchOS 11.0, tvOS 18.0, visionOS 2.0, *) {
            return (SecCertificateCopyNotValidBeforeDate(self) as Date?) ?? .distantPast
        } else {
            guard let certificate = try? InternalCertificate(derEncoded: [UInt8](derRepresentation)[...]) else {
                return .distantPast
            }
            return certificate.notValidBefore
        }
    }

    /// The date after which this certificate is not valid.
    public var notValidAfter: Date {
        if #available(iOS 18.0, macOS 15.0, watchOS 11.0, tvOS 18.0, visionOS 2.0, *) {
            return (SecCertificateCopyNotValidAfterDate(self) as Date?) ?? .distantFuture
        } else {
            guard let certificate = try? InternalCertificate(derEncoded: [UInt8](derRepresentation)[...]) else {
                return .distantFuture
            }
            return certificate.notValidAfter
        }
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

extension Security.SecTrust: Swift.Decodable, Swift.Encodable {}

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
    
    /// Leaf certiticate of certificate chain which is first one in array.
    public var leaf: SecCertificate {
        certificateChain.first.unsafelyUnwrapped
    }

    /// Certificate chain
    public var certificateChain: [SecCertificate] {
        (SecTrustCopyCertificateChain(self) as? [SecCertificate]) ?? []
    }
    
    /// Return the public key for a leaf certificate after it has been evaluated.
    public var publicKey: SecKey? {
        SecTrustCopyKey(self)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey?.verifySignature(signature, for: data, using: algorithm)
    }
    
    /// Verify validity of certificate chain with RFC 5280 policy.
    public func verifyChain(currentDate: Date? = nil) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let queue = DispatchQueue.global(qos: .userInitiated)
            queue.async {
                if let currentDate {
                    SecTrustSetVerifyDate(self, currentDate as CFDate)
                } else {
                    SecTrustSetVerifyDate(self, Date() as CFDate)
                }
                SecTrustSetPolicies(self, [SecPolicyCreateBasicX509()] as CFArray)
                let result = SecTrustEvaluateAsyncWithError(self, queue) { _, isValid, error in
                    if isValid {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: error.unsafelyUnwrapped)
                    }
                }
                if result != errSecSuccess {
                    continuation.resume(throwing: CryptoKitError.authenticationFailure)
                }
            }
        }
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
        self = try .init(certificates)
    }
    
    /// Initiializes with certificate chain, which first element is leaf certificate.
    public init(_ certificates: [SecCertificate]) throws {
        guard !certificates.isEmpty else {
            throw JSONWebKeyError.keyNotFound
        }
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
#endif
