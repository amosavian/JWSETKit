//
//  P256K+ECDH.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/12/1.
//

#if P256K
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import LibSECP256k1

// MARK: - P256K + KeyAgreement

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K {
    /// A mechanism used to create a shared secret between two users by
    /// performing secp256k1 elliptic curve Diffie Hellman (ECDH) key
    /// exchange.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KeyAgreement: Sendable {
        /// Asecp256k1 public key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: Sendable {
            var impl: Secp256K1BackingPublic

            /// Creates a secp256k1 public key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                self.impl = try .init(rawRepresentation: rawRepresentation)
            }

            /// Creates a secp256k1 public key for key agreement from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(compactRepresentation: compactRepresentation)
            }

            /// Creates a secp256k1 public key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(x963Representation: x963Representation)
            }
            
            /// Creates a secp256k1 public key for key agreement from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a secp256k1 public key for key agreement from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                self.impl = try .init(pemRepresentation: pemRepresentation)
            }
#endif

            /// Creates a secp256k1 public key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                self.impl = try .init(derRepresentation: derRepresentation)
            }
            
            init(impl: Secp256K1BackingPublic) {
                self.impl = impl
            }
            
            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data { impl.derRepresentation }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String { impl.pemRepresentation }
#endif
        }

        /// A secp256k1 private key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: Sendable {
            let impl: Secp256K1BackingPrivate

            /// Creates a random secp256k1 private key for key agreement.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                self.impl = .init(compactRepresentable: compactRepresentable)
            }

            /// Creates a secp256k1 private key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(x963Representation: x963Representation)
            }

            /// Creates a secp256k1 private key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(rawRepresentation: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a secp256k1 private key for key agreement from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                self.impl = try .init(pemRepresentation: pemRepresentation)
            }
#endif

            /// Creates a secp256k1 private key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                self.impl = try .init(derRepresentation: derRepresentation)
            }
            
            /// The corresponding public key.
            public var publicKey: P256K.KeyAgreement.PublicKey {
                .init(impl: impl.publicKey)
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data { impl.derRepresentation }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String { impl.pemRepresentation }
#endif
        }
    }
}

// MARK: - P256K + DH

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Computes a shared secret with the provided public key from another party.
    ///
    /// - Parameters:
    ///   - publicKeyShare: The public key from another party to be combined with the private
    /// key from this user to create the shared secret.
    /// - Returns: The computed shared secret.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P256K.KeyAgreement.PublicKey) throws(CryptoKitMetaError) -> SharedSecret {
        var secret = [UInt8](repeating: 0, count: 32)
        var pubKey = publicKeyShare.impl.key
        let result = secp256k1_ecdh(P256K.context, &secret, &pubKey, impl.bytes, nil, nil)
        guard result == 1 else {
            throw CryptoKitError.incorrectParameterSize
        }
        return try SharedSecret(from: secret)
    }
}

extension SharedSecret {
    init<D: DataProtocol>(from bytes: D) throws {
        var result = switch bytes.count {
        case 32:
            try P256.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PrivateKey().publicKey)
        case 48:
            try P384.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: P384.KeyAgreement.PrivateKey().publicKey)
        case 66:
            try P521.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: P521.KeyAgreement.PrivateKey().publicKey)
        default:
            throw CryptoKitError.incorrectParameterSize
        }
        result.setBytes(bytes)
        self = result
    }
}

#endif
