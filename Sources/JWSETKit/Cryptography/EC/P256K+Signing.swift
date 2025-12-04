//
//  P256K+Signing.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/11/30.
//

#if P256K
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import LibSECP256k1

/// An elliptic curve that enables P256K signatures and key agreement.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum P256K: Sendable {
    static let coordinateByteCount = 32
    
    nonisolated(unsafe) static let context: OpaquePointer = {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        var seed = [UInt8](SymmetricKey(size: .bits256).data)
        _ = secp256k1_context_randomize(context, &seed)
        return context
    }()
}

// MARK: - P256K + Signing

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K {
    /// A mechanism used to create or verify a cryptographic signature using
    /// the P-256K elliptic curve digital signature algorithm (ECDSA).
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Signing: Sendable {
        /// A P-256 public key used to verify cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: Sendable {
            var impl: Secp256K1BackingPublic
            
            /// Creates a P-256 public key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                self.impl = try .init(rawRepresentation: rawRepresentation)
            }
            
            /// Creates a P-256 public key for signing from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(compactRepresentation: compactRepresentation)
            }
            
            /// Creates a P-256 public key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(x963Representation: x963Representation)
            }
            
            /// Creates a P-256 public key for signing from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                try self.init(x963Representation: compressedRepresentation.data)
            }

#if !hasFeature(Embedded)
            /// Creates a P-256 public key for signing from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                self.impl = try .init(pemRepresentation: pemRepresentation)
            }
#endif

            /// Creates a P-256 public key for signing from a Distinguished Encoding
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

        /// A P-256 private key used to create cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: Sendable {
            let impl: Secp256K1BackingPrivate
            
            /// Creates a random P-256 private key for signing.
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

            /// Creates a P-256 private key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(x963Representation: x963Representation)
            }

            /// Creates a P-256 private key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                self.impl = try .init(rawRepresentation: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-256 private key for signing from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                self.impl = try .init(pemRepresentation: pemRepresentation)
            }
#endif

            /// Creates a P-256 private key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                self.impl = try .init(derRepresentation: derRepresentation)
            }

            /// The corresponding public key.
            public var publicKey: P256K.Signing.PublicKey { .init(impl: impl.publicKey) }

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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K.Signing {
    /// A P256K elliptic curve digital signature algorithm (ECDSA) signature.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct ECDSASignature: ContiguousBytes, Sendable {
        /// A raw data representation of a P256K digital signature.
        public var rawRepresentation: Data
        
        var signature: secp256k1_ecdsa_signature {
            var signature = secp256k1_ecdsa_signature()
            secp256k1_ecdsa_signature_parse_compact(P256K.context, &signature, [UInt8](rawRepresentation))
            return signature
        }

        /// Creates a P256K digital signature from a raw representation.
        ///
        /// - Parameters:
        ///   - rawRepresentation: A raw representation of the signature as a
        /// collection of contiguous bytes.
        public init<D: DataProtocol>(rawRepresentation: D) throws(CryptoKitMetaError) {
            guard rawRepresentation.count == 2 * P256K.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        init(_ dataRepresentation: Data) throws(CryptoKitMetaError) {
            guard dataRepresentation.count == 2 * P256K.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }
        
        init(_ signature: secp256k1_ecdsa_signature) throws(CryptoKitMetaError) {
            var signature = signature
            var rawRepresentation = [UInt8](repeating: 0, count: 64)
            secp256k1_ecdsa_signature_serialize_compact(P256K.context, &rawRepresentation, &signature)
            self.rawRepresentation = Data(rawRepresentation)
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(half), combined.suffix(half))
        }

        /// Creates a P256K digital signature from a Distinguished Encoding
        /// Rules (DER) encoded representation.
        ///
        /// - Parameters:
        ///   - derRepresentation: The DER-encoded representation of the
        /// signature.
        public init<D: DataProtocol>(derRepresentation: D) throws(CryptoKitMetaError) {
            var signature = secp256k1_ecdsa_signature()
            let derRepresentation = [UInt8](derRepresentation)
            var rawRepresentation = [UInt8](repeating: 0, count: 64)

            // Parse the DER signature
            let parseResult = secp256k1_ecdsa_signature_parse_der(P256K.context, &signature, derRepresentation, derRepresentation.count)
            guard parseResult == 1 else {
                throw CryptoKitError.incorrectParameterSize
            }

            // Normalize the signature to ensure low-s form (prevent malleability)
            // This converts high-s signatures to low-s form
            var normalizedSignature = secp256k1_ecdsa_signature()
            secp256k1_ecdsa_signature_normalize(P256K.context, &normalizedSignature, &signature)
            signature = normalizedSignature

            // Serialize to compact form
            secp256k1_ecdsa_signature_serialize_compact(P256K.context, &rawRepresentation, &signature)
            self.rawRepresentation = Data(rawRepresentation)
        }

/// Invokes the given closure with a buffer pointer covering the raw
/// bytes of the signature.
#if hasFeature(Embedded)
        public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
#else
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
#endif

        /// A Distinguished Encoding Rules (DER) encoded representation of a
        /// P256K digital signature.
        public var derRepresentation: Data {
            var signature = secp256k1_ecdsa_signature()
            var rawRepresentation = [UInt8](rawRepresentation)
            var derLength = 72
            var derRepresentation = [UInt8](repeating: 0, count: derLength)
            secp256k1_ecdsa_signature_parse_compact(P256K.context, &signature, &rawRepresentation)
            secp256k1_ecdsa_signature_serialize_der(P256K.context, &derRepresentation, &derLength, &signature)
            return Data(derRepresentation).prefix(derLength)
        }
    }
}

// MARK: - P256 + PrivateKey

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K.Signing.PrivateKey {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the digest you provide over the P256K elliptic curve.
    ///
    /// - Parameters:
    ///   - digest: The digest of the data to sign.
    /// - Returns: The signature corresponding to the digest. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: Digest>(for digest: D) throws(CryptoKitMetaError) -> P256K.Signing.ECDSASignature {
        var signature = secp256k1_ecdsa_signature()
        let success = impl.key.withUnsafeBytes {
            secp256k1_ecdsa_sign(P256K.context, &signature, [UInt8](digest.data), $0.baseAddress.unsafelyUnwrapped, secp256k1_nonce_function_rfc6979, nil)
        }
        if success != 1 {
            throw CryptoKitError.incorrectKeySize
        }
        return try .init(signature)
    }
    
    /// Generates an Schnorr signature of the digest you provide over the
    /// P256K elliptic curve.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    /// - Returns: The signature corresponding to the data. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func schnorrSignature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> Data {
        let data = [UInt8](data)
        var signature = [UInt8](repeating: 0, count: 64)
        var key = impl.keypair
        let success = secp256k1_schnorrsig_sign_custom(P256K.context, &signature, data, data.count, &key, nil)
        guard success == 1 else {
            throw CryptoKitError.authenticationFailure
        }
        return Data(signature)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K.Signing.PrivateKey {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the data you provide over the P256K elliptic curve,
    /// using SHA-256 as the hash function.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    /// - Returns: The signature corresponding to the data. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> P256K.Signing.ECDSASignature {
        try signature(for: SHA256.hash(data: data))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K.Signing.PublicKey {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a digest over the P256K elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The signed digest.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given digest; otherwise, `false`.
    public func isValidSignature<D: Digest>(_ signature: P256K.Signing.ECDSASignature, for digest: D) -> Bool {
        var signature = signature.signature
        var pubkey = impl.key
        return secp256k1_ecdsa_verify(P256K.context, &signature, [UInt8](digest.data), &pubkey) == 1
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256K.Signing.PublicKey {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a block of data over the P256K elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The signed data.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given data; otherwise, `false`.
    public func isValidSignature<D: DataProtocol>(_ signature: P256K.Signing.ECDSASignature, for data: D) -> Bool {
        isValidSignature(signature, for: SHA256.hash(data: data))
    }
    
    /// Verifies an Schnorr signature on a block of data over the
    /// P256K elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The signed data.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given data; otherwise, `false`.
    public func isValidSchnorrSignature<D: DataProtocol>(_ signature: Data, for data: D) -> Bool {
        let signature = [UInt8](signature)
        let message = [UInt8](data)
        var (pubkey, _) = impl.xonlyKey
        return secp256k1_schnorrsig_verify(P256K.context, signature, message, message.count, &pubkey) == 1
    }
}
#endif
