//
//  P256K+Signing.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2025/11/30.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import LibSECP256k1

/// An elliptic curve that enables P256K signatures and key agreement.
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

extension P256K {
    /// A mechanism used to create or verify a cryptographic signature using
    /// the P-256K elliptic curve digital signature algorithm (ECDSA).
    public enum Signing: Sendable {
        /// A P-256 public key used to verify cryptographic signatures.
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
            
            /// Creates a secp256k1 public key for signing from a ElligatorSwift representation.
            ///
            /// - Parameters:
            ///   - elligatorSwiftRepresentation: A 64-byte ElligatorSwift representation of the key.
            public init<Bytes: RandomAccessCollection>(elligatorSwiftRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                self.impl = try .init(elligatorSwiftRepresentation: elligatorSwiftRepresentation)
            }
            
            init(impl: Secp256K1BackingPublic) {
                self.impl = impl
            }
            
            /// A compact representation of the public key.
            public var compactRepresentation: Data? {
                impl.compactRepresentation
            }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data {
                impl.rawRepresentation
            }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data {
                impl.x963Representation
            }
            
            /// A compressed representation of the public key.
            public var compressedRepresentation: Data {
                impl.compressedRepresentation
            }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                impl.derRepresentation
            }
            
#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                impl.pemRepresentation
            }
#endif
            
            /// A 64-byte ElligatorSwift representation of the public key.
            public var elligatorSwiftRepresentation: Data {
                impl.elligatorSwiftRepresentation
            }
        }
        
        /// A P-256 private key used to create cryptographic signatures.
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
            public var publicKey: P256K.Signing.PublicKey {
                .init(impl: impl.publicKey)
            }
            
            /// A data representation of the private key.
            public var rawRepresentation: Data {
                impl.rawRepresentation
            }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data {
                impl.x963Representation
            }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                impl.derRepresentation
            }
            
#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                impl.pemRepresentation
            }
#endif
        }
    }
}

extension P256K.Signing {
    /// A P256K elliptic curve digital signature algorithm (ECDSA) signature.
    public struct ECDSASignature: ContiguousBytes, Sendable {
        /// Indicates where recovery id must be place inside the signature representation.
        ///
        /// In Bitcoin, it is either header byte or most upper bit of S part. While
        /// Etherium related formats places recovery id after signature.
        public enum CompactRepresentationFormat: Hashable, Sendable {
            /// Encoded recovery id at the end of signature, equals with `libsec256k1` default
            /// compact representation.
            ///
            /// Total bytes count must be 65.
            case raw
            
            /// Bitcoin encodes the recovery ID in a header byte that also indicates the key type,
            /// which is offset by 27 or 31.
            ///
            /// Total bytes count must be 65.
            case bitcoin
            
            /// Etherium signatures where a tail byte contains recovery id offset by 27.
            ///
            /// Total bytes count must be 65.
            case etherium
            
            /// Etherium signatures that prevents cross-chain replay attacks by encoding
            /// chain id in tail byte.
            ///
            /// Total bytes count is variable.
            case eip155(chainId: Int)
            
            /// Etherium signatures that the recovery bit is packed into the highest bit of s.
            ///
            /// Total bytes count must be 64.
            case eip2098
            
            var lengthRange: ClosedRange<Int> {
                switch self {
                case .raw, .bitcoin, .etherium:
                    65 ... 65
                case .eip155:
                    65 ... 72
                case .eip2098:
                    64 ... 64
                }
            }
        }
        
        fileprivate var backing: Secp256K1BackingSignature
        
        /// A raw data representation of a P256K digital signature.
        public var rawRepresentation: Data {
            .init(backing.rawRepresentation)
        }
        
        /// The recovery ID (0, 1, 2 or 3) if the signature is initialized with recovery ID.
        public var recoveryId: UInt8? {
            backing.recoveryId
        }
        
        /// Creates a P256K digital signature from a raw representation.
        ///
        /// - Parameters:
        ///   - rawRepresentation: A raw representation of the signature as a
        ///         collection of contiguous bytes.
        ///   - recoveryId: The recovery ID (0, 1, 2 or 3) if the signature is initialized with recovery ID.
        public init<D: DataProtocol, R: BinaryInteger & Sendable>(
            rawRepresentation: D, recoveryId: R? = UInt8?.none
        ) throws(CryptoKitMetaError) {
            guard rawRepresentation.count == 2 * P256K.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }
            let rawRepresentation = [UInt8](rawRepresentation)
            
            if let recoveryId = recoveryId.flatMap(CInt.init(exactly:)) {
                var signature = secp256k1_ecdsa_recoverable_signature()
                secp256k1_ecdsa_recoverable_signature_parse_compact(P256K.context, &signature, rawRepresentation, recoveryId)
                try self.init(signature)
            } else {
                var signature = secp256k1_ecdsa_signature()
                secp256k1_ecdsa_signature_parse_compact(P256K.context, &signature, rawRepresentation)
                try self.init(signature)
            }
        }
        
        init(_ signature: secp256k1_ecdsa_signature) throws(CryptoKitMetaError) {
            self.backing = .ecdsa(signature: signature)
            backing.normalize()
        }
        
        init(_ signature: secp256k1_ecdsa_recoverable_signature) throws(CryptoKitMetaError) {
            self.backing = .recoverable(recoverableSignature: signature)
            backing.normalize()
        }
        
        init(_ backing: Secp256K1BackingSignature) {
            self.backing = backing
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
            self.backing = try .init(derRepresentation: [UInt8](derRepresentation))
        }
        
        /// Creates a P256K digital signature from a compact representation.
        ///
        /// - Parameters:
        ///   - compactRepresentation: A compact formatted representation of the signature as a
        ///         collection of contiguous bytes.
        ///   - format: Representation format.
        public init<D: DataProtocol>(
            compactRepresentation: D, format: CompactRepresentationFormat
        ) throws(CryptoKitMetaError) {
            guard format.lengthRange.contains(compactRepresentation.count) else {
                throw CryptoKitError.incorrectParameterSize
            }
            let rawRepresentation: any DataProtocol
            let recoveryId: UInt8
            switch format {
            case .raw:
                rawRepresentation = compactRepresentation.prefix(64)
                recoveryId = compactRepresentation.last.unsafelyUnwrapped
            case .bitcoin:
                rawRepresentation = compactRepresentation.suffix(64)
                recoveryId = compactRepresentation.first.unsafelyUnwrapped - 27
            case .etherium:
                rawRepresentation = compactRepresentation.prefix(64)
                recoveryId = compactRepresentation.last.unsafelyUnwrapped - 27
            case .eip155:
                rawRepresentation = compactRepresentation.prefix(64)
                recoveryId = (compactRepresentation.last.unsafelyUnwrapped &- 35) & 0x01
            case .eip2098:
                var bytes = Data(compactRepresentation)
                recoveryId = bytes[32] >> 7
                bytes[32] &= 0x7F
                rawRepresentation = bytes
            }
            try self.init(rawRepresentation: rawRepresentation, recoveryId: recoveryId)
        }
        
#if hasFeature(Embedded)
        /// Invokes the given closure with a buffer pointer covering the raw
        /// bytes of the signature.
        public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            try backing.rawRepresentation.withUnsafeBytes(body)
        }
#else
        /// Invokes the given closure with a buffer pointer covering the raw
        /// bytes of the signature.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try backing.rawRepresentation.withUnsafeBytes(body)
        }
#endif
        
        /// A Distinguished Encoding Rules (DER) encoded representation of a
        /// P256K digital signature.
        public var derRepresentation: Data {
            backing.derRepresentation
        }
        
        /// Recovers secp256k1 public used to sign message using hash and signature
        /// when recovery ID is available.
        ///
        /// - Parameter signedMessageHash: 32-byte message hash which is signed.
        /// - Returns: secp256k1 public key.
        public func recoverPublicKey<D: DataProtocol>(from signedMessageHash: D) throws -> P256K.Signing.PublicKey {
            let key = try backing.recoverPublicKey(from: [UInt8](signedMessageHash))
            return .init(impl: key)
        }
        
        /// Recovers secp256k1 public used to sign message using hash and signature
        /// when recovery ID is available.
        ///
        /// - Parameter signedMessageHash: 32-byte message hash which is signed.
        /// - Returns: secp256k1 public key.
        public func recoverPublicKey<D: Digest>(from signedMessageHash: D) throws -> P256K.Signing.PublicKey {
            try recoverPublicKey(from: [UInt8](signedMessageHash))
        }
        
        /// Returns compact (including recovery bit) representation of signature.
        ///
        /// Total length can be 65 bytes for some formats which indicated including recovery bits.
        ///
        /// - Parameter format: Compact representation format which indicated recovery bits placement
        /// - Returns: Signature's compact representation
        public func compactRepresentation(format: CompactRepresentationFormat) throws -> Data {
            guard let recoveryId else {
                throw CryptoKitError.incorrectParameterSize
            }
            
            switch format {
            case .raw:
                return rawRepresentation + [recoveryId]
            case .bitcoin:
                return [recoveryId + 27] + rawRepresentation
            case .etherium:
                return rawRepresentation + [recoveryId + 27]
            case .eip155(let chainId):
                let tail = (UInt(recoveryId) + 35 + 2 * UInt(chainId)).withBigEndianIntegerBytes { bytes in
                    bytes.drop(while: { $0 == 0 })
                }
                return rawRepresentation + [UInt8](tail)
            case .eip2098:
                var result = rawRepresentation
                result[32] |= (recoveryId & 0x01) << 7
                return result
            }
        }
    }
}

// MARK: - P256 + PrivateKey

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
        guard D.byteCount == 32 else {
            throw CryptoKitError.incorrectParameterSize
        }
        let signature = try Secp256K1BackingSignature(key: impl, digest: [UInt8](digest), nonceFunction: secp256k1_nonce_function_rfc6979, nonceData: nil)
        return .init(signature)
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
        var signature = signature.backing.signature
        var pubkey = impl.key
        return secp256k1_ecdsa_verify(P256K.context, &signature, [UInt8](digest.data), &pubkey) == 1
    }
}

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

extension ContiguousBytes {
    @usableFromInline
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
    
    mutating func setBytes<D: DataProtocol>(_ bytes: D) {
        withUnsafeBytes { buffer in
            UnsafeMutableRawBufferPointer(mutating: buffer).copyBytes(from: bytes.prefix(buffer.count))
        }
    }
}
