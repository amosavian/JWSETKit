//
//  P256K+Backing.swift
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
import CryptoASN1
import LibSECP256k1
import SwiftASN1

enum Secp256K1BackingPublic: Hashable {
    case x963(secp256k1_pubkey)
    case xonly(secp256k1_xonly_pubkey)
    
    var key: secp256k1_pubkey {
        switch self {
        case .x963(let pubkey):
            return pubkey
        case .xonly(var pubkey):
            var result = secp256k1_pubkey()
            var key = [UInt8](repeating: 0, count: 32)
            secp256k1_xonly_pubkey_serialize(P256K.context, &key, &pubkey)
            key.insert(0x02, at: 0)
            _ = secp256k1_ec_pubkey_parse(P256K.context, &result, &key, key.count)
            return result
        }
    }
    
    var xonlyKey: (key: secp256k1_xonly_pubkey, parity: Bool) {
        switch self {
        case .x963(var pubkey):
            var xonlyPubkey = secp256k1_xonly_pubkey()
            var parity: Int32 = 0
            secp256k1_xonly_pubkey_from_pubkey(P256K.context, &xonlyPubkey, &parity, &pubkey)
            return (xonlyPubkey, parity == 1)
        case .xonly(let pubkey):
            return (pubkey, false)
        }
    }
    
    init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
        try self.init(x963Representation: [0x04] + rawRepresentation.data)
    }
    
    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
        var pubkey = secp256k1_xonly_pubkey()
        let result = try compactRepresentation.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                throw CryptoKitError.incorrectKeySize
            }
            return secp256k1_xonly_pubkey_parse(P256K.context, &pubkey, baseAddress)
        }
        if result == 1 {
            self = .xonly(pubkey)
        } else {
            throw CryptoKitError.incorrectKeySize
        }
    }
    
    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
        var pubkey = secp256k1_pubkey()
        let result = try x963Representation.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                throw CryptoKitError.incorrectKeySize
            }
            return secp256k1_ec_pubkey_parse(P256K.context, &pubkey, baseAddress, buffer.count)
        }
        if result == 1 {
            self = .x963(pubkey)
        } else {
            throw CryptoKitError.incorrectKeySize
        }
    }
    
    init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
        try self.init(x963Representation: compressedRepresentation.data)
    }
    
#if !hasFeature(Embedded)
    init(pemRepresentation: String) throws(CryptoKitMetaError) {
        let pem = try PEMDocument(pemString: pemRepresentation)
        guard pem.discriminator == "PUBLIC KEY" else {
            throw CryptoKitASN1Error.invalidPEMDocument
        }
        self = try .init(derRepresentation: pem.derBytes)
    }
#endif
    
    init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
        let bytes = Array(derRepresentation)
        let parsed = try SubjectPublicKeyInfo(derEncoded: bytes)
        try self.init(x963Representation: parsed.key.bytes)
    }
    
    init<Bytes: RandomAccessCollection>(elligatorSwiftRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
        let bytes = Array(elligatorSwiftRepresentation)
        var pubkey = secp256k1_pubkey()
        let result = try bytes.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                throw CryptoKitError.incorrectKeySize
            }
            return secp256k1_ellswift_decode(P256K.context, &pubkey, baseAddress)
        }
        if result == 1 {
            self = .x963(pubkey)
        } else {
            throw CryptoKitError.incorrectKeySize
        }
    }
    
    init(impl: secp256k1_pubkey) {
        self = .x963(impl)
    }
    
    init(impl: secp256k1_xonly_pubkey) {
        self = .xonly(impl)
    }
    
    static func == (lhs: Secp256K1BackingPublic, rhs: Secp256K1BackingPublic) -> Bool {
        switch (lhs, rhs) {
        case (.x963(var lhsKey), .x963(var rhsKey)):
            return secp256k1_ec_pubkey_cmp(P256K.context, &lhsKey, &rhsKey) == 0
        case (.xonly(var lhsKey), .xonly(var rhsKey)):
            return secp256k1_xonly_pubkey_cmp(P256K.context, &lhsKey, &rhsKey) == 0
        case (.x963(var lhsKey), .xonly):
            var rhsKey = rhs.key
            return secp256k1_ec_pubkey_cmp(P256K.context, &lhsKey, &rhsKey) == 0
        case (.xonly, .x963(var rhsKey)):
            var lhsKey = lhs.key
            return secp256k1_ec_pubkey_cmp(P256K.context, &lhsKey, &rhsKey) == 0
        }
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(derRepresentation)
    }
    
    func serialize(compressed: Bool = false) -> Data {
        var length = compressed ? 33 : 65
        var result = [UInt8](repeating: 0, count: length)
        var pubkey = key
        secp256k1_ec_pubkey_serialize(
            P256K.context, &result, &length, &pubkey,
            UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)
        )
        return Data(result.prefix(length))
    }
    
    var compactRepresentation: Data? {
        var result = [UInt8](repeating: 0, count: 32)
        var (pubkey, parity) = xonlyKey
        guard !parity else {
            return nil
        }
        secp256k1_xonly_pubkey_serialize(P256K.context, &result, &pubkey)
        return Data(result)
    }
    
    var rawRepresentation: Data {
        serialize().dropFirst()
    }
    
    var x963Representation: Data {
        serialize()
    }
    
    var compressedRepresentation: Data {
        serialize(compressed: true)
    }
    
    var derRepresentation: Data {
        let spki = SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaSecp256k1, key: Array(x963Representation))
        return (try? spki.derRepresentation) ?? .init()
    }
    
#if !hasFeature(Embedded)
    var pemRepresentation: String {
        let pemDocument = PEMDocument(type: "PUBLIC KEY", derBytes: .init(derRepresentation))
        return pemDocument.pemString
    }
#endif
    
    var elligatorSwiftRepresentation: Data {
        var result = [UInt8](repeating: 0, count: 64)
        var pubkey = key
        let randomKey = SymmetricKey(size: .bits128)
        _ = randomKey.withUnsafeBytes { buffer in
            secp256k1_ellswift_encode(P256K.context, &result, &pubkey, buffer.baseAddress.unsafelyUnwrapped)
        }
        
        return Data(result)
    }
}

struct Secp256K1BackingPrivate: Hashable {
    let key: SymmetricKey
    
    var keypair: secp256k1_keypair {
        var result = secp256k1_keypair()
        key.withUnsafeBytes {
            _ = secp256k1_keypair_create(P256K.context, &result, $0.baseAddress.unsafelyUnwrapped)
        }
        return result
    }
    
    func hash(into hasher: inout Hasher) {
        key.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
    
    static func isCompactRepresentable(_ key: SymmetricKey) -> Bool {
        var pubkey = secp256k1_pubkey()
        key.withUnsafeBytes {
            _ = secp256k1_ec_pubkey_create(P256K.context, &pubkey, $0.baseAddress.unsafelyUnwrapped)
        }
        return !Secp256K1BackingPublic(impl: pubkey).xonlyKey.parity
    }
    
    private static func isValid(_ key: SymmetricKey, compactRepresentable: Bool) -> Bool {
        key.withUnsafeBytes {
            secp256k1_ec_seckey_verify(P256K.context, $0.baseAddress.unsafelyUnwrapped) == 0 && (!compactRepresentable || isCompactRepresentable(key))
        }
    }
    
    /// Creates a random P-256 private key for signing.
    ///
    /// Keys that use a compact point encoding enable shorter public keys, but aren’t
    /// compliant with FIPS certification. If your app requires FIPS certification,
    /// create a key with ``init(rawRepresentation:)``.
    ///
    /// - Parameters:
    ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
    /// creates the key with the structure to enable compact point encoding.
    init(compactRepresentable: Bool = true) {
        var key: SymmetricKey
        repeat {
            key = SymmetricKey(size: .bits256)
        } while Self.isValid(key, compactRepresentable: compactRepresentable)
        self.key = key
    }
    
    /// Creates a P-256 private key for signing from an ANSI x9.63
    /// representation.
    ///
    /// - Parameters:
    ///   - x963Representation: An ANSI x9.63 representation of the key.
    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
        guard x963Representation.data.count == 1 + 3 * 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        self.key = SymmetricKey(data: x963Representation.data.suffix(32))
    }
    
    /// Creates a P-256 private key for signing from a collection of bytes.
    ///
    /// - Parameters:
    ///   - rawRepresentation: A raw representation of the key as a collection of
    /// contiguous bytes.
    init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
        guard rawRepresentation.data.count == 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        self.key = SymmetricKey(data: rawRepresentation.data)
    }
    
#if !hasFeature(Embedded)
    /// Creates a P-256 private key for signing from a Privacy-Enhanced Mail
    /// PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    init(pemRepresentation: String) throws(CryptoKitMetaError) {
        let pem = try PEMDocument(pemString: pemRepresentation)
        
        switch pem.discriminator {
        case "EC PRIVATE KEY":
            let parsed = try SEC1PrivateKey(derEncoded: Array(pem.derBytes))
            try self.init(rawRepresentation: parsed.privateKey.bytes)
        case "PRIVATE KEY":
            let parsed = try PKCS8PrivateKey(derEncoded: Array(pem.derBytes))
            guard let privateKey = (parsed.privateKey as? SEC1PrivateKey)?.privateKey else {
                throw CryptoASN1Error.invalidPEMDocument
            }
            try self.init(rawRepresentation: privateKey.bytes)
        default:
            throw CryptoKitASN1Error.invalidPEMDocument
        }
    }
#endif
    
    /// Creates a P-256 private key for signing from a Distinguished Encoding
    /// Rules (DER) encoded representation.
    ///
    /// - Parameters:
    ///   - derRepresentation: A DER-encoded representation of the key.
    init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
        let bytes = Array(derRepresentation)
        
        // We have to try to parse this twice because we have no information about what kind of key this is.
        // We try with PKCS#8 first, and then fall back to SEC.1.
        
        do {
            let parsed = try PKCS8PrivateKey(derEncoded: Array(bytes))
            guard let privateKey = (parsed.privateKey as? SEC1PrivateKey)?.privateKey else {
                throw CryptoASN1Error.invalidPEMDocument
            }
            self = try .init(rawRepresentation: privateKey.bytes)
        } catch {
            let key = try SEC1PrivateKey(derEncoded: bytes)
            self = try .init(rawRepresentation: key.privateKey.bytes)
        }
    }
    
    /// The corresponding public key.
    var publicKey: Secp256K1BackingPublic {
        var pubkey = secp256k1_pubkey()
        key.withUnsafeBytes {
            _ = secp256k1_ec_pubkey_create(P256K.context, &pubkey, $0.baseAddress.unsafelyUnwrapped)
        }
        return Secp256K1BackingPublic(impl: pubkey)
    }
    
    /// A data representation of the private key.
    var rawRepresentation: Data {
        key.data
    }
    
    /// An ANSI x9.63 representation of the private key.
    var x963Representation: Data {
        publicKey.x963Representation + key.data
    }
    
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
    var derRepresentation: Data {
        let pkey = PKCS8PrivateKey(algorithm: .ecdsaSecp256k1, privateKey: Array(rawRepresentation), publicKey: Array(publicKey.x963Representation))
        return (try? pkey.derRepresentation) ?? .init()
    }
    
#if !hasFeature(Embedded)
    /// A Privacy-Enhanced Mail (PEM) representation of the private key.
    var pemRepresentation: String {
        let pemDocument = PEMDocument(type: "PRIVATE KEY", derBytes: [UInt8](derRepresentation))
        return pemDocument.pemString
    }
#endif
}

enum Secp256K1BackingSignature {
    case ecdsa(signature: secp256k1_ecdsa_signature)
    case recoverable(recoverableSignature: secp256k1_ecdsa_recoverable_signature)
    
    var signature: secp256k1_ecdsa_signature {
        switch self {
        case .ecdsa(let signature):
            return signature
        case .recoverable(var recoverableSignature):
            var signature = secp256k1_ecdsa_signature()
            secp256k1_ecdsa_recoverable_signature_convert(P256K.context, &signature, &recoverableSignature)
            return signature
        }
    }
    
    var rawRepresentation: [UInt8] {
        var result = [UInt8](repeating: 0, count: P256K.coordinateByteCount * 2)
        switch self {
        case .ecdsa(var signature):
            secp256k1_ecdsa_signature_serialize_compact(P256K.context, &result, &signature)
        case .recoverable(var recoverableSignature):
            var recid: CInt = 0
            secp256k1_ecdsa_recoverable_signature_serialize_compact(P256K.context, &result, &recid, &recoverableSignature)
        }
        return result
    }
    
    var recoveryId: UInt8? {
        switch self {
        case .ecdsa:
            return nil
        case .recoverable(var recoverableSignature):
            var result = [UInt8](repeating: 0, count: P256K.coordinateByteCount * 2)
            var recid: CInt = 0
            secp256k1_ecdsa_recoverable_signature_serialize_compact(P256K.context, &result, &recid, &recoverableSignature)
            return UInt8(exactly: recid)
        }
    }
    
    var derRepresentation: Data {
        var signature = self.signature
        var derLength = 72
        var derRepresentation = [UInt8](repeating: 0, count: derLength)
        secp256k1_ecdsa_signature_serialize_der(P256K.context, &derRepresentation, &derLength, &signature)
        return Data(derRepresentation).prefix(derLength)
    }
    
    init(derRepresentation: [UInt8]) throws(CryptoKitMetaError) {
        var signature = secp256k1_ecdsa_signature()
        
        // Parse the DER signature
        let parseResult = secp256k1_ecdsa_signature_parse_der(P256K.context, &signature, derRepresentation, derRepresentation.count)
        guard parseResult == 1 else {
            throw CryptoKitError.incorrectParameterSize
        }
        self = .ecdsa(signature: signature)
        normalize()
    }
    
    init(key: Secp256K1BackingPrivate, digest: [UInt8], nonceFunction: secp256k1_nonce_function, nonceData: [UInt8]?) throws {
        guard digest.count == 32 else {
            throw CryptoKitError.incorrectParameterSize
        }
        var signature = secp256k1_ecdsa_recoverable_signature()
        let success = key.key.withUnsafeBytes {
            secp256k1_ecdsa_sign_recoverable(P256K.context, &signature, digest, $0.baseAddress.unsafelyUnwrapped, secp256k1_nonce_function_rfc6979, nil)
        }
        if success != 1 {
            throw CryptoKitError.incorrectKeySize
        }
        self = .recoverable(recoverableSignature: signature)
    }
    
    func recoverPublicKey(from signedMessageHash: [UInt8]) throws -> Secp256K1BackingPublic {
        guard signedMessageHash.count == 32 else {
            throw CryptoKitError.incorrectParameterSize
        }
        switch self {
        case .ecdsa:
            throw CryptoKitError.incorrectParameterSize
        case .recoverable(var recoverableSignature):
            var pubKey = secp256k1_pubkey()
            let result = secp256k1_ecdsa_recover(
                P256K.context, &pubKey,
                &recoverableSignature,
                signedMessageHash
            )
            guard result == 1 else {
                throw CryptoKitError.incorrectParameterSize
            }
            return .init(impl: pubKey)
        }
    }
    
    mutating func normalize() {
        switch self {
        case .ecdsa(var signature):
            var normalized = secp256k1_ecdsa_signature()
            secp256k1_ecdsa_signature_normalize(P256K.context, &normalized, &signature)
            self = .ecdsa(signature: normalized)
        case .recoverable:
            var result = secp256k1_ecdsa_recoverable_signature()
            var signature = Self.ecdsa(signature: signature)
            signature.normalize()
            var rawRepresentation = signature.rawRepresentation
            secp256k1_ecdsa_recoverable_signature_parse_compact(P256K.context, &result, &rawRepresentation, CInt(recoveryId.unsafelyUnwrapped))
            self = .recoverable(recoverableSignature: result)
        }
    }
}
