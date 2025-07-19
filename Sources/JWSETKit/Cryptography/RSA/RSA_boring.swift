//
//  RSA_boring.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 6/20/25.
//

#if canImport(_CryptoExtras)
import _CryptoExtras
import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

enum RSAEncryptionPadding {
    case pkcs1_5
    case pkcs1_oaep(Digest)
    
    enum Digest {
        case sha1
        case sha256
        case sha384
        case sha512
    }
    
    init(algorithm: some JSONWebAlgorithm) throws {
        switch algorithm {
        case .unsafeRSAEncryptionPKCS1:
            self = .pkcs1_5
        case .rsaEncryptionOAEP:
            self = .pkcs1_oaep(.sha1)
        case .rsaEncryptionOAEPSHA256:
            self = .pkcs1_oaep(.sha256)
        case .rsaEncryptionOAEPSHA384:
            self = .pkcs1_oaep(.sha384)
        case .rsaEncryptionOAEPSHA512:
            self = .pkcs1_oaep(.sha512)
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension BoringSSLRSAPublicKey: JSONWebEncryptingKey {
    var storage: JSONWebValueStorage {
        let (n, e) = getKeyPrimitives()
        var result = AnyJSONWebKey()
        result.keyType = .rsa
        result.modulus = n
        result.exponent = e
        return result.storage
    }
    
    init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent else {
            throw CryptoKitError.incorrectParameterSize
        }
        try self.init(n: modulus, e: exponent)
    }

    func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try encrypt(data, padding: .init(algorithm: algorithm))
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.getKeyPrimitives() == rhs.getKeyPrimitives()
    }
    
    func hash(into hasher: inout Hasher) {
        let (n, e) = getKeyPrimitives()
        hasher.combine(n)
        hasher.combine(e)
    }
}

extension BoringSSLRSAPrivateKey: JSONWebDecryptingKey {
    var storage: JSONWebValueStorage {
        let (n, e, d, p, q, dp, dq, qi) = getKeyPrimitives()
        var result = AnyJSONWebKey()
        result.keyType = .rsa
        result.modulus = n
        result.exponent = e
        result.privateExponent = d
        result.firstPrimeFactor = p
        result.secondPrimeFactor = q
        result.firstCRTCoefficient = dp
        result.secondFactorCRTExponent = dq
        result.firstCRTCoefficient = qi
        return result.storage
    }
    
    init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let modulus = key.modulus, let exponent = key.exponent, let privateExponent = key.privateExponent else {
            throw CryptoKitError.incorrectParameterSize
        }
        if let firstPrimeFactor = key.firstPrimeFactor,
           let secondPrimeFactor = key.secondPrimeFactor,
           let firstFactorCRTExponent = key.firstFactorCRTExponent,
           let secondFactorCRTExponent = key.secondFactorCRTExponent,
           let firstCRTCoefficient = key.firstCRTCoefficient
        {
            try self.init(
                n: modulus, e: exponent, d: privateExponent,
                p: firstPrimeFactor, q: secondPrimeFactor,
                dmp1: firstFactorCRTExponent, dmq1: secondFactorCRTExponent,
                iqmp: firstCRTCoefficient
            )
        } else {
            try self.init(n: modulus, e: exponent, d: privateExponent)
        }
    }

    init(algorithm _: some JSONWebAlgorithm) throws {
        fatalError()
    }

    func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try decrypt(data, padding: .init(algorithm: algorithm))
    }
}

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CCryptoBoringSSL
import CCryptoBoringSSLShims

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CryptoKitError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> CryptoKitError {
        .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct BoringSSLRSAPublicKey: Sendable {
    private var backing: Backing

    init(n: some ContiguousBytes, e: some ContiguousBytes) throws {
        self.backing = try Backing(n: n, e: e)
    }

    init(_ other: BoringSSLRSAPublicKey) throws {
        self = other
    }

    fileprivate init(_ backing: Backing) {
        self.backing = backing
    }

    func getKeyPrimitives() -> (n: Data, e: Data) {
        backing.getKeyPrimitives()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct BoringSSLRSAPrivateKey: Sendable {
    private var backing: Backing

    init(
        n: some ContiguousBytes,
        e: some ContiguousBytes,
        d: some ContiguousBytes
    ) throws {
        self.backing = try Backing(n: n, e: e, d: d)
    }
    
    init(
        n: some ContiguousBytes,
        e: some ContiguousBytes,
        d: some ContiguousBytes,
        p: some ContiguousBytes,
        q: some ContiguousBytes,
        dmp1: some ContiguousBytes,
        dmq1: some ContiguousBytes,
        iqmp: some ContiguousBytes
    ) throws {
        self.backing = try Backing(n: n, e: e, d: d, p: p, q: q, dmp1: dmp1, dmq1: dmq1, iqmp: iqmp)
    }

    init(_ other: BoringSSLRSAPrivateKey) throws {
        self = other
    }

    var keySizeInBits: Int {
        backing.keySizeInBits
    }

    var publicKey: BoringSSLRSAPublicKey {
        backing.publicKey
    }

    func getKeyPrimitives() -> (n: Data, e: Data, d: Data, p: Data, q: Data, dp: Data, dq: Data, qi: Data) {
        backing.getKeyPrimitives()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPrivateKey {
    func decrypt<D: DataProtocol>(_ data: D, padding: RSAEncryptionPadding) throws -> Data {
        try backing.decrypt(data, padding: padding)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPublicKey {
    func encrypt<D: DataProtocol>(_ data: D, padding: RSAEncryptionPadding) throws -> Data {
        try backing.encrypt(data, padding: padding)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPublicKey {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate final class Backing: @unchecked Sendable {
        private let pointer: OpaquePointer

        fileprivate init(takingOwnershipOf pointer: OpaquePointer) {
            self.pointer = pointer
        }

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPublicKey = CCryptoBoringSSL_RSAPublicKey_dup(
                CCryptoBoringSSL_EVP_PKEY_get0_RSA(other.pointer)
            )
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pointer, rsaPublicKey)
        }

        fileprivate init(n: some ContiguousBytes, e: some ContiguousBytes) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let n = try ArbitraryPrecisionInteger(bytes: n)
            let e = try ArbitraryPrecisionInteger(bytes: e)

            // Create BoringSSL RSA key.
            guard
                let rsaPtr = n.withUnsafeBignumPointer({ n in
                    e.withUnsafeBignumPointer { e in
                        CCryptoBoringSSL_RSA_new_public_key(n, e)
                    }
                })
            else { throw CryptoKitError.internalBoringSSLError() }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pointer, rsaPtr)
        }

        fileprivate var keySizeInBits: Int {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)
            return Int(CCryptoBoringSSL_RSA_size(rsaPublicKey)) * 8
        }

        fileprivate func encrypt<D: DataProtocol>(
            _ data: D,
            padding: RSAEncryptionPadding
        ) throws
            -> Data
        {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))
            var output = Data(count: outputSize)

            let contiguousData: any ContiguousBytes =
                data.regions.count == 1 ? data.regions.first! : Array(data)
            try output.withUnsafeMutableBytes { bufferPtr in
                try contiguousData.withUnsafeBytes { dataPtr in
                    // `nil` 'engine' defaults to the standard implementation with no hooks
                    let ctx = CCryptoBoringSSL_EVP_PKEY_CTX_new(self.pointer, nil)
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_CTX_free(ctx)
                    }

                    CCryptoBoringSSL_EVP_PKEY_encrypt_init(ctx)

                    switch padding {
                    case .pkcs1_5:
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)
                    case .pkcs1_oaep(let digest):
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                        switch digest {
                        case .sha1:
                            break // default case, nothing to set
                        case .sha256:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha256())
                        case .sha384:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha384())
                        case .sha512:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha512())
                        }
                    }

                    var writtenLength = bufferPtr.count
                    let rc = CCryptoBoringSSLShims_EVP_PKEY_encrypt(
                        ctx,
                        bufferPtr.baseAddress,
                        &writtenLength,
                        dataPtr.baseAddress,
                        dataPtr.count
                    )
                    precondition(
                        writtenLength == bufferPtr.count,
                        "PKEY encrypt actual written length should match RSA key size."
                    )

                    guard rc == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                }
            }
            return output
        }

        deinit {
            CCryptoBoringSSL_EVP_PKEY_free(self.pointer)
        }

        fileprivate func getKeyPrimitives() -> (n: Data, e: Data) {
            let key = CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)

            func getPrimitive(_ getPointer: (OpaquePointer?) -> UnsafePointer<BIGNUM>?) -> Data {
                let ptr = getPointer(key)
                let size = Int(CCryptoBoringSSL_BN_num_bytes(ptr))
                var data = Data(count: size)
                data.withUnsafeMutableBytes { dataPtr in
                    _ = CCryptoBoringSSL_BN_bn2bin(ptr, dataPtr.baseAddress)
                }
                return data
            }

            return (getPrimitive(CCryptoBoringSSL_RSA_get0_n), getPrimitive(CCryptoBoringSSL_RSA_get0_e))
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPrivateKey {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate final class Backing: @unchecked Sendable {
        private let pointer: OpaquePointer
        
        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPrivateKey = CCryptoBoringSSL_RSAPrivateKey_dup(
                CCryptoBoringSSL_EVP_PKEY_get0_RSA(other.pointer)
            )
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pointer, rsaPrivateKey)
        }
        
        fileprivate init(
            n: some ContiguousBytes,
            e: some ContiguousBytes,
            d: some ContiguousBytes
        ) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let n = try ArbitraryPrecisionInteger(bytes: n)
            let e = try ArbitraryPrecisionInteger(bytes: e)
            let d = try ArbitraryPrecisionInteger(bytes: d)
            // Create BoringSSL RSA key.
            guard
                let rsaPtr = n.withUnsafeBignumPointer({ n in
                    e.withUnsafeBignumPointer { e in
                        d.withUnsafeBignumPointer { d in
                            CCryptoBoringSSL_RSA_new_private_key_no_crt(n, e, d)
                        }
                    }
                })
            else { throw CryptoKitError.internalBoringSSLError() }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pointer, rsaPtr)
        }
        
        fileprivate init(
            n: some ContiguousBytes,
            e: some ContiguousBytes,
            d: some ContiguousBytes,
            p: some ContiguousBytes,
            q: some ContiguousBytes,
            dmp1: some ContiguousBytes,
            dmq1: some ContiguousBytes,
            iqmp: some ContiguousBytes
        ) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let n = try ArbitraryPrecisionInteger(bytes: n)
            let e = try ArbitraryPrecisionInteger(bytes: e)
            let d = try ArbitraryPrecisionInteger(bytes: d)
            let p = try ArbitraryPrecisionInteger(bytes: p)
            let q = try ArbitraryPrecisionInteger(bytes: q)
            let dmp1 = try ArbitraryPrecisionInteger(bytes: dmp1)
            let dmq1 = try ArbitraryPrecisionInteger(bytes: dmq1)
            let iqmp = try ArbitraryPrecisionInteger(bytes: iqmp)
            
            // Create BoringSSL RSA key.
            guard
                let rsaPtr = n.withUnsafeBignumPointer({ n in
                    e.withUnsafeBignumPointer { e in
                        d.withUnsafeBignumPointer { d in
                            p.withUnsafeBignumPointer { p in
                                q.withUnsafeBignumPointer { q in
                                    dmp1.withUnsafeBignumPointer { dmp1 in
                                        dmq1.withUnsafeBignumPointer { dmq1 in
                                            iqmp.withUnsafeBignumPointer { iqmp in
                                                CCryptoBoringSSL_RSA_new_private_key(n, e, d, p, q, dmp1, dmq1, iqmp)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                })
            else { throw CryptoKitError.internalBoringSSLError() }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pointer, rsaPtr)
        }
        
        fileprivate var keySizeInBits: Int {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)
            return Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey)) * 8
        }
        
        fileprivate var publicKey: BoringSSLRSAPublicKey {
            let pkey = CCryptoBoringSSL_EVP_PKEY_new()!
            let rsaPublicKey = CCryptoBoringSSL_RSAPublicKey_dup(
                CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)
            )
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pkey, rsaPublicKey)
            let backing = BoringSSLRSAPublicKey.Backing(
                takingOwnershipOf: pkey
            )
            return BoringSSLRSAPublicKey(backing)
        }
        
        fileprivate func getKeyPrimitives() -> (n: Data, e: Data, d: Data, p: Data, q: Data, dp: Data, dq: Data, qi: Data) {
            let key = CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)
            
            func getPrimitive(_ getPointer: (OpaquePointer?) -> UnsafePointer<BIGNUM>?) -> Data {
                let ptr = getPointer(key)
                let size = Int(CCryptoBoringSSL_BN_num_bytes(ptr))
                var data = Data(count: size)
                data.withUnsafeMutableBytes { dataPtr in
                    _ = CCryptoBoringSSL_BN_bn2bin(ptr, dataPtr.baseAddress)
                }
                return data
            }
            
            return (
                getPrimitive(CCryptoBoringSSL_RSA_get0_n),
                getPrimitive(CCryptoBoringSSL_RSA_get0_e),
                getPrimitive(CCryptoBoringSSL_RSA_get0_d),
                getPrimitive(CCryptoBoringSSL_RSA_get0_p),
                getPrimitive(CCryptoBoringSSL_RSA_get0_q),
                getPrimitive(CCryptoBoringSSL_RSA_get0_dmp1),
                getPrimitive(CCryptoBoringSSL_RSA_get0_dmq1),
                getPrimitive(CCryptoBoringSSL_RSA_get0_iqmp)
            )
        }
        
        fileprivate func decrypt<D: DataProtocol>(
            _ data: D,
            padding: RSAEncryptionPadding
        ) throws
            -> Data
        {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))
            var output = Data(count: outputSize)
            
            let contiguousData: any ContiguousBytes =
                data.regions.count == 1 ? data.regions.first! : Array(data)
            let writtenLength: CInt = try output.withUnsafeMutableBytes { bufferPtr in
                try contiguousData.withUnsafeBytes { dataPtr in
                    let ctx = CCryptoBoringSSL_EVP_PKEY_CTX_new(self.pointer, nil)
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_CTX_free(ctx)
                    }
                    
                    CCryptoBoringSSL_EVP_PKEY_decrypt_init(ctx)
                    switch padding {
                    case .pkcs1_5:
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)
                    case .pkcs1_oaep(let digest):
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                        switch digest {
                        case .sha1:
                            break // default case, nothing to set
                        case .sha256:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha256())
                        case .sha384:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha384())
                        case .sha512:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha512())
                        }
                    }
                    
                    var writtenLength = bufferPtr.count
                    
                    let rc = CCryptoBoringSSLShims_EVP_PKEY_decrypt(
                        ctx,
                        bufferPtr.baseAddress,
                        &writtenLength,
                        dataPtr.baseAddress,
                        dataPtr.count
                    )
                    
                    guard rc == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    
                    return CInt(writtenLength)
                }
            }
            
            output.removeSubrange(
                output.index(output.startIndex, offsetBy: Int(writtenLength)) ..< output.endIndex
            )
            return output
        }
    }
}

/// A wrapper around the OpenSSL BIGNUM object that is appropriately lifetime managed,
/// and that provides better Swift types for this object.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
package struct ArbitraryPrecisionInteger {
    private var _backing: BackingStorage

    @usableFromInline
    package init() {
        self._backing = BackingStorage()
    }

    package init(copying original: UnsafePointer<BIGNUM>) throws {
        self._backing = try BackingStorage(copying: original)
    }

    @usableFromInline
    package init(_ original: ArbitraryPrecisionInteger) throws {
        self._backing = try BackingStorage(copying: original._backing)
    }

    @usableFromInline
    package init(integerLiteral value: Int64) {
        self._backing = BackingStorage(value)
    }
}

// MARK: - BackingStorage

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate final class BackingStorage {
        private var _backing: BIGNUM

        init() {
            self._backing = BIGNUM()
            CCryptoBoringSSL_BN_init(&_backing)
        }

        init(copying original: UnsafePointer<BIGNUM>) throws {
            self._backing = BIGNUM()
            guard CCryptoBoringSSL_BN_copy(&_backing, original) != nil else {
                throw CryptoKitError.internalBoringSSLError()
            }
        }

        init(copying original: BackingStorage) throws {
            self._backing = BIGNUM()

            try original.withUnsafeMutableBignumPointer { bnPtr in
                guard CCryptoBoringSSL_BN_copy(&self._backing, bnPtr) != nil else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
        }

        init(_ value: Int64) {
            self._backing = BIGNUM()
            let rc = CCryptoBoringSSL_BN_set_u64(&_backing, value.magnitude)
            precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

            if value < 0 {
                CCryptoBoringSSL_BN_set_negative(&_backing, 1)
            }
        }

        deinit {
            CCryptoBoringSSL_BN_clear_free(&self._backing)
        }
    }
}

// MARK: - Extra initializers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @usableFromInline
    package init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self._backing = try BackingStorage(bytes: bytes)
    }

    /// Create an `ArbitraryPrecisionInteger` from a hex string.
    ///
    /// - Parameter hexString: Hex byte string (big-endian, no `0x` prefix, may start with `-` for a negative number).
    @usableFromInline
    package init(hexString: String) throws {
        self._backing = try BackingStorage(hexString: hexString)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger.BackingStorage {
    convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self.init()

        let rc: UnsafeMutablePointer<BIGNUM>? = bytes.withUnsafeBytes { bytesPointer in
            CCryptoBoringSSLShims_BN_bin2bn(
                bytesPointer.baseAddress,
                bytesPointer.count,
                &self._backing
            )
        }
        guard rc != nil else {
            throw CryptoKitError.internalBoringSSLError()
        }
    }

    @inlinable
    convenience init(hexString: String) throws {
        self.init()
        try hexString.withCString { hexStringPtr in
            /// `BN_hex2bin` takes a `BIGNUM **` so we need a double WUMP dance.
            try withUnsafeMutablePointer(to: &self._backing) { backingPtr in
                var backingPtr: UnsafeMutablePointer<BIGNUM>? = backingPtr
                try withUnsafeMutablePointer(to: &backingPtr) { backingPtrPtr in
                    /// `BN_hex2bin` returns the number of bytes of `in` processed or zero on error.
                    guard CCryptoBoringSSL_BN_hex2bn(backingPtrPtr, hexStringPtr) == hexString.count else {
                        throw CryptoKitError.incorrectParameterSize
                    }
                }
            }
        }
    }
}

// MARK: - Pointer helpers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    package func withUnsafeBignumPointer<T>(
        _ body: (UnsafePointer<BIGNUM>) throws -> T
    ) rethrows
        -> T
    {
        try _backing.withUnsafeBignumPointer(body)
    }

    package mutating func withUnsafeMutableBignumPointer<T>(
        _ body: (UnsafeMutablePointer<BIGNUM>) throws -> T
    ) throws -> T {
        if !isKnownUniquelyReferenced(&_backing) {
            // Failing to CoW is a fatal error here.
            _backing = try BackingStorage(copying: _backing)
        }

        return try _backing.withUnsafeMutableBignumPointer(body)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger.BackingStorage {
    func withUnsafeBignumPointer<T>(_ body: (UnsafePointer<BIGNUM>) throws -> T) rethrows -> T {
        try body(&_backing)
    }

    func withUnsafeMutableBignumPointer<T>(
        _ body: (UnsafeMutablePointer<BIGNUM>) throws -> T
    )
        rethrows -> T
    {
        try body(&_backing)
    }
}
#endif
