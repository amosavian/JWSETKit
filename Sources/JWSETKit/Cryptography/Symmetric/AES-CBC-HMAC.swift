//
//  AES-CBC-HMAC.swift
//
//
//  Created by Amir Abbas Mousavian on 10/3/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import _CryptoExtras

/// JSON Web Key (JWK) container for AES-CBC keys for encryption/decryption with HMAC authentication.
public struct JSONWebKeyAESCBCHMAC: MutableJSONWebKey, JSONWebSealingKey, Sendable {
    public typealias PublicKey = Self
    
    public var publicKey: JSONWebKeyAESCBCHMAC { self }
    
    public var storage: JSONWebValueStorage
    
    /// Symmetric key using for encryption.
    public var symmetricKey: SymmetricKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            guard let keyValue = self.keyValue else {
                throw CryptoKitError.incorrectKeySize
            }
            return keyValue
        }
    }
    
    public var ivLength: Int { 16 }
    
    public var tagLength: Int {
        (try? symmetricKey.bitCount) ?? 0 / 16
    }
    
    /// AES-CBC symmetric key using for encryption.
    public var aesSymmetricKey: SymmetricKey {
        get throws {
            let key = try symmetricKey.withUnsafeBytes { Data($0) }
            return SymmetricKey(data: key.suffix(key.count / 2))
        }
    }
    
    /// HMAC symmetric key using for encryption.
    public var hmacSymmetricKey: SymmetricKey {
        get throws {
            let key = try symmetricKey.withUnsafeBytes { Data($0) }
            return SymmetricKey(data: key.prefix(key.count / 2))
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebKeyAESCBCHMAC {
        .init(storage: storage)
    }
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// Returns a new AES-CBC with HMAC with random key.
    ///
    /// - Parameter keySize: Size of random key for AES-CBC in bits.
    public init(_ keySize: SymmetricKeySize) {
        self.storage = .init()
        self.algorithm = .aesEncryptionCBCSHA(bitCount: keySize.bitCount)
        self.keyValue = SymmetricKey(size: .init(bitCount: keySize.bitCount * 2))
    }
    
    /// Initializes a AES-CBC with HMAC key for encryption.
    ///
    /// - Parameter key: A symmetric cryptographic key.
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.algorithm = .aesEncryptionCBCSHA(bitCount: key.bitCount / 2)
        self.keyValue = key
    }
    
    public func seal<D, IV, AAD, JWA>(_ data: D, iv: IV?, authenticating: AAD?, using _: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        var generator = SystemRandomNumberGenerator()
        let iv = iv.map { Data($0) } ?? Data((0 ..< ivLength).map { _ in UInt8.random(in: UInt8.min ... UInt8.max, using: &generator) })
        guard iv.count == ivLength else {
            throw CryptoKitError.incorrectParameterSize
        }
        let ciphertext = try AES._CBC.encrypt(data, using: aesSymmetricKey, iv: .init(ivBytes: iv))
        let authenticated = authenticating.map { Data($0) } ?? .init()
        let tag = try hmac(authenticated + Data(iv) + ciphertext + Data(authenticated.count.bigEndian))
        return .init(iv: Data(iv), ciphertext: ciphertext, tag: tag.prefix(tagLength))
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using _: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        let authenticated = authenticating.map { Data($0) } ?? .init()
        let tagData = authenticated + Data(data.iv) + data.ciphertext + Data(authenticated.count.bigEndian)
        guard try data.tag == hmac(tagData).prefix(tagLength) else {
            throw CryptoKitError.authenticationFailure
        }
        return try AES._CBC.decrypt(data.ciphertext, using: aesSymmetricKey, iv: .init(ivBytes: data.iv))
    }
    
    private func hmac(_ data: Data) throws -> Data {
        switch tagLength {
        case SHA256.byteCount:
            var hmac = try HMAC<SHA256>(key: hmacSymmetricKey)
            hmac.update(data: data)
            return Data(hmac.finalize())
        case SHA384.byteCount:
            var hmac = try HMAC<SHA384>(key: hmacSymmetricKey)
            hmac.update(data: data)
            return Data(hmac.finalize())
        case SHA512.byteCount:
            var hmac = try HMAC<SHA512>(key: hmacSymmetricKey)
            hmac.update(data: data)
            return Data(hmac.finalize())
        default:
            throw CryptoKitError.incorrectKeySize
        }
    }
}

extension Data {
    init<T: FixedWidthInteger>(_ value: T) {
        let count = T.bitWidth / 8
        var _endian = value
        let bytePtr = withUnsafePointer(to: &_endian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        self = Data(bytePtr)
    }
}
