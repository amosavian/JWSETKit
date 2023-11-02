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
#if canImport(_CryptoExtras)
import _CryptoExtras
#endif

/// JSON Web Key (JWK) container for AES-CBC keys for encryption/decryption with HMAC authentication.
public struct JSONWebKeyAESCBCHMAC: MutableJSONWebKey, JSONWebSealingKey, JSONWebSymmetricDecryptingKey, Sendable {
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
        ((try? symmetricKey.bitCount) ?? 0) / 16
    }
    
    /// AES-CBC symmetric key using for encryption.
    public var aesSymmetricKey: SymmetricKey {
        get throws {
            let key = try symmetricKey.data
            return SymmetricKey(data: key.suffix(key.count / 2))
        }
    }
    
    /// HMAC symmetric key using for encryption.
    public var hmacSymmetricKey: SymmetricKey {
        get throws {
            let key = try symmetricKey.data
            return SymmetricKey(data: key.prefix(key.count / 2))
        }
    }
    
    public init(algorithm: any JSONWebAlgorithm) throws {
        guard let keySize = JSONWebContentEncryptionAlgorithm(algorithm.rawValue).keyLength else {
            throw CryptoKitError.incorrectKeySize
        }
        self.init(size: keySize)
    }
    
    public init() throws {
        self.init(size: .bits256)
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
    public init(size: SymmetricKeySize) {
        self.storage = .init()
        self.algorithm = .aesEncryptionCBCSHA(bitCount: size.bitCount)
        self.keyValue = SymmetricKey(size: .init(bitCount: size.bitCount * 2))
    }
    
    /// Initializes a AES-CBC with HMAC key for encryption.
    ///
    /// - Parameter key: A symmetric cryptographic key.
    public init(_ key: SymmetricKey) throws {
        guard [256, 384, 512].contains(key.bitCount) else {
            throw CryptoKitError.incorrectKeySize
        }
        self.storage = .init()
        self.algorithm = .aesEncryptionCBCSHA(bitCount: key.bitCount / 2)
        self.keyValue = key
    }
    
    public func seal<D, IV, AAD, JWA>(_ data: D, iv: IV?, authenticating: AAD?, using _: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        let iv = iv.map { Data($0) } ?? SymmetricKey(size: .init(bitCount: ivLength * 8)).data
        guard iv.count == ivLength else {
            throw CryptoKitError.incorrectParameterSize
        }
#if canImport(CommonCrypto)
        let ciphertext = try aesSymmetricKey.ccCrypt(operation: .aesCBC(decrypt: false), iv: iv, data: Data(data))
#else
        let ciphertext = try AES._CBC.encrypt(data, using: aesSymmetricKey, iv: .init(ivBytes: iv))
#endif
        let authenticated = authenticating.map { Data($0) } ?? .init()
        let tag = try hmac(authenticated + Data(iv) + ciphertext + authenticated.cbcTagLengthOctetHexData())
        return .init(iv: Data(iv), ciphertext: ciphertext, tag: tag.prefix(tagLength))
    }
    
    public func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using _: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        let authenticated = authenticating.map { Data($0) } ?? .init()
        let tagData = authenticated + Data(data.iv) + data.ciphertext + authenticated.cbcTagLengthOctetHexData()
        guard try data.tag == hmac(tagData).prefix(tagLength) else {
            throw CryptoKitError.authenticationFailure
        }
        
#if canImport(CommonCrypto)
        return try aesSymmetricKey.ccCrypt(operation: .aesCBC(decrypt: true), iv: data.iv, data: data.ciphertext)
#else
        return try AES._CBC.decrypt(data.ciphertext, using: aesSymmetricKey, iv: .init(ivBytes: data.iv))
#endif
    }
    
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, using: algorithm).combined
    }
    
    public func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try open(.init(data: data, ivLength: ivLength, tagLength: tagLength), using: algorithm)
    }
    
    private func hmac(_ data: Data) throws -> Data {
        switch tagLength * 2 {
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
    func cbcTagLengthOctetHexData() -> Data {
        let dataLength = UInt64(count * 8)
        let dataLengthInHex = String(dataLength, radix: 16, uppercase: false)
        
        var dataLengthBytes = [UInt8](repeatElement(0x00, count: 8))
        
        var dataIndex = dataLengthBytes.count - 1
        for index in stride(from: 0, to: dataLengthInHex.count, by: 2) {
            var offset = 2
            var hexStringChunk = ""
            
            if dataLengthInHex.count - index == 1 {
                offset = 1
            }
            
            let endIndex = dataLengthInHex.index(dataLengthInHex.endIndex, offsetBy: -index)
            let startIndex = dataLengthInHex.index(endIndex, offsetBy: -offset)
            let range = Range(uncheckedBounds: (lower: startIndex, upper: endIndex))
            hexStringChunk = String(dataLengthInHex[range])
            
            if let hexByte = UInt8(hexStringChunk, radix: 16) {
                dataLengthBytes[dataIndex] = hexByte
            }
            
            dataIndex -= 1
        }
        
        return Data(dataLengthBytes)
    }
}
