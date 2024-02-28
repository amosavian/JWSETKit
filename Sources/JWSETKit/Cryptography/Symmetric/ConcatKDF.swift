//
//  ConcatKDF.swift
//
//
//  Created by Amir Abbas Mousavian on 2/14/24.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

extension SymmetricKey {
    /// Concatenation Key Derivation Function regarding NIST SP800-56Ar2 section 5.8.1.
    ///
    /// - Parameters:
    ///  - secret: The secret key.
    ///  - hashFunction: The hash function to use.
    ///  - params: The parameters to concatenate .
    public static func concatDerivedSymmetricKey<H, P>(
        parameters: [P],
        hashFunction: H.Type,
        keySize: Int
    ) throws -> SymmetricKey where H: HashFunction, P: DataProtocol {
        let hashSize = hashFunction.Digest.byteCount * 8
        let iterations = (keySize / hashSize) + (!keySize.isMultiple(of: hashSize) ? 1 : 0)
        
        let derivedKey = (1 ... iterations).reduce(Data()) { partialResult, counter in
            var hash = hashFunction.init()
            hash.update(UInt32(counter).bigEndian)
            parameters.forEach { hash.update(data: $0) }
            return partialResult + hash.finalize().data
        }
        return .init(data: derivedKey.toBitCount(keySize))
    }
}

extension SharedSecret {
    func concatDerivedSymmetricKey<H, APU, APV>(
        algorithm: JSONWebKeyEncryptionAlgorithm,
        contentEncryptionAlgorithm: JSONWebContentEncryptionAlgorithm?,
        apu: APU,
        apv: APV,
        hashFunction: H.Type
    ) throws -> SymmetricKey where H: HashFunction, APU: DataProtocol, APV: DataProtocol {
        let algorithmID: String
        let keySize: Int
        if algorithm == .ecdhEphemeralStatic {
            guard let cek = contentEncryptionAlgorithm, let contentKeySize = cek.keyLength?.bitCount else {
                throw CryptoKitError.incorrectKeySize
            }
            algorithmID = cek.rawValue
            keySize = contentKeySize
        } else if let length = algorithm.keyLength {
            algorithmID = algorithm.rawValue
            keySize = length
        } else {
            throw CryptoKitError.incorrectKeySize
        }
        
        return try SymmetricKey.concatDerivedSymmetricKey(
            parameters: [
                data,
                Data(algorithmID.utf8).lengthPrefixed,
                Data(apu).lengthPrefixed,
                Data(apv).lengthPrefixed,
                Data(value: UInt32(keySize).bigEndian), // suppPubInfo
            ],
            hashFunction: hashFunction,
            keySize: keySize
        )
    }
}

extension Data {
    func toBitCount(_ bitCount: Int) -> Self {
        var result = self
        if bitCount.isMultiple(of: 8) {
            result.count = bitCount / 8
            return result
        } else {
            result.count = bitCount / 8 + 1
            result[result.count - 1] &= ~(0xFF >> (UInt(bitCount) % 8))
        }
        
        return result
    }
    
    var lengthPrefixed: Data {
        Data(value: UInt32(count).bigEndian) + self
    }
}

extension HashFunction {
    mutating func update<T>(_ value: T) {
        withUnsafeBytes(of: value) {
            self.update(bufferPointer: $0)
        }
    }
}
