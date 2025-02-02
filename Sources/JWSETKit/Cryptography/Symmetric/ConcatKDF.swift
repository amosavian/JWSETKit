//
//  ConcatKDF.swift
//
//
//  Created by Amir Abbas Mousavian on 2/14/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

extension SymmetricKey {
    /// Concatenation Key Derivation Function regarding NIST SP800-56Ar2 section 5.8.1.
    ///
    /// - Parameters:
    ///  - secret: The secret key.
    ///  - hashFunction: The hash function to use.
    ///  - params: The parameters to concatenate .
    public static func concatDerivedSymmetricKey<H>(
        parameters: [any DataProtocol],
        hashFunction: H.Type,
        keySize: Int
    ) throws -> SymmetricKey where H: HashFunction {
        let hashSize = hashFunction.Digest.byteCount * 8
        let iterations = (keySize / hashSize) + (!keySize.isMultiple(of: hashSize) ? 1 : 0)
        
        let derivedKey = (1 ... iterations).reduce(Data()) { partialResult, counter in
            var hash = hashFunction.init()
            hash.update(UInt32(counter).bigEndian)
            parameters.forEach { hash.update(data: $0) }
            return partialResult + hash.finalize().data
        }
        return .init(data: derivedKey.trim(bitCount: keySize))
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
        if let length = algorithm.keyLength {
            algorithmID = algorithm.rawValue
            keySize = length
        } else {
            guard let cek = contentEncryptionAlgorithm, let contentKeySize = cek.keyLength?.bitCount else {
                throw CryptoKitError.incorrectKeySize
            }
            algorithmID = cek.rawValue
            keySize = contentKeySize
        }
        let algorithm = Data(algorithmID.utf8)
        return try SymmetricKey.concatDerivedSymmetricKey(
            parameters: [
                data,
                algorithm.lengthBytes, algorithm,
                apu.lengthBytes, apu,
                apv.lengthBytes, apv,
                Data(value: UInt32(keySize).bigEndian), // suppPubInfo
            ],
            hashFunction: hashFunction,
            keySize: keySize
        )
    }
}

extension Data {
    fileprivate func trim(bitCount: Int) -> Self {
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
}

extension DataProtocol {
    fileprivate var lengthBytes: Data {
        Data(value: UInt32(count).bigEndian)
    }
}

extension HashFunction {
    mutating func update<T>(_ value: T) {
        withUnsafeBytes(of: value) {
            self.update(bufferPointer: $0)
        }
    }
}
