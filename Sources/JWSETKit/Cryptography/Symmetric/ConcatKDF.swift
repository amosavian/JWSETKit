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

extension SharedSecret {
    /// Derives a symmetric encryption key from the secret using NIST SP800-56Ar2 section 5.8.1
    /// derivation.
    ///
    /// - Parameters:
    ///   - hashFunction: The hash function to use for key derivation.
    ///   - otherInfo: The other information to use for key derivation.
    ///   - outputByteCount: The length in bytes of resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public func concatDerivedSymmetricKey<H, OI>(
        using hashFunction: H.Type,
        otherInfo: OI,
        outputByteCount keySize: Int
    ) -> SymmetricKey where H: HashFunction, OI: DataProtocol {
        let hashSize = hashFunction.Digest.byteCount * 8
        let iterations = (keySize / hashSize) + (!keySize.isMultiple(of: hashSize) ? 1 : 0)
        
        let derivedKey = (1 ... iterations).reduce(Data()) { partialResult, counter in
            var hash = H()
            hash.update(UInt32(counter).bigEndian)
            withUnsafeBytes { hash.update(bufferPointer: $0) }
            hash.update(data: otherInfo)
            return partialResult + hash.finalize().data
        }
        return .init(data: derivedKey.trim(bitCount: keySize))
    }
    
    func concatDerivedSymmetricKey<H, APU, APV>(
        using hashFunction: H.Type,
        algorithm: JSONWebKeyEncryptionAlgorithm,
        contentEncryptionAlgorithm: JSONWebContentEncryptionAlgorithm?,
        apu: APU,
        apv: APV
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
        return concatDerivedSymmetricKey(
            using: hashFunction,
            otherInfo: Data([
                algorithm.lengthBytes, algorithm,
                apu.lengthBytes, Data(apu),
                apv.lengthBytes, Data(apv),
                Data(value: UInt32(keySize).bigEndian), // <- suppPubInfo
            ].joined()),
            outputByteCount: keySize
        )
    }
}

extension MutableDataProtocol {
    fileprivate func trim(bitCount: Int) -> Self {
        var result = self
        if bitCount.isMultiple(of: 8) {
            result.removeLast(count - bitCount / 8)
        } else {
            result.removeLast(count - bitCount / 8 - 1)
            result[result.index(before: result.endIndex)] &= ~(0xFF >> (UInt(bitCount) % 8))
        }
        
        return result
    }
}

extension RandomAccessCollection where Self.Element == UInt8 {
    fileprivate var lengthBytes: Data {
        Data(value: UInt32(count).bigEndian)
    }
}

extension HashFunction {
    @inlinable
    mutating func update<T>(_ value: T) {
        withUnsafeBytes(of: value) {
            self.update(bufferPointer: $0)
        }
    }
}
