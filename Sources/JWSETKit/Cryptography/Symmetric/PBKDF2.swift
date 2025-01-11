//
//  PBKDF2.swift
//
//
//  Created by Amir Abbas Mousavian on 10/11/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
#if canImport(_CryptoExtras)
import _CryptoExtras
#endif

extension SymmetricKey {
    static let defaultPBES2IterationCount: [Int: Int] = [
        128: 600_000,
        192: 450_000,
        256: 210_000,
    ]
    
    /// Generates a symmetric key using `PBKDF2` algorithm.
    ///
    /// - Parameters:
    ///   - password: The master password from which a derived key is generated.
    ///   - salt: A sequence of bits, known as a cryptographic salt.
    ///   - hashFunction: Pseudorandom function algorithm.
    ///   - iterations: Iteration count, a positive integer.
    ///
    /// - Returns: A symmetric key derived from parameters.
    public static func paswordBased2DerivedSymmetricKey<PD, SD, H>(
        password: PD, salt: SD, iterations: Int, length: Int? = nil, hashFunction: H.Type
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
        let length = length ?? hashFunction.Digest.byteCount
#if canImport(CommonCrypto)
        return try ccPbkdf2(pbkdf2Password: password, salt: salt, iterations: iterations, length: length, hashFunction: hashFunction)
#elseif canImport(_CryptoExtras)
        return try KDF.Insecure.PBKDF2.deriveKey(from: password, salt: salt, using: .init(hashFunction), outputByteCount: length, unsafeUncheckedRounds: iterations)
#else
#error("Unimplemented")
#endif
    }
}

extension KDF.Insecure.PBKDF2.HashFunction {
    init<H>(_: H.Type) throws where H: HashFunction {
        if H.self == Insecure.SHA1.self {
            self = .insecureSHA1
        } else if H.self == SHA256.self {
            self = .sha256
        } else if H.self == SHA384.self {
            self = .sha384
        } else if H.self == SHA512.self {
            self = .sha512
        } else {
            throw CryptoKitError.incorrectKeySize
        }
    }
}
