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
#if canImport(CryptoExtras)
import CryptoExtras
#endif

extension SymmetricKey {
    static let defaultPBES2IterationCount: [Int: Int] = [
        128: 600_000,
        192: 450_000,
        256: 310_000,
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
    public static func passwordBased2DerivedSymmetricKey<PD, SD, H>(
        password: PD, salt: SD, iterations: Int, length: Int? = nil, hashFunction: H.Type
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
        let length = length ?? hashFunction.Digest.byteCount
#if canImport(CommonCrypto)
        return try ccPbkdf2(pbkdf2Password: password, salt: salt, iterations: iterations, length: length, hashFunction: hashFunction)
#elseif canImport(CryptoExtras)
        return try KDF.Insecure.PBKDF2.deriveKey(from: password, salt: salt, using: .init(hashFunction), outputByteCount: length, unsafeUncheckedRounds: iterations)
#else
        #error("Unimplemented")
#endif
    }
}

#if canImport(CryptoExtras)
extension KDF.Insecure.PBKDF2.HashFunction {
    init<H>(_: H.Type) throws where H: HashFunction {
        switch H.self {
        case is Insecure.SHA1.Type:
            self = .insecureSHA1
        case is SHA256.Type:
            self = .sha256
        case is SHA384.Type:
            self = .sha384
        case is SHA512.Type:
            self = .sha512
        default:
            throw CryptoKitError.incorrectKeySize
        }
    }
}
#endif
