//
//  PBKDF2.swift
//
//
//  Created by Amir Abbas Mousavian on 10/11/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#else
import CryptoSwift
#endif

extension SymmetricKey {
    /// Generates a symmetric key using `PBKDF2` algorithm.
    ///
    /// - Parameters:
    ///   - password: The master password from which a derived key is generated.
    ///   - salt: A sequence of bits, known as a cryptographic salt.
    ///   - hashFunction: Pseudorandom function algorithm.
    ///   - iterations: Iteration count, a positive integer.
    ///
    /// - Returns: A symmetric key derived from parameters.
    public static func pbkdf2<PD, SD, H>(
        pbkdf2Password password: PD, salt: SD, hashFunction: H.Type, iterations: Int
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
#if canImport(CommonCrypto)
        return try ccPbkdf2(pbkdf2Password: password, salt: salt, hashFunction: hashFunction, iterations: iterations)
#elseif canImport(CryptoSwift)
        let variant = try CryptoSwift.HMAC.Variant(hashFunction)
        let key = try PKCS5.PBKDF2(password: [UInt8](password), salt: [UInt8](salt), iterations: iterations, variant: variant).calculate()
        return .init(data: key)
#else
        // This should never happen as CommonCrypto is available on Darwin platforms
        // and CryptoSwift is used on non-Darwin platform.
        fatalError("Unimplemented")
#endif
    }
}

#if canImport(CryptoSwift)
extension CryptoSwift.HMAC.Variant {
    init<H>(_ hashFunction: H.Type) throws where H: HashFunction {
        switch hashFunction.Digest.byteCount {
        case SHA256.byteCount:
            self = .sha2(.sha256)
        case SHA384.byteCount:
            self = .sha2(.sha384)
        case SHA512.byteCount:
            self = .sha2(.sha512)
        case Insecure.SHA1.byteCount:
            self = .sha1
        default:
            throw CryptoKitError.incorrectKeySize
        }
    }
}
#endif
