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
import CryptoSwift
#endif
#if canImport(CommonCrypto)
import CommonCrypto
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
        let hash: CCPseudoRandomAlgorithm
        switch hashFunction.Digest.byteCount {
        case SHA256.byteCount:
            hash = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case SHA384.byteCount:
            hash = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case SHA512.byteCount:
            hash = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        case Insecure.SHA1.byteCount:
            hash = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        default:
            throw CryptoKitError.incorrectKeySize
        }
        
        var derivedKeyData = Data(repeating: 0, count: hashFunction.Digest.byteCount)
        let derivedCount = derivedKeyData.count
        
        let derivationStatus: OSStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            Data(salt).withUnsafeBytes { saltBytes in
                Data(password).withUnsafeBytes {
                    let saltBytes = saltBytes.bindMemory(to: UInt8.self).baseAddress
                    let derivedKeyRawBytes = derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress
                    let passwordBytes = $0.bindMemory(to: UInt8.self).baseAddress
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes,
                        password.count,
                        saltBytes,
                        salt.count,
                        hash,
                        UInt32(iterations),
                        derivedKeyRawBytes,
                        derivedCount
                    )
                }
            }
        }
        
        switch Int(derivationStatus) {
        case kCCSuccess:
            return .init(data: derivedKeyData)
        case kCCParamError:
            throw CryptoKitError.incorrectParameterSize
        case kCCBufferTooSmall, kCCMemoryFailure, kCCAlignmentError,
             kCCDecodeError, kCCUnimplemented, kCCOverflow,
             kCCRNGFailure, kCCUnspecifiedError, kCCCallSequenceError:
            throw CryptoKitError.underlyingCoreCryptoError(error: Int32(derivationStatus))
        case kCCKeySizeError, kCCInvalidKey:
            throw CryptoKitError.incorrectKeySize
        default:
            throw CryptoKitError.incorrectKeySize
        }
#else
        let variant: CryptoSwift.HMAC.Variant
        switch hashFunction.Digest.byteCount {
        case SHA256.byteCount:
            variant = .sha2(.sha256)
        case SHA384.byteCount:
            variant = .sha2(.sha384)
        case SHA512.byteCount:
            variant = .sha2(.sha512)
        case Insecure.SHA1.byteCount:
            variant = .sha1
        default:
            throw CryptoKitError.incorrectKeySize
        }
        let key = try PKCS5.PBKDF2(password: [UInt8](password), salt: [UInt8](salt), iterations: iterations, variant: variant).calculate()
        return .init(data: key)
#endif
    }
}
