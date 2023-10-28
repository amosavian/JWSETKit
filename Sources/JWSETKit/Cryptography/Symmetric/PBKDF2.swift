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
#if canImport(CommonCrypto)
    private static func ccpbkdf2<PD, SD, H>(
        pbkdf2Password password: PD, salt: SD, hashFunction: H.Type, iterations: Int
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
        let hash = try CCPseudoRandomAlgorithm(hashFunction)
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
                        passwordBytes, password.count,
                        saltBytes, salt.count,
                        hash,
                        UInt32(iterations),
                        derivedKeyRawBytes, derivedCount
                    )
                }
            }
        }
        
        switch Int(derivationStatus) {
        case kCCSuccess:
            return .init(data: derivedKeyData)
        case kCCParamError:
            throw CryptoKitError.incorrectParameterSize
        case kCCKeySizeError, kCCInvalidKey:
            throw CryptoKitError.incorrectKeySize
        default:
            throw CryptoKitError.underlyingCoreCryptoError(error: Int32(derivationStatus))
        }
    }
    #endif
    
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
        return try ccpbkdf2(pbkdf2Password: password, salt: salt, hashFunction: hashFunction, iterations: iterations)
#else
        let variant = try CryptoSwift.HMAC.Variant(hashFunction)
        let key = try PKCS5.PBKDF2(password: [UInt8](password), salt: [UInt8](salt), iterations: iterations, variant: variant).calculate()
        return .init(data: key)
#endif
    }
}

#if canImport(CommonCrypto)
extension CCPseudoRandomAlgorithm {
    init<H>(_ hashFunction: H.Type) throws where H: HashFunction {
        switch H.Digest.byteCount {
        case SHA256.byteCount:
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case SHA384.byteCount:
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case SHA512.byteCount:
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        case Insecure.SHA1.byteCount:
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        default:
            throw CryptoKitError.incorrectKeySize
        }
    }
}
#else
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
