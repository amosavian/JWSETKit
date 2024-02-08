//
//  CommonCrypto.swift
//
//
//  Created by Amir Abbas Mousavian on 11/1/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(CommonCrypto)
import CommonCrypto

struct CryptOperation {
    let operation: CCOperation
    let algorithm: CCAlgorithm
    let options: CCOptions
    let blockSize: Int
    
    init(operation: CCOperation, algorithm: CCAlgorithm, options: CCOptions, blockSize: Int) {
        self.operation = operation
        self.algorithm = algorithm
        self.options = options
        self.blockSize = blockSize
    }
    
    static func aesCBC(decrypt: Bool) -> Self {
        .init(
            operation: CCOperation(decrypt ? kCCDecrypt : kCCEncrypt),
            algorithm: CCAlgorithm(kCCAlgorithmAES),
            options: CCOptions(kCCOptionPKCS7Padding),
            blockSize: kCCBlockSizeAES128
        )
    }
}

extension SymmetricKey {
    func ccCrypt<IV, D>(operation: CryptOperation, iv: IV, data: D) throws -> Data where IV: DataProtocol, D: DataProtocol {
        let bufferSize: Int = iv.count + data.count + operation.blockSize
        var result = Data(repeating: 0, count: bufferSize)
        var resultLength = 0
        
        let status: CCCryptorStatus = result.withUnsafeMutableBytes { resultBytes in
            self.withUnsafeBytes { keyBytes in
                data.withUnsafeBuffer { dataBytes in
                    iv.withUnsafeBuffer { ivBytes in
                        CCCrypt(
                            operation.operation,
                            operation.algorithm,
                            operation.options,
                            keyBytes.baseAddress, keyBytes.count,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, dataBytes.count,
                            resultBytes.baseAddress, resultBytes.count,
                            &resultLength
                        )
                    }
                }
            }
        }
        
        switch Int(status) {
        case kCCSuccess:
            return result.prefix(resultLength)
        case kCCDecodeError:
            throw JSONWebKeyError.decryptionFailed
        case kCCAlignmentError, kCCBufferTooSmall:
            throw CryptoKitError.incorrectKeySize
        default:
            throw CryptoKitError.underlyingCoreCryptoError(error: Int32(status))
        }
    }
    
    public func ccWrapKey(_ key: SymmetricKey) throws -> Data {
        let keyLength = key.bitCount / 8
        var wrappedKey = Data(repeating: 0, count: CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), keyLength))
        let (result, wrappedKeyCount) = withUnsafeBytes { kek in
            key.withUnsafeBytes { rawKey in
                wrappedKey.withUnsafeMutableBytes { wrappedKey in
                    var wrappedKeyCount = 0
                    let result = CCSymmetricKeyWrap(
                        CCWrappingAlgorithm(kCCWRAPAES),
                        CCrfc3394_iv,
                        CCrfc3394_ivLen,
                        kek.baseAddress,
                        kek.count,
                        rawKey.baseAddress,
                        rawKey.count,
                        wrappedKey.baseAddress,
                        &wrappedKeyCount
                    )
                    return (result, wrappedKeyCount)
                }
            }
        }
        switch Int(result) {
        case kCCSuccess:
            return wrappedKey.prefix(wrappedKeyCount)
        case kCCParamError:
            throw CryptoKitError.incorrectParameterSize
        case kCCBufferTooSmall:
            throw CryptoKitError.incorrectKeySize
        default:
            throw CryptoKitError.underlyingCoreCryptoError(error: result)
        }
    }
    
    func ccUnwrapKey<D>(_ wrappedKey: D) throws -> SymmetricKey where D: DataProtocol {
        var rawKey = Data(repeating: 0, count: CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count))
        let (result, unwrappedKeyCount) = withUnsafeBytes { kek in
            wrappedKey.withUnsafeBuffer { wrappedKey in
                rawKey.withUnsafeMutableBytes { rawKey in
                    var unwrappedKeyCount = 0
                    let result = CCSymmetricKeyUnwrap(
                        CCWrappingAlgorithm(kCCWRAPAES),
                        CCrfc3394_iv,
                        CCrfc3394_ivLen,
                        kek.baseAddress,
                        kek.count,
                        wrappedKey.baseAddress,
                        wrappedKey.count,
                        rawKey.baseAddress,
                        &unwrappedKeyCount
                    )
                    return (result, unwrappedKeyCount)
                }
            }
        }
        switch Int(result) {
        case kCCSuccess:
            return .init(data: rawKey.prefix(unwrappedKeyCount))
        case kCCParamError:
            throw CryptoKitError.incorrectParameterSize
        case kCCBufferTooSmall:
            throw CryptoKitError.incorrectKeySize
        default:
            throw CryptoKitError.underlyingCoreCryptoError(error: result)
        }
    }
    
    static func ccPbkdf2<PD, SD, H>(
        pbkdf2Password password: PD, salt: SD, hashFunction: H.Type, iterations: Int
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
        let hash = try CCPseudoRandomAlgorithm(hashFunction)
        var derivedKeyData = Data(repeating: 0, count: hashFunction.Digest.byteCount)
        let derivedCount = derivedKeyData.count
        
        let derivationStatus: OSStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBuffer { saltBytes in
                password.withUnsafeBuffer {
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
}

extension CCPseudoRandomAlgorithm {
    init<H>(_: H.Type) throws where H: HashFunction {
        if H.self == Insecure.SHA1.self {
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        } else if H.self == SHA256.self {
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        } else if H.self == SHA384.self {
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        } else if H.self == SHA512.self {
            self = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        } else {
            throw CryptoKitError.incorrectKeySize
        }
    }
}
#endif
