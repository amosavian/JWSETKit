//
//  CommonCrypto.swift
//
//
//  Created by Amir Abbas Mousavian on 11/1/23.
//

import Foundation
import Crypto
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
    
    func ccWrapKey(_ key: SymmetricKey) throws -> Data {
        let kek = data
        let rawKeyLength = key.data.count
        var wrappedKeyLength = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKeyLength)
        var wrappedKey = Data(count: wrappedKeyLength)
        
        let status = key.data.withUnsafeBytes { rawKeyBytes in
            kek.withUnsafeBytes { kekBytes in
                wrappedKey.withUnsafeMutableBytes { wrappedKeyBytes in
                    CCSymmetricKeyWrap(
                        CCWrappingAlgorithm(kCCWRAPAES),
                        CCrfc3394_iv,
                        CCrfc3394_ivLen,
                        kekBytes.baseAddress,
                        kek.count,
                        rawKeyBytes.baseAddress,
                        rawKeyLength,
                        wrappedKeyBytes.baseAddress,
                        &wrappedKeyLength
                    )
                }
            }
        }
        if let error = status.cryptoKitError {
            throw error
        } else {
            return wrappedKey.prefix(wrappedKeyLength)
        }
    }
    
    func ccUnwrapKey<D>(_ wrappedKey: D) throws -> SymmetricKey where D: DataProtocol {
        let kek = data
        var unwrappedKeyLength = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count)
        var rawKey = Data(count: unwrappedKeyLength)
        let status = kek.withUnsafeBytes { kekBytes in
            wrappedKey.withUnsafeBuffer { wrappedKeyBytes in
                rawKey.withUnsafeMutableBytes { rawKeyBytes in
                    CCSymmetricKeyUnwrap(
                        CCWrappingAlgorithm(kCCWRAPAES),
                        CCrfc3394_iv,
                        CCrfc3394_ivLen,
                        kekBytes.baseAddress,
                        kekBytes.count,
                        wrappedKeyBytes.baseAddress,
                        wrappedKeyBytes.count,
                        rawKeyBytes.baseAddress,
                        &unwrappedKeyLength
                    )
                }
            }
        }
        if let error = status.cryptoKitError {
            throw error
        } else {
            return .init(data: rawKey.prefix(unwrappedKeyLength))
        }
    }
    
    static func ccPbkdf2<PD, SD, H>(
        pbkdf2Password password: PD, salt: SD, iterations: Int, length: Int? = nil, hashFunction: H.Type
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
        let hash = try CCPseudoRandomAlgorithm(hashFunction)
        var derivedKeyData = Data(repeating: 0, count: length ?? hashFunction.Digest.byteCount)
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

extension Int32 {
    fileprivate var cryptoKitError: CryptoKitError? {
        switch Int(self) {
        case kCCSuccess:
            return nil
        case kCCParamError:
            return CryptoKitError.incorrectParameterSize
        case kCCBufferTooSmall:
            return CryptoKitError.incorrectKeySize
        default:
            return CryptoKitError.underlyingCoreCryptoError(error: self)
        }
    }
}
#endif
