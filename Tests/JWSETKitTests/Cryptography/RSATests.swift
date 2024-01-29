//
//  RSATests.swift
//
//
//  Created by Amir Abbas Mousavian on 10/31/23.
//

import XCTest
@testable import JWSETKit
#if canImport(CommonCrypto)
import CommonCrypto
#endif

final class RSATests: XCTestCase {
    let privateKeyDER = Data(base64Encoded: """
    MIIEogIBAAKCAQBc8heBuESxpRARckQCuVNuiLsH5AX73F1lqNxpFsS+GPWl6rrT\
    Q0j9Ox/ag2ZwyPby3FtJ11gWT/kDYkjTbqYBCzmzUeGjm3MbuCzErQLPjzGvdUDn\
    vCxx8G+uE2uqTdryfEaregUyo69JmucLq3HQ91cHVeLMN/xMvaAu+xEUbZFiDBcV\
    wOOWUft7HmrS+QLngCPlTMyU8Q9ISDtEfE/7rbIRyO49u56Y9SulTm/aOcQn/1Qg\
    pc5NvHfRnHJ4Y7zclERWhtOLiDlVPIR7JjOMg3wVUEK18XPgoKdTxHBLJymLF2dQ\
    SQhfhLruUcndV0R9vOdt3kMB0cSo7NzF4FcbAgMBAAECggEAM9pTxujYWgruRe1r\
    h+GAbEAXp7VMqVAtQtPL80zigfNGyEOF6uq0w6HCiZOZCP701lSdETr0R65iC8M/\
    QcWPEzICBMp/iVjmBObhAvBKiyUl4O8XQLE4UnCCvajT/fTlWzZ97phqYe/zkKq8\
    j0QcgSocAVmm56usM9vui4dB5hT1TSpBj6UOXD4qSRmlHm+Ynp+5R19ktI0ay7fo\
    P6QxZ/18QlS2VmVWu2tmfbbXU1EFjfQbdmIkEJI78rhEYXU/r3MDW3UnXCNDJTqq\
    Q5/uD688BrRyTMZD1kZYCr7mlzx05keDQubSEXbVHG1bS4xAFzvmFB0A+lZn+Inl\
    NqjggQKBgQCsCQtSTGmIqyPdF3siIK4HvfRbcn0WUJGMp/N8/Lu8CFHiT3hOkwN9\
    6rBLLTl1qn8HjpHc226bHCPIbuHhZea3WlW2AIfbOJle/0m+BN8jEE8woZWOcgd/\
    a7UV6mzxIxw8wq+4tWVoTYGadrePGZzOKkqD+W44uVn/vWCB2yhrOwKBgQCKTzCH\
    qVMcrXLUqlQbJGOpfd+UzzsB0SOCZX83aifx+8vsNzXUgjyxIvz7oNZNyXHT7CnN\
    9poldxgg2ajxQ9Nfr+e98eUD/nHjwbixGr+m1KRaiM0q+raLGpFQAcrgiVxFXVEH\
    BVuoTW/uTCVfEdDQg0iCLb1nCJoIrU2bUMpFoQKBgEpZzk7PP30VmfZfw5PIU+58\
    pjMvk+glAgKsQ4ttHyXw4pLQjcpHt2agG3kiHodAHI6Di37MR006KCzj3zOu+rub\
    ixeRuyV/nKl148UADf/1eIQoEZ7yoVLsleLW4iaFahrIeXF21FDzzmOXk1WBWEex\
    92p6TqytTrw8eI0mzp0pAoGAbZqJq8gcS+qLyEnecs/ohqVwa725VhxFFo2WPfTL\
    CPFwTZYG+4vlyr4eWs2/Zk9P/A/3pPdaenwhS88RGXiVZgvBCv5JbVvTJxkaYob+\
    /5cdU317kSazSBLauttgyYUw8OsdTgIJ+5q6K85+AxPcNZEEAd17bc4cOuoTSRTB\
    5mECgYEAiZXJe66KpFZlzomsvoghwjTCdMb0CSzH8DvstGRC7X2QR1s9BhS8pvSS\
    1cPwodOyPbUm6t16iYgZN1ibqxWG+TtiftzNzBjrPWGAIWVW+v0uvYBRgdOKbN/c\
    nFi6gyV13lGIMMK61gCaEgcgBtJ9hbuIEH6B3a3n8TACIzewfx0=
    """)!
    
    let publicKeyDER = Data(base64Encoded: """
    MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBc8heBuESxpRARckQCuVNu\
    iLsH5AX73F1lqNxpFsS+GPWl6rrTQ0j9Ox/ag2ZwyPby3FtJ11gWT/kDYkjTbqYB\
    CzmzUeGjm3MbuCzErQLPjzGvdUDnvCxx8G+uE2uqTdryfEaregUyo69JmucLq3HQ\
    91cHVeLMN/xMvaAu+xEUbZFiDBcVwOOWUft7HmrS+QLngCPlTMyU8Q9ISDtEfE/7\
    rbIRyO49u56Y9SulTm/aOcQn/1Qgpc5NvHfRnHJ4Y7zclERWhtOLiDlVPIR7JjOM\
    g3wVUEK18XPgoKdTxHBLJymLF2dQSQhfhLruUcndV0R9vOdt3kMB0cSo7NzF4Fcb\
    AgMBAAE=
    """)!
    
    let plaintext = Data("The quick brown fox jumps over the lazy dog.".utf8)
    
    func testPKCS8Init() throws {
        XCTAssertNoThrow(try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER))
        XCTAssertNoThrow(try JSONWebRSAPublicKey(derRepresentation: publicKeyDER))
    }
    
#if canImport(CommonCrypto)
    func testSecKeyInit() throws {
        XCTAssertNoThrow(try SecKey(derRepresentation: publicKeyDER, keyType: .rsa))
        XCTAssertNoThrow(try SecKey(derRepresentation: privateKeyDER, keyType: .rsa))
    }
#endif
    
    func testEncrypt_RSA2048_OAEP_SHA1() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let ciphertext = try publicKey.encrypt(plaintext, using: .rsaEncryptionOAEP)
        let decrypted = try privateKey.decrypt(ciphertext, using: .rsaEncryptionOAEP)
        
        XCTAssertEqual(plaintext, decrypted)
        XCTAssertNotEqual(plaintext, ciphertext)
        XCTAssertEqual(ciphertext.count, 2048 / 8)
    }
    
    func testEncrypt_RSA2048_OAEP_SHA256() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let ciphertext = try publicKey.encrypt(plaintext, using: .rsaEncryptionOAEPSHA256)
        let decrypted = try privateKey.decrypt(ciphertext, using: .rsaEncryptionOAEPSHA256)
        
        XCTAssertEqual(plaintext, decrypted)
        XCTAssertNotEqual(plaintext, ciphertext)
        XCTAssertEqual(ciphertext.count, 2048 / 8)
    }
    
#if canImport(CommonCrypto)
    func testEcrypt_RSA2048_OAEP_SHA384() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let ciphertext = try publicKey.encrypt(plaintext, using: .rsaEncryptionOAEPSHA384)
        let decrypted = try privateKey.decrypt(ciphertext, using: .rsaEncryptionOAEPSHA384)
        
        XCTAssertEqual(plaintext, decrypted)
        XCTAssertNotEqual(plaintext, ciphertext)
        XCTAssertEqual(ciphertext.count, 2048 / 8)
    }
    
    func testEncrypt_RSA2048_OAEP_SHA512() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let ciphertext = try publicKey.encrypt(plaintext, using: .rsaEncryptionOAEPSHA512)
        let decrypted = try privateKey.decrypt(ciphertext, using: .rsaEncryptionOAEPSHA512)
        
        XCTAssertEqual(plaintext, decrypted)
        XCTAssertNotEqual(plaintext, ciphertext)
        XCTAssertEqual(ciphertext.count, 2048 / 8)
    }
#endif
    
    func testSigning_RSA2048_PKCS1_SHA256() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePKCS1v15SHA256)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePKCS1v15SHA256))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 2048 / 8)
    }
    
    func testSigning_RSA2048_PKCS1_SHA384() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePKCS1v15SHA384)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePKCS1v15SHA384))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 2048 / 8)
    }
    
    func testSigning_RSA2048_PKCS1_SHA512() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)
        
        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePKCS1v15SHA512)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePKCS1v15SHA512))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 2048 / 8)
    }
    
    func testSigning_RSA2048_PSS_SHA256() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)

        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePSSSHA256)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePSSSHA256))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 2048 / 8)
    }
    
    func testSigning_RSA2048_PSS_SHA384() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)

        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePSSSHA384)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePSSSHA384))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 2048 / 8)
    }
    
    func testSigning_RSA2048_PSS_SHA512() throws {
        let publicKey = try JSONWebRSAPublicKey(derRepresentation: publicKeyDER)
        let privateKey = try JSONWebRSAPrivateKey(derRepresentation: privateKeyDER)

        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePSSSHA512)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePSSSHA512))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 2048 / 8)
    }
    
    func testSigning_RSA3072_PSS_SHA256() throws {
        let privateKey = try JSONWebRSAPrivateKey(keySize: .bits3072)
        let publicKey = privateKey.publicKey
        
        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePSSSHA256)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePSSSHA256))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 3072 / 8)
    }
    
    func testSigning_RSA4096_PSS_SHA256() throws {
        let privateKey = try JSONWebRSAPrivateKey(keySize: .bits4096)
        let publicKey = privateKey.publicKey
        
        let signature = try privateKey.signature(plaintext, using: .rsaSignaturePSSSHA256)
        XCTAssertNoThrow(try publicKey.verifySignature(signature, for: plaintext, using: .rsaSignaturePSSSHA256))
        
        XCTAssertNotEqual(plaintext, signature)
        XCTAssertEqual(signature.count, 4096 / 8)
    }
}
