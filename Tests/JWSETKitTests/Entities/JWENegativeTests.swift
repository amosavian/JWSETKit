//
//  JWENegativeTests.swift
//
//
//  Created by Claude on 12/13/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

/// Tests for invalid JWE inputs and decryption errors
@Suite
struct JWENegativeTests {
    // MARK: - Test Keys
    
    private let rsaKey = try! JSONWebRSAPrivateKey(importing: Data(
        """
        {"kty":"RSA",
         "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
         "e":"AQAB",
         "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
         "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
         "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
         "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
         "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
         "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
        }
        """.utf8
    ), format: .jwk)
    
    private let ecKey = try! JSONWebECPrivateKey(
        importing:
        """
        {"kty":"EC",
         "crv":"P-256",
         "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
         "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
         "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
        """.data, format: .jwk
    )
    
    private let symmetricKey = try! JSONWebKeyAESKW(
        SymmetricKey(data: Data(urlBase64Encoded: "GawgguFyGrWKav7AX4VKUg").unsafelyUnwrapped)
    )
    
    private let plaintext = Data("Hello, World!".utf8)
    
    // MARK: - Invalid Compact Format Tests
    
    @Test
    func invalidCompactOnlyOneSegment() throws {
        let invalidJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func invalidCompactOnlyTwoSegments() throws {
        let invalidJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.encryptedKey"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func invalidCompactOnlyThreeSegments() throws {
        let invalidJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.encryptedKey.iv"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func invalidCompactOnlyFourSegments() throws {
        let invalidJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.encryptedKey.iv.ciphertext"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func invalidCompactExtraSegments() throws {
        let invalidJWE = "header.encKey.iv.ciphertext.tag.extra"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func emptyJWEString() throws {
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: "")
        }
    }
    
    @Test
    func onlyDotsJWE() throws {
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: "....")
        }
    }
    
    // MARK: - Invalid Base64 Tests
    
    @Test
    func invalidBase64InHeader() throws {
        let invalidJWE = "!!!invalid@@@.encKey.iv.ciphertext.tag"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func invalidBase64InEncryptedKey() throws {
        let header = Data("{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}".utf8).urlBase64EncodedString()
        let invalidJWE = "\(header).###invalid###.iv.ciphertext.tag"
        
        // The library may parse this but decryption will fail
        do {
            let jwe = try JSONWebEncryption(from: invalidJWE)
            #expect(throws: Error.self) {
                try jwe.decrypt(using: rsaKey)
            }
        } catch {
            // Parsing failed, which is also acceptable
        }
    }
    
    // MARK: - Invalid JSON Tests
    
    @Test
    func invalidJSONInHeader() throws {
        let invalidHeader = Data("not json".utf8).urlBase64EncodedString()
        let invalidJWE = "\(invalidHeader).encKey.iv.ciphertext.tag"
        #expect(throws: Error.self) {
            try JSONWebEncryption(from: invalidJWE)
        }
    }
    
    @Test
    func headerMissingAlg() throws {
        // Header without "alg"
        let header = Data("{\"enc\":\"A256GCM\"}".utf8).urlBase64EncodedString()
        let iv = Data(repeating: 0, count: 12).urlBase64EncodedString()
        let ciphertext = Data("encrypted".utf8).urlBase64EncodedString()
        let tag = Data(repeating: 0, count: 16).urlBase64EncodedString()
        let encKey = Data(repeating: 0, count: 32).urlBase64EncodedString()
        let jweString = "\(header).\(encKey).\(iv).\(ciphertext).\(tag)"
        
        let jwe = try JSONWebEncryption(from: jweString)
        #expect(throws: Error.self) {
            try jwe.decrypt(using: rsaKey)
        }
    }
    
    @Test
    func headerMissingEnc() throws {
        // Header without "enc"
        let header = Data("{\"alg\":\"RSA-OAEP\"}".utf8).urlBase64EncodedString()
        let iv = Data(repeating: 0, count: 12).urlBase64EncodedString()
        let ciphertext = Data("encrypted".utf8).urlBase64EncodedString()
        let tag = Data(repeating: 0, count: 16).urlBase64EncodedString()
        let encKey = Data(repeating: 0, count: 32).urlBase64EncodedString()
        let jweString = "\(header).\(encKey).\(iv).\(ciphertext).\(tag)"
        
        let jwe = try JSONWebEncryption(from: jweString)
        #expect(throws: Error.self) {
            try jwe.decrypt(using: rsaKey)
        }
    }
    
    // MARK: - Unsupported Algorithm Tests
    
    @Test
    func unsupportedKeyEncryptionAlgorithm() throws {
        let header = Data("{\"alg\":\"FAKE-ALG\",\"enc\":\"A256GCM\"}".utf8).urlBase64EncodedString()
        let iv = Data(repeating: 0, count: 12).urlBase64EncodedString()
        let ciphertext = Data("encrypted".utf8).urlBase64EncodedString()
        let tag = Data(repeating: 0, count: 16).urlBase64EncodedString()
        let encKey = Data(repeating: 0, count: 32).urlBase64EncodedString()
        let jweString = "\(header).\(encKey).\(iv).\(ciphertext).\(tag)"
        
        let jwe = try JSONWebEncryption(from: jweString)
        #expect(throws: Error.self) {
            try jwe.decrypt(using: rsaKey)
        }
    }
    
    @Test
    func unsupportedContentEncryptionAlgorithm() throws {
        let header = Data("{\"alg\":\"RSA-OAEP\",\"enc\":\"FAKE-ENC\"}".utf8).urlBase64EncodedString()
        let iv = Data(repeating: 0, count: 12).urlBase64EncodedString()
        let ciphertext = Data("encrypted".utf8).urlBase64EncodedString()
        let tag = Data(repeating: 0, count: 16).urlBase64EncodedString()
        let encKey = Data(repeating: 0, count: 32).urlBase64EncodedString()
        let jweString = "\(header).\(encKey).\(iv).\(ciphertext).\(tag)"
        
        let jwe = try JSONWebEncryption(from: jweString)
        #expect(throws: Error.self) {
            try jwe.decrypt(using: rsaKey)
        }
    }
    
    // MARK: - Wrong Key Type Tests
    
    @Test
    func ecKeyForRSAAlgorithm() throws {
        // Create JWE with RSA-OAEP
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Try to decrypt with EC key
        #expect(throws: Error.self) {
            try jwe.decrypt(using: ecKey)
        }
    }
    
    @Test
    func rsaKeyForECDHAlgorithm() throws {
        // Create JWE with ECDH-ES
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .ecdhEphemeralStatic,
            keyEncryptionKey: ecKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Try to decrypt with RSA key
        #expect(throws: Error.self) {
            try jwe.decrypt(using: rsaKey)
        }
    }
    
    @Test
    func symmetricKeyForAsymmetricAlgorithm() throws {
        // Create JWE with RSA-OAEP
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Try to decrypt with symmetric key
        #expect(throws: Error.self) {
            try jwe.decrypt(using: symmetricKey)
        }
    }
    
    // MARK: - Decryption with Wrong Key Tests
    
    @Test
    func decryptWithDifferentRSAKey() throws {
        // Create JWE with one RSA key
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Create a different RSA key
        let differentKey = try JSONWebRSAPrivateKey(importing: Data(
            """
            {"kty":"RSA",
             "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
             "e":"AQAB",
             "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
             "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
             "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
             "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
             "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
             "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
            }
            """.utf8
        ), format: .jwk)
        
        // Try to decrypt with different key
        #expect(throws: Error.self) {
            try jwe.decrypt(using: differentKey)
        }
    }
    
    @Test
    func decryptWithDifferentSymmetricKey() throws {
        // Create JWE with one symmetric key
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .aesKeyWrap128,
            keyEncryptionKey: symmetricKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128
        )
        
        // Create a different symmetric key
        let differentKey = try JSONWebKeyAESKW(SymmetricKey(size: .bits128))
        
        // Try to decrypt with different key
        #expect(throws: Error.self) {
            try jwe.decrypt(using: differentKey)
        }
    }
    
    // MARK: - Tampered Ciphertext Tests
    
    @Test
    func tamperedCiphertext() throws {
        // Create valid JWE
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Get compact representation
        let compact = jwe.description
        let parts = compact.split(separator: ".")
        
        // Tamper with ciphertext (4th segment)
        var tamperedCiphertext = Data(urlBase64Encoded: String(parts[3])) ?? Data()
        if !tamperedCiphertext.isEmpty {
            tamperedCiphertext[0] ^= 0xFF // Flip bits
        }
        
        let tamperedJWE = "\(parts[0]).\(parts[1]).\(parts[2]).\(tamperedCiphertext.urlBase64EncodedString()).\(parts[4])"
        
        let parsedJWE = try JSONWebEncryption(from: tamperedJWE)
        #expect(throws: Error.self) {
            try parsedJWE.decrypt(using: rsaKey)
        }
    }
    
    @Test
    func tamperedAuthTag() throws {
        // Create valid JWE
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Get compact representation
        let compact = jwe.description
        let parts = compact.split(separator: ".")
        
        // Tamper with auth tag (5th segment)
        var tamperedTag = Data(urlBase64Encoded: String(parts[4])) ?? Data()
        if !tamperedTag.isEmpty {
            tamperedTag[0] ^= 0xFF // Flip bits
        }
        
        let tamperedJWE = "\(parts[0]).\(parts[1]).\(parts[2]).\(parts[3]).\(tamperedTag.urlBase64EncodedString())"
        
        let parsedJWE = try JSONWebEncryption(from: tamperedJWE)
        #expect(throws: Error.self) {
            try parsedJWE.decrypt(using: rsaKey)
        }
    }
    
    @Test
    func tamperedIV() throws {
        // Create valid JWE
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Get compact representation
        let compact = jwe.description
        let parts = compact.split(separator: ".")
        
        // Tamper with IV (3rd segment)
        var tamperedIV = Data(urlBase64Encoded: String(parts[2])) ?? Data()
        if !tamperedIV.isEmpty {
            tamperedIV[0] ^= 0xFF // Flip bits
        }
        
        let tamperedJWE = "\(parts[0]).\(parts[1]).\(tamperedIV.urlBase64EncodedString()).\(parts[3]).\(parts[4])"
        
        let parsedJWE = try JSONWebEncryption(from: tamperedJWE)
        #expect(throws: Error.self) {
            try parsedJWE.decrypt(using: rsaKey)
        }
    }
    
    @Test
    func tamperedEncryptedKey() throws {
        // Create valid JWE
        let jwe = try JSONWebEncryption(
            content: plaintext,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: rsaKey.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        // Get compact representation
        let compact = jwe.description
        let parts = compact.split(separator: ".")
        
        // Tamper with encrypted key (2nd segment)
        var tamperedEncKey = Data(urlBase64Encoded: String(parts[1])) ?? Data()
        if !tamperedEncKey.isEmpty {
            tamperedEncKey[0] ^= 0xFF // Flip bits
        }
        
        let tamperedJWE = "\(parts[0]).\(tamperedEncKey.urlBase64EncodedString()).\(parts[2]).\(parts[3]).\(parts[4])"
        
        let parsedJWE = try JSONWebEncryption(from: tamperedJWE)
        #expect(throws: Error.self) {
            try parsedJWE.decrypt(using: rsaKey)
        }
    }
    
    // MARK: - Wrong Size Tests
    
    @Test
    func wrongIVSize() throws {
        let header = Data("{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}".utf8).urlBase64EncodedString()
        // GCM expects 12-byte IV, provide wrong size
        let wrongIV = Data(repeating: 0, count: 8).urlBase64EncodedString()
        let ciphertext = Data("encrypted".utf8).urlBase64EncodedString()
        let tag = Data(repeating: 0, count: 16).urlBase64EncodedString()
        let encKey = Data(repeating: 0, count: 24).urlBase64EncodedString() // Wrapped key
        
        let jweString = "\(header).\(encKey).\(wrongIV).\(ciphertext).\(tag)"
        
        let jwe = try JSONWebEncryption(from: jweString)
        #expect(throws: Error.self) {
            try jwe.decrypt(using: symmetricKey)
        }
    }
    
    @Test
    func wrongTagSize() throws {
        let header = Data("{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}".utf8).urlBase64EncodedString()
        let iv = Data(repeating: 0, count: 12).urlBase64EncodedString()
        let ciphertext = Data("encrypted".utf8).urlBase64EncodedString()
        // GCM expects 16-byte tag, provide wrong size
        let wrongTag = Data(repeating: 0, count: 8).urlBase64EncodedString()
        let encKey = Data(repeating: 0, count: 24).urlBase64EncodedString()
        
        let jweString = "\(header).\(encKey).\(iv).\(ciphertext).\(wrongTag)"
        
        let jwe = try JSONWebEncryption(from: jweString)
        #expect(throws: Error.self) {
            try jwe.decrypt(using: symmetricKey)
        }
    }
    
    // MARK: - Edge Cases
    
    @Test
    func emptyPlaintext() throws {
        // Empty plaintext should work with symmetric encryption
        let emptyData = Data()
        let jwe = try JSONWebEncryption(
            content: emptyData,
            keyEncryptingAlgorithm: .aesKeyWrap128,
            keyEncryptionKey: symmetricKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128
        )
        
        let decrypted = try jwe.decrypt(using: symmetricKey)
        #expect(decrypted == emptyData)
    }
    
    @Test
    func veryLargePlaintext() throws {
        // 1MB of data with symmetric encryption
        let largeData = Data(repeating: 0x42, count: 1024 * 1024)
        let jwe = try JSONWebEncryption(
            content: largeData,
            keyEncryptingAlgorithm: .aesKeyWrap128,
            keyEncryptionKey: symmetricKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128
        )
        
        let decrypted = try jwe.decrypt(using: symmetricKey)
        #expect(decrypted == largeData)
    }
}
