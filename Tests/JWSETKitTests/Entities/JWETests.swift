//
//  JWETests.swift
//
//
//  Created by Amir Abbas Mousavian on 10/20/23.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

extension Crypto.SymmetricKey: @unchecked Swift.Sendable {}

@Suite
struct JWETests {
    @Test
    func testDecode() throws {
        let jwe = try JSONWebEncryption(from: RSA_OAEP_GCM.jweString)
        
        var header = JOSEHeader()
        header.algorithm = .rsaEncryptionOAEP
        header.encryptionAlgorithm = .aesEncryptionGCM256
        #expect(header == jwe.header.protected.value)
        #expect(jwe.encryptedKey == Data(urlBase64Encoded: """
        OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe\
        ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb\
        Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV\
        mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8\
        1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi\
        6UklfCpIMfIjf7iGdXKHzg
        """))
        #expect(jwe.sealed.nonce == Data(urlBase64Encoded: "48V1_ALb6US04U3b"))
        #expect(jwe.sealed.ciphertext == Data(urlBase64Encoded: """
        5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
        SdiwkIr3ajwQzaBtQD_A
        """))
        #expect(jwe.sealed.tag == Data(urlBase64Encoded: "XFBoMYUZodetZdvTiFvSkQ"))
    }
    
    @Test
    func testDecrypt_RSA_OAEP_AES_GCM() throws {
        let jwe = try JSONWebEncryption(from: RSA_OAEP_GCM.jweString)
        
        guard let algorithm = JSONWebKeyEncryptionAlgorithm(jwe.header.protected.algorithm) else {
            Issue.record("Invalid algorithm")
            return
        }
        let decryptedCEK = try RSA_OAEP_GCM.kek.decrypt(jwe.encryptedKey!, using: algorithm)
        #expect(decryptedCEK == RSA_OAEP_GCM.cek.data)
        
        let data = try jwe.decrypt(using: RSA_OAEP_GCM.kek)
        #expect(RSA_OAEP_GCM.plainData == data)
    }
    
    func testDecrypt_RSA_PKCS1_5_CBC() throws {
        let jwe = try JSONWebEncryption(from: RSA_PKCS1_5_CBC.jweString)
        
        guard let algorithm = JSONWebKeyEncryptionAlgorithm(jwe.header.protected.algorithm) else {
            Issue.record("Invalid algorithm")
            return
        }
        let decryptedCEK = try RSA_PKCS1_5_CBC.kek.decrypt(jwe.encryptedKey!, using: algorithm)
        #expect(decryptedCEK == RSA_PKCS1_5_CBC.cek.data)
        
        let data = try jwe.decrypt(using: RSA_PKCS1_5_CBC.kek)
        #expect(RSA_PKCS1_5_CBC.plainData == data)
    }
    
    @Test
    func testDecrypt_AESKW_CBC() throws {
        let jwe = try JSONWebEncryption(from: AESKW_CBC.jweString)
        
        guard let algorithm = JSONWebKeyEncryptionAlgorithm(jwe.header.protected.algorithm) else {
            Issue.record("Invalid algorithm")
            return
        }
        let decryptedCEK = try AESKW_CBC.kek.decrypt(jwe.encryptedKey!, using: algorithm)
        #expect(decryptedCEK == AESKW_CBC.cek.data)
        
        let data = try jwe.decrypt(using: AESKW_CBC.kek)
        #expect(AESKW_CBC.plainData == data)
    }
    
    @Test
    func testEncrypt_Direct() throws {
        let jwe = try JSONWebEncryption(
            content: Direct.plainData,
            keyEncryptingAlgorithm: .direct,
            keyEncryptionKey: nil,
            contentEncryptionAlgorithm: .aesEncryptionGCM128,
            contentEncryptionKey: Direct.kek.publicKey
        )
        
        let data = try jwe.decrypt(using: Direct.kek)
        #expect(Direct.plainData == data)
    }
    
    @Test
    func testEncrypt_RSA_OAEP_AES_GCM() throws {
        let jwe = try JSONWebEncryption(
            content: RSA_OAEP_GCM.plainData,
            keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
            keyEncryptionKey: RSA_OAEP_GCM.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128
        )
        
        let data = try jwe.decrypt(using: RSA_OAEP_GCM.kek)
        #expect(RSA_OAEP_GCM.plainData == data)
    }

    @Test
    func testEncryptWithCEK_RSA_OAEP_AES_GCM() throws {
        let jwe = try JSONWebEncryption(
            content: RSA_OAEP_GCM.plainData,
            keyEncryptingAlgorithm: .rsaEncryptionOAEP,
            keyEncryptionKey: RSA_OAEP_GCM.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128,
            contentEncryptionKey: RSA_OAEP_GCM.cek
        )
        
        let data = try jwe.decrypt(using: RSA_OAEP_GCM.kek)
        #expect(RSA_OAEP_GCM.plainData == data)
    }
    
    @Test
    func testEncryptWithCEK_RSA_OAEP_SHA256_AES_GCM() throws {
        let jwe = try JSONWebEncryption(
            content: RSA_OAEP_GCM.plainData,
            keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
            keyEncryptionKey: RSA_OAEP_GCM.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128,
            contentEncryptionKey: RSA_OAEP_GCM.cek
        )
        
        let data = try jwe.decrypt(using: RSA_OAEP_GCM.kek)
        #expect(RSA_OAEP_GCM.plainData == data)
    }
    
    @Test
    func testEncrypt_RSA_PKCS1_5_CBC() throws {
        let jwe = try JSONWebEncryption(
            content: RSA_PKCS1_5_CBC.plainData,
            keyEncryptingAlgorithm: .unsafeRSAEncryptionPKCS1,
            keyEncryptionKey: RSA_PKCS1_5_CBC.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionCBC256SHA512
        )
        
        let data = try jwe.decrypt(using: RSA_PKCS1_5_CBC.kek)
        #expect(RSA_PKCS1_5_CBC.plainData == data)
    }

    @Test
    func testEncryptWithCEK_RSA_PKCS1_5_CBC() throws {
        let jwe = try JSONWebEncryption(
            content: RSA_PKCS1_5_CBC.plainData,
            keyEncryptingAlgorithm: .unsafeRSAEncryptionPKCS1,
            keyEncryptionKey: RSA_PKCS1_5_CBC.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionCBC256SHA512,
            contentEncryptionKey: RSA_PKCS1_5_CBC.cek
        )
        
        let data = try jwe.decrypt(using: RSA_PKCS1_5_CBC.kek)
        #expect(RSA_PKCS1_5_CBC.plainData == data)
    }
    
    @Test
    func testEncrypt_AESKW_CBC() throws {
        let jwe = try JSONWebEncryption(
            content: AESKW_CBC.plainData,
            keyEncryptingAlgorithm: .aesKeyWrap256,
            keyEncryptionKey: AESKW_CBC.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionCBC256SHA512
        )
        
        let data = try jwe.decrypt(using: AESKW_CBC.kek)
        #expect(AESKW_CBC.plainData == data)
    }

    @Test
    func testEncrypt_AESGCMKW_CBC() throws {
        let jwe = try JSONWebEncryption(
            content: AESGCMKW_CBC.plainData,
            keyEncryptingAlgorithm: .aesGCM128KeyWrap,
            keyEncryptionKey: AESGCMKW_CBC.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionCBC256SHA512,
            contentEncryptionKey: AESGCMKW_CBC.cek
        )
        
        let data = try jwe.decrypt(using: AESGCMKW_CBC.kek)
        #expect(AESGCMKW_CBC.plainData == data)
    }
    
    @Test
    func testEncrypt_PBES2_GCM() throws {
        let jwe = try JSONWebEncryption(
            content: PBES2_GCM.plainData,
            keyEncryptingAlgorithm: .pbes2hmac256,
            keyEncryptionKey: PBES2_GCM.kek.publicKey,
            contentEncryptionAlgorithm: .aesEncryptionGCM128,
            contentEncryptionKey: PBES2_GCM.cek
        )
        
        let data = try jwe.decrypt(using: PBES2_GCM.kek)
        #expect(PBES2_GCM.plainData == data)
    }
    
    @Test
    func testEncrypt_ECDH_ES_CBC() throws {
        let jwe = try JSONWebEncryption(
            content: ECDH_ES.plainData,
            keyEncryptingAlgorithm: .ecdhEphemeralStatic,
            keyEncryptionKey: ECDH_ES.kek,
            contentEncryptionAlgorithm: .aesEncryptionCBC256SHA512
        )
        
        let data = try jwe.decrypt(using: ECDH_ES.kek)
        #expect(ECDH_ES.plainData == data)
    }
    
    @Test
    func testEncrypt_ECDH_ES_GCM() throws {
        let jwe = try JSONWebEncryption(
            content: ECDH_ES.plainData,
            keyEncryptingAlgorithm: .ecdhEphemeralStatic,
            keyEncryptionKey: ECDH_ES.kek,
            contentEncryptionAlgorithm: .aesEncryptionGCM256
        )
        
        let data = try jwe.decrypt(using: ECDH_ES.kek)
        #expect(ECDH_ES.plainData == data)
    }
    
    @Test
    func testEncrypt_ECDH_ES_KW_CBC() throws {
        let jwe = try JSONWebEncryption(
            content: ECDH_ES_KW.plainData,
            keyEncryptingAlgorithm: .ecdhEphemeralStaticAESKeyWrap128,
            keyEncryptionKey: ECDH_ES_KW.kek,
            contentEncryptionAlgorithm: .aesEncryptionCBC256SHA512,
            contentEncryptionKey: ECDH_ES_KW.cek
        )
        
        let data = try jwe.decrypt(using: ECDH_ES_KW.kek)
        #expect(ECDH_ES_KW.plainData == data)
    }
}

private let key128 = SymmetricKey(data: Data(urlBase64Encoded: "GawgguFyGrWKav7AX4VKUg").unsafelyUnwrapped)
private let key256 = SymmetricKey(data: [
    177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
    212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
    234, 64, 252,
])

private let shortRandomBytes = Data([
    76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
    112, 114, 111, 115, 112, 101, 114, 46,
])

enum Direct {
    static let jweString = """
    """
    
    static let kek = try! JSONWebKeyAESGCM(key128)
    
    static let plainData = shortRandomBytes
}

enum RSA_OAEP_GCM {
    static let jweString = """
    eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.\
    OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe\
    ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb\
    Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV\
    mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8\
    1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi\
    6UklfCpIMfIjf7iGdXKHzg.\
    48V1_ALb6US04U3b.\
    5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
    SdiwkIr3ajwQzaBtQD_A.\
    XFBoMYUZodetZdvTiFvSkQ
    """
    
    static let kek = try! JSONWebRSAPrivateKey(importing: Data(
        """
        {"kty":"RSA",
         "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
         "e":"AQAB",
         "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
         "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
         "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
         "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
         "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
         "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
        }
        """.utf8
    ), format: .jwk)
    
    static let cek = key256
    
    static let plainData = Data([
        84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
        111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
        101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
        101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
        110, 97, 116, 105, 111, 110, 46,
    ])
}

enum RSA_PKCS1_5_CBC {
    static let jweString = """
    eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
    UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm\
    1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc\
    HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF\
    NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8\
    rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv\
    -B3oWh2TbqmScqXMR4gp_A.\
    AxY8DCtDaGlsbGljb3RoZQ.\
    KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
    9hH0vgRfYgPnAHOd8stkvw
    """
    
    static let kek = try! JSONWebRSAPrivateKey(importing: Data(
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
    
    static let cek = SymmetricKey(data: [
        4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
        44, 207,
    ])
    
    static let plainData = shortRandomBytes
}

enum AESKW_CBC {
    static let jweString = """
    eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
    6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.\
    AxY8DCtDaGlsbGljb3RoZQ.\
    KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
    U0m_YmjN04DJvceFICbCVQ
    """
    
    static let kek = try! JSONWebKeyAESKW(key128)
    
    static let cek = SymmetricKey(data: [
        4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
        44, 207,
    ])
    
    static let plainData = shortRandomBytes
}

enum AESGCMKW_CBC {
    static let jweString = """
    """
    
    static let kek = try! JSONWebKeyAESGCM(key128)
    
    static let cek = key256
    
    static let plainData = shortRandomBytes
}

enum PBES2_GCM {
    static let jweString = """
    """
    
    static let kek = SymmetricKey(data: Data("entrap_oar".utf8))
    
    static let cek = key256
    
    static let plainData = shortRandomBytes
}

enum ECDH_ES {
    static let jweString = """
    """
    
    static let kek = try! JSONWebECPrivateKey(
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
    
    static let plainData = shortRandomBytes
}

enum ECDH_ES_KW {
    static let jweString = """
    """
    
    static let kek = try! JSONWebECPrivateKey(
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
    
    static let cek = key256
    
    static let plainData = shortRandomBytes
}
