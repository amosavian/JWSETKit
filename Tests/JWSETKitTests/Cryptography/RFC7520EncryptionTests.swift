//
//  RFC7520EncryptionTests.swift
//
//
//  Created by Amir Abbas Mousavian on 5/3/24.
//

import XCTest
@testable import JWSETKit
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class RFC7520EncryptionTests: XCTestCase {
    let plainText = """
    You can trust us to stick with you through thick and \
    thin\u{2013}to the bitter end. And you can trust us to \
    keep any secret of yours\u{2013}closer than you keep it \
    yourself. But you cannot trust us to let you face trouble \
    alone, and go off without a word. We are your friends, Frodo.
    """
    
    func testEncrypt_RSA_v1_5() throws {
        let header = "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "bbd5sTkYwhAIqfHsx8DayA".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.rsa1_5EncPublicKey.key,
            contentEncryptionKey: SymmetricKey(data: "3qyTVhIWt5juqZUCpfRqpvauwB956MEJL2Rt-8qXKSo".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.sealed.nonce, "bbd5sTkYwhAIqfHsx8DayA".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r\
        aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O\
        WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV\
        yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0\
        zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2\
        O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW\
        i7lzA6BP430m
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "kvKuFBXHe5mQr4lqgobAUg".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.rsa1_5EncPrivateKey.key), plainText.data)
    }
    
    func testEncrypt_RSA_OAEP() throws {
        let header = "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0".decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "-nBoKLH0YkLZPSI9".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.rsaOAEPEncPublicKey.key,
            contentEncryptionKey: SymmetricKey(data: "mYMfsggkTAm0TbvtlFh2hyoXnbEzJQjMxmgLN3d8xXA".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.sealed.nonce, "-nBoKLH0YkLZPSI9".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR\
        L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw\
        P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8\
        iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML\
        7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV\
        maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "UCGiqJxhBI3IFVdPalHHvA".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.rsaOAEPEncPrivateKey.key), plainText.data)
    }
    
    func testEncrypt_PBES2() throws {
        let plainText = """
        {"keys":[{\
        "kty":"oct",\
        "kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a",\
        "use":"enc",\
        "alg":"A128GCM",\
        "k":"XctOhJAkA-pD9Lh7ZgW_2A"\
        },{\
        "kty":"oct",\
        "kid":"81b20965-8332-43d9-a468-82160ad91ac8",\
        "use":"enc",\
        "alg":"A128KW",\
        "k":"GZy6sIZ6wl9NJOKB-jnmVQ"\
        },{\
        "kty":"oct",\
        "kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",\
        "use":"enc",\
        "alg":"A256GCMKW",\
        "k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"\
        }]}
        """
        
        let pbkdf2Key = SymmetricKey(data: "entrap_o\u{2013}peter_long\u{2013}credit_tun".data)
        
        let header = """
        eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3\
        hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl\
        bmMiOiJBMTI4Q0JDLUhTMjU2In0
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "VBiCzVHNoLiR3F4V82uoTQ".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: pbkdf2Key,
            contentEncryptionKey: SymmetricKey(data: "uwsjJXaBK407Qaf0_zpcpmr1Cs0CC50hIUEyGNEt3m0".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "VBiCzVHNoLiR3F4V82uoTQ".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR\
        sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l\
        TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb\
        6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL\
        _SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd\
        PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok\
        AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-\
        zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V\
        3kobXZ77ulMwDs4p
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "0HlwodAhOCILG5SQ2LQ9dg".decoded)
        XCTAssertEqual(try jwe.decrypt(using: pbkdf2Key), plainText.data)
    }
    
    func testEncrypt_ECDH_ES_AESKW() throws {
        let header = """
        eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH\
        Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt\
        Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH\
        hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy\
        ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT\
        h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "mH-G2zVqgztUtnW_".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.ecdhPrivateKey.key,
            contentEncryptionKey: SymmetricKey(data: "Nou2ueKlP70ZXDbq9UrRwg".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "mH-G2zVqgztUtnW_".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP\
        WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0\
        IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc\
        Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0\
        3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu\
        07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "WuGzxmcreYjpHGJoa17EBg".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.ecdhPrivateKey.key), plainText.data)
    }
    
    func testEncrypt_ECDH_ES_AESCBC() throws {
        let kek = """
        {
          "kty": "EC",
          "kid": "meriadoc.brandybuck@buckland.example",
          "use": "enc",
          "crv": "P-256",
          "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
          "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
          "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
        }
        """
        let header = """
        eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW\
        NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi\
        LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF\
        lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0\
        RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "yc9N8v5sYyv3iGQT926IUg".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: kek.key,
            contentEncryptionKey: SymmetricKey(data: "hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, nil)
        XCTAssertEqual(jwe.sealed.nonce, "yc9N8v5sYyv3iGQT926IUg".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9\
        IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e\
        vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-\
        IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI\
        -sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7\
        MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61\
        95_JGG2m9Csg
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "WCCkNa-x4BeB9hIDIfFuhg".decoded)
        XCTAssertEqual(try jwe.decrypt(using: kek.key), plainText.data)
    }
    
    func testEncrypt_Direct_AESGCM() throws {
        let key = try JSONWebKeyAESGCM(
            importing: "XctOhJAkA-pD9Lh7ZgW_2A".decoded,
            format: .raw
        )
        let header = """
        eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT\
        diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "refa467QzzKx6QAB".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: nil,
            contentEncryptionKey: key
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, nil)
        XCTAssertEqual(jwe.sealed.nonce, "refa467QzzKx6QAB".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y\
        hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM\
        DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_\
        BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5\
        g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn\
        ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "vbb32Xvllea2OtmHAdccRQ".decoded)
        XCTAssertEqual(try jwe.decrypt(using: key), plainText.data)
    }
    
    func testEncrypt_AESGCMKW() throws {
        let header = """
        eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYj\
        IwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3\
        IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1Ni\
        J9
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "gz6NjyEFNm_vm8Gj6FwoFQ".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.keyWrapGCMSymmetricKey.key,
            contentEncryptionKey: SymmetricKey(data: "UWxARpat23nL9ReIj4WG3D1ee9I4r-Mv5QLuFXdy_rE".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "gz6NjyEFNm_vm8Gj6FwoFQ".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaE\
        eVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCz\
        LjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFq\
        hpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hde\
        b6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0Jtj\
        xAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR\
        1B-gxpNk3xWU
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "DKW7jrb4WaRSNfbXVPlT5g".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapGCMSymmetricKey.key), plainText.data)
    }
    
    func testEncrypt_AESKW() throws {
        let header = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC\
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "Qx0pmsDa8KnJc9Jo".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.keyWrapSymmetricKey.key,
            contentEncryptionKey: SymmetricKey(data: "aY5_Ghmk9KxWPBLu_glx1w".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "Qx0pmsDa8KnJc9Jo".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6\
        1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe\
        F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE\
        wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p\
        uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa\
        a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "ER7MWJZ1FBI_NKvn7Zb1Lw".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key), plainText.data)
    }
    
    func testEncrypt_AESKW_Deflate() throws {
        let header = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC\
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "p9pUq6XHY0jfEZIl".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.keyWrapSymmetricKey.key,
            contentEncryptionKey: SymmetricKey(data: "hC-MpLZSuwWv8sexS6ydfw".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "p9pUq6XHY0jfEZIl".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyez\
        SPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0\
        m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBK\
        hpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "VILuUwuIxaLVmh5X-T7kmA".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key), plainText.data)
    }
    
    func testEncrypt_AES_KW_AAD() throws {
        let aad = """
        WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fS\
        widGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0Iixb\
        IkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LC\
        J0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d
        """
        
        let header = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC\
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0
        """.decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: nil,
            nounce: "veCx9ece2orS7c_N".decoded,
            content: plainText.data,
            additionalAuthenticatedData: aad.decoded,
            keyEncryptionKey: RFC7520ExampleKeys.keyWrapSymmetricKey.key,
            contentEncryptionKey: SymmetricKey(data: "75m1ALsYv10pZTKPWrsqdg".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "veCx9ece2orS7c_N".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0Ui8p74SchQP8xygM1\
        oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14T_4NFqF-p2Mx8zkbKxI7oPK\
        8KNarFbyxIDvICNqBLba-v3uzXBdB89fzOI-Lv4PjOFAQGHrgv1rjXAmKbgkft\
        9cB4WeyZw8MldbBhc-V_KWZslrsLNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4a\
        q3FXBxOxCys35PhCdaggy2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHr\
        RDQeHyMRoBljoV3X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "vOaH_Rajnpy_3hOtqvZHRA".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key), plainText.data)
    }
    
    func testEncrypt_AES_KW_PartialUnprotectedHeader() throws {
        let header = "eyJlbmMiOiJBMTI4R0NNIn0".decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: .init { container in
                container.algorithm = .aesKeyWrap128
                container.keyId = "81b20965-8332-43d9-a468-82160ad91ac8"
            },
            nounce: "WgEJsDS9bkoXQ3nR".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.keyWrapSymmetricKey.key,
            contentEncryptionKey: SymmetricKey(data: "WDgEptBmQs9ouUvArz6x6g".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "WgEJsDS9bkoXQ3nR".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFL\
        YMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8\
        fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyF\
        XPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nO\
        WL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWL\
        Hs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "fNYLqpUe84KD45lvDiaBAQ".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key), plainText.data)
    }
    
    func testEncrypt_AES_KW_UnprotectedHeader() throws {
        let header = "".decoded
        let jwe = try JSONWebEncryption(
            protected: .init(encoded: header),
            unprotected: .init { container in
                container.algorithm = .aesKeyWrap128
                container.encryptionAlgorithm = .aesEncryptionGCM128
                container.keyId = "81b20965-8332-43d9-a468-82160ad91ac8"
            },
            nounce: "YihBoVOGsR1l7jCD".decoded,
            content: plainText.data,
            additionalAuthenticatedData: nil,
            keyEncryptionKey: RFC7520ExampleKeys.keyWrapSymmetricKey.key,
            contentEncryptionKey: SymmetricKey(data: "KBooAFl30QPV3vkcZlXnzQ".decoded)
        )
        
        XCTAssertEqual(jwe.header.protected.encoded, header)
        XCTAssertEqual(jwe.encryptedKey, "244YHfO_W7RMpQW81UjQrZcq5LSyqiPv".decoded)
        XCTAssertEqual(jwe.sealed.nonce, "YihBoVOGsR1l7jCD".decoded)
        XCTAssertEqual(jwe.sealed.ciphertext, """
        qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS\
        6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3\
        svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNI\
        QURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISO\
        a6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z\
        4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF
        """.decoded)
        XCTAssertEqual(jwe.sealed.tag, "e2m0Vm7JvjK2VpCKXS-kyg".decoded)
        XCTAssertEqual(try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key), plainText.data)
    }
}
