//
//  RFC7520DecryptionTests.swift
//
//
//  Created by Amir Abbas Mousavian on 1/5/24.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite
struct RFC7520DecryptionTests {
    let plainText = """
    You can trust us to stick with you through thick and \
    thin\u{2013}to the bitter end. And you can trust us to \
    keep any secret of yours\u{2013}closer than you keep it \
    yourself. But you cannot trust us to let you face trouble \
    alone, and go off without a word. We are your friends, Frodo.
    """
    
    @Test
    func testDecryptCompact_RSA_v1_5() throws {
        let jweString = """
        eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm\
        V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\
        .\
        laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF\
        vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G\
        Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG\
        TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl\
        zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh\
        MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw\
        .\
        bbd5sTkYwhAIqfHsx8DayA\
        .\
        0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r\
        aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O\
        WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV\
        yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0\
        zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2\
        O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW\
        i7lzA6BP430m\
        .\
        kvKuFBXHe5mQr4lqgobAUg
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.rsa1_5EncPrivateKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptFlatJSON_RSA_v1_5() throws {
        let jweString = """
        {
          "protected": "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW\
        5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In\
        0",
          "encrypted_key": "laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJ\
        Buuzxg0V7yk1WClnQePFvG2K-pvSlWc9BRIazDrn50RcRai__3TDON39\
        5H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WXC2F5Xbb71ClQ\
        1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt36r1Kt3OSj7EyBQX\
        oZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8VlzNmoxaGMny3YnGir5W\
        f6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOhMBs9M8XL223F\
        g47xlGsMXdfuY-4jaqVw",
          "iv": "bbd5sTkYwhAIqfHsx8DayA",
          "ciphertext": "0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62\
        JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wn\
        I3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc\
        2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtm\
        RdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0y\
        KVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2O6_7uInMGhFeX4c\
        tHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP4\
        30m",
          "tag": "kvKuFBXHe5mQr4lqgobAUg"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.rsa1_5EncPrivateKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompleteJSON_RSA_v1_5() throws {
        let jweString = """
        {
          "recipients": [
            {
              "encrypted_key": "laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzf\
        TihJBuuzxg0V7yk1WClnQePFvG2K-pvSlWc9BRIazDrn50RcRai_\
        _3TDON395H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WX\
        C2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt\
        36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8\
        VlzNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx\
        1BpyIfgvfjOhMBs9M8XL223Fg47xlGsMXdfuY-4jaqVw"
            }
          ],
          "protected": "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW\
        5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In\
        0",
          "iv": "bbd5sTkYwhAIqfHsx8DayA",
          "ciphertext": "0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62\
        JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wn\
        I3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc\
        2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtm\
        RdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0y\
        KVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2O6_7uInMGhFeX4c\
        tHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP4\
        30m",
          "tag": "kvKuFBXHe5mQr4lqgobAUg"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.rsa1_5EncPrivateKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_RSA_OAEP() throws {
        let jweString = """
        eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG\
        9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0\
        .\
        rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi\
        beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu\
        cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58\
        -Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx\
        KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK\
        IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7\
        pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ\
        fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3\
        8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU\
        06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5\
        Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR\
        s\
        .\
        -nBoKLH0YkLZPSI9\
        .\
        o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR\
        L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw\
        P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8\
        iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML\
        7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV\
        maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw\
        .\
        UCGiqJxhBI3IFVdPalHHvA
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.rsaOAEPEncPrivateKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_PBES2() throws {
        let jweString = """
        eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3\
        hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl\
        bmMiOiJBMTI4Q0JDLUhTMjU2In0\
        .\
        d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g\
        .\
        VBiCzVHNoLiR3F4V82uoTQ\
        .\
        23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR\
        sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l\
        TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb\
        6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL\
        _SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd\
        PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok\
        AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-\
        zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V\
        3kobXZ77ulMwDs4p\
        .\
        0HlwodAhOCILG5SQ2LQ9dg
        """
        
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
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: pbkdf2Key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_ECDH_ES_AESKW() throws {
        let jweString = """
        eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH\
        Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt\
        Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH\
        hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy\
        ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT\
        h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0\
        .\
        0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2\
        .\
        mH-G2zVqgztUtnW_\
        .\
        tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP\
        WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0\
        IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc\
        Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0\
        3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu\
        07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ\
        .\
        WuGzxmcreYjpHGJoa17EBg
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.ecdhPrivateKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_ECDH_ES_AESCBC() throws {
        let jweString = """
        eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW\
        NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi\
        LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF\
        lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0\
        RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ\
        .\
        .\
        yc9N8v5sYyv3iGQT926IUg\
        .\
        BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9\
        IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e\
        vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-\
        IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI\
        -sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7\
        MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61\
        95_JGG2m9Csg\
        .\
        WCCkNa-x4BeB9hIDIfFuhg
        """
        
        let ecdhP256PrivateKey = """
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
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: ecdhP256PrivateKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_Direct_AESGCM() throws {
        let jweString = """
        eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT\
        diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0\
        .\
        .\
        refa467QzzKx6QAB\
        .\
        JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y\
        hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM\
        DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_\
        BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5\
        g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn\
        ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp\
        .\
        vbb32Xvllea2OtmHAdccRQ
        """
        
        let aesGCM128SymmetricKey = """
        {
          "kty": "oct",
          "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
          "use": "enc",
          "alg": "A128GCM",
          "k": "XctOhJAkA-pD9Lh7ZgW_2A"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: aesGCM128SymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_AESGCMKW() throws {
        let jweString = """
        eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYj\
        IwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3\
        IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1Ni\
        J9\
        .\
        lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok\
        .\
        gz6NjyEFNm_vm8Gj6FwoFQ\
        .\
        Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaE\
        eVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCz\
        LjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFq\
        hpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hde\
        b6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0Jtj\
        xAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR\
        1B-gxpNk3xWU\
        .\
        DKW7jrb4WaRSNfbXVPlT5g
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapGCMSymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptCompact_AESKW() throws {
        let jweString = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC\
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0\
        .\
        CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx\
        .\
        Qx0pmsDa8KnJc9Jo\
        .\
        AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6\
        1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe\
        F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE\
        wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p\
        uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa\
        a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF\
        .\
        ER7MWJZ1FBI_NKvn7Zb1Lw
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test // (.disabled(if: JSONWebCompressionAlgorithm.registeredAlgorithms.isEmpty))
    func testDecryptCompact_AESKW_Deflate() throws {
        let jweString = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC\
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0\
        .\
        5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi\
        .\
        p9pUq6XHY0jfEZIl\
        .\
        HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyez\
        SPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0\
        m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBK\
        hpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw\
        .\
        VILuUwuIxaLVmh5X-T7kmA
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptFlatJSON_AES_KW_AAD() throws {
        let jweString = """
        {
          "protected": "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04Mz\
        MyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn\
        0",
          "encrypted_key": "4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X",
          "aad": "WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxb\
        ImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4i\
        LHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIs\
        IiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVy\
        Iix7fSwidGV4dCIsIk0iXV1d",
          "iv": "veCx9ece2orS7c_N",
          "ciphertext": "Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0\
        Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14\
        T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fz\
        OI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrs\
        LNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy\
        2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3\
        X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV",
          "tag": "vOaH_Rajnpy_3hOtqvZHRA"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptFlatJSON_AES_KW_PartialUnprotectedHeader() throws {
        let jweString = """
        {
          "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
          "unprotected": {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8"
          },
          "encrypted_key": "jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H",
          "iv": "WgEJsDS9bkoXQ3nR",
          "ciphertext": "lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2D\
        M3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9O\
        CCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6\
        uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5\
        g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU\
        4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3\
        HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf",
          "tag": "fNYLqpUe84KD45lvDiaBAQ"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptFlatJSON_AES_KW_UnprotectedHeader() throws {
        let jweString = """
        {
          "unprotected": {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
            "enc": "A128GCM"
          },
          "encrypted_key": "244YHfO_W7RMpQW81UjQrZcq5LSyqiPv",
          "iv": "YihBoVOGsR1l7jCD",
          "ciphertext": "qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-\
        arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHF\
        SP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDs\
        RPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8\
        ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDf\
        rb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4\
        -8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF",
          "tag": "e2m0Vm7JvjK2VpCKXS-kyg"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let decodedText = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapSymmetricKey.key)
        #expect(decodedText == plainText.data)
    }
    
    @Test
    func testDecryptMultipleRecipients() throws {
        let jweString = """
        {
          "recipients": [
            {
              "encrypted_key": "dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zj\
        wj4w6Y5G4XJQsNNIBiqyvUUAOcpL7S7-cFe7Pio7gV_Q06WmCSa-\
        vhW6me4bWrBf7cHwEQJdXihidAYWVajJIaKMXMvFRMV6iDlRr076\
        DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-wqjw0-b-S\
        1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbe\
        YSrRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n\
        5trGuExtp_-dbHcGlihqc_wGgho9fLMK8JOArYLcMDNQ",
              "header": {
                "alg": "RSA1_5",
                "kid": "frodo.baggins@hobbiton.example"
              }
            },
            {
              "encrypted_key": "ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHixJuw_elY4gSSId_w",
              "header": {
                "alg": "ECDH-ES+A256KW",
                "kid": "peregrin.took@tuckborough.example",
                "epk": {
                  "kty": "EC",
                  "crv": "P-384",
                  "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2DtMRb25Ma2CX",
                  "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw91fzZ84pbfm"
                }
              }
            },
            {
              "encrypted_key": "a7CclAejo_7JSuPB8zeagxXRam8dwCfmkt9-WyTpS1E",
              "header": {
                "alg": "A256GCMKW",
                "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                "tag": "59Nqh1LlYtVIhfD3pgRGvw",
                "iv": "AvpeoPZ9Ncn9mkBn"
              }
            }
          ],
          "unprotected": {
            "cty": "text/plain"
          },
          "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
          "iv": "VgEIHY20EnzUtZFl2RpB1g",
          "ciphertext": "ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK\
        04SjdxQeSw2L9mu3a_k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM\
        9tBURMFqLByJ8vOYQX0oJW4VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSa\
        P6ga7-siYxStR7_G07Thd1jh-zGT0wxM5g-VRORtq0K6AXpLlwEqRp7p\
        kt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZukLpCbzhzMDLLw2-8I14FQ\
        rgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXMY9YQjorZ_P_JYG3\
        ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2ofDQdLCht\
        azE",
          "tag": "BESYyFN7T09KY7i8zKs5_g"
        }
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        
        // First recipient: RSAv1.5
        let decodedText1 = try jwe.decrypt(using: RFC7520ExampleKeys.rsa1_5EncPrivateKey.key)
        #expect(decodedText1 == plainText.data)
        
        // Second recipient: ECDH-ES
        let decodedText2 = try jwe.decrypt(using: RFC7520ExampleKeys.ecdhPrivateKey.key)
        #expect(decodedText2 == plainText.data)
        
        // Third recipient: AES-GCM KeyWrap
        let decodedText3 = try jwe.decrypt(using: RFC7520ExampleKeys.keyWrapGCMSymmetricKey.key)
        #expect(decodedText3 == plainText.data)
        
        let decodedText4 = try jwe.decrypt(using: [
            RFC7520ExampleKeys.rsaOAEPEncPrivateKey.key,
            RFC7520ExampleKeys.ecdhPrivateKey.key,
            RFC7520ExampleKeys.keyWrapSymmetricKey.key,
        ])
        #expect(decodedText4 == plainText.data)
    }
    
    @Test
    func testDescryptNestedJWS() throws {
        let jweString = """
        eyJhbGciOiJSU0EtT0FFUCIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00ifQ\
        .\
        a0JHRoITfpX4qRewImjlStn8m3CPxBV1ueYlVhjurCyrBg3I7YhCRYjphDOOS4\
        E7rXbr2Fn6NyQq-A-gqT0FXqNjVOGrG-bi13mwy7RoYhjTkBEC6P7sMYMXXx4g\
        zMedpiJHQVeyI-zkZV7A9matpgevAJWrXzOUysYGTtwoSN6gtUVtlLaivjvb21\
        O0ul4YxSHV-ByK1kyeetRp_fuYJxHoKLQL9P424sKx2WGYb4zsBIPF4ssl_e5I\
        R7nany-25_UmC2urosNkoFz9cQ82MypZP8gqbQJyPN-Fpp4Z-5o6yV64x6yzDU\
        F_5JCIdl-Qv6H5dMVIY7q1eKpXcV1lWO_2FefEBqXxXvIjLeZivjNkzogCq3-I\
        apSjVFnMjBxjpYLT8muaawo1yy1XXMuinIpNcOY3n4KKrXLrCcteX85m4IIHMZ\
        a38s1Hpr56fPPseMA-Jltmt-a9iEDtOzhtxz8AXy9tsCAZV2XBWNG8c3kJusAa\
        mBKOYwfk7JhLRDgOnJjlJLhn7TI4UxDp9dCmUXEN6z0v23W15qJIEXNJtqnblp\
        ymooeWAHCT4e_Owbim1g0AEpTHUdA2iiLNs9WTX_H_TXuPC8yDDhi1smxS_X_x\
        pkIHkiIHWDOLx03BpqDTivpKkBYwqP2UZkcxqX2Fo_GnVrNwlK7Lgxw6FSQvDO\
        0\
        .\
        GbX1i9kXz0sxXPmA\
        .\
        SZI4IvKHmwpazl_pJQXX3mHv1ANnOU4Wf9-utWYUcKrBNgCe2OFMf66cSJ8k2Q\
        kxaQD3_R60MGE9ofomwtky3GFxMeGRjtpMt9OAvVLsAXB0_UTCBGyBg3C2bWLX\
        qZlfJAAoJRUPRk-BimYZY81zVBuIhc7HsQePCpu33SzMsFHjn4lP_idrJz_glZ\
        TNgKDt8zdnUPauKTKDNOH1DD4fuzvDYfDIAfqGPyL5sVRwbiXpXdGokEszM-9C\
        hMPqW1QNhzuX_Zul3bvrJwr7nuGZs4cUScY3n8yE3AHCLurgls-A9mz1X38xEa\
        ulV18l4Fg9tLejdkAuQZjPbqeHQBJe4IwGD5Ee0dQ-Mtz4NnhkIWx-YKBb_Xo2\
        zI3Q_1sYjKUuis7yWW-HTr_vqvFt0bj7WJf2vzB0TZ3dvsoGaTvPH2dyWwumUr\
        lx4gmPUzBdwTO6ubfYSDUEEz5py0d_OtWeUSYcCYBKD-aM7tXg26qJo21gYjLf\
        hn9zy-W19sOCZGuzgFjPhawXHpvnj_t-0_ES96kogjJLxS1IMU9Y5XmnwZMyNc\
        9EIwnogsCg-hVuvzyP0sIruktmI94_SL1xgMl7o03phcTMxtlMizR88NKU1WkB\
        siXMCjy1Noue7MD-ShDp5dmM\
        .\
        KnIKEhN8U-3C9s4gtSpjSw
        """
        
        let jwe = try JSONWebEncryption(from: jweString.data)
        let jwt = try JSONWebToken(from: jwe.decrypt(using: RFC7520ExampleKeys.rsaOAEPEncPrivateKey.key))
        
        #expect(jwt.payload.issuer == "hobbiton.example")
        #expect(jwt.payload.expiry == Date(timeIntervalSince1970: 1_300_819_380))
        #expect(jwt.payload["http://example.com/is_root"] == true)
    }
}
