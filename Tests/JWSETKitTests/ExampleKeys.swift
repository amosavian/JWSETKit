//
//  ExampleKeys.swift
//
//
//  Created by Amir Abbas Mousavian on 9/19/23.
//

import Foundation
import X509
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import JWSETKit

enum ExampleKeys {
    static let publicEC256 = try! JSONWebECPublicKey(importing: Data(
        """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let privateEC256 = try! JSONWebECPrivateKey(importing: Data(
        """
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let publicEC384 = try! JSONWebECPublicKey(importing: Data(
        """
        {"kty":"EC",
         "crv":"P-384",
         "x":"ngGa_TM3LepygN5KLwNmlnd2bEShghi08__4L581jsP16_BjGfP2P3SwNixr7fFZ",
         "y":"0fv1xzyRiGymgQdXlBv5D7YS8IcyXFJD_o3K7DpPtFP2jVoalGVhrquiur4NPyjN",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let privateEC384 = try! JSONWebECPrivateKey(importing: Data(
        """
        {"kty":"EC",
         "crv":"P-384",
         "x":"ngGa_TM3LepygN5KLwNmlnd2bEShghi08__4L581jsP16_BjGfP2P3SwNixr7fFZ",
         "y":"0fv1xzyRiGymgQdXlBv5D7YS8IcyXFJD_o3K7DpPtFP2jVoalGVhrquiur4NPyjN",
         "d":"8v-MgbBQ8W1q7TB9QHsdZIz9HH3qYbAzD-om_MdpyupBU0jHHm-8P4x5E5aZ-vz5",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let publicEC521 = try! JSONWebECPublicKey(importing: Data(
        """
        {"kty":"EC",
         "crv":"P-521",
         "x":"AN1ohCpgsoH3ihEnf_oc6OARdO8f5God-y_45WsUF3k2-jC7l0QgiDhWt2KU72eoiM-56ITNkLiwtfi_V8MIIUsS",
         "y":"AWK8LnVkd5AkfEFFSJZiIQFyDLobKmexQTl5pmHeHStLF6VDKuKT3Q4z1OE4EbMFKQEoZCg4nLY0H2JGK5YKR80_",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let privateEC521 = try! JSONWebECPrivateKey(importing: Data(
        """
        {"kty":"EC",
         "crv":"P-521",
         "x":"AN1ohCpgsoH3ihEnf_oc6OARdO8f5God-y_45WsUF3k2-jC7l0QgiDhWt2KU72eoiM-56ITNkLiwtfi_V8MIIUsS",
         "y":"AWK8LnVkd5AkfEFFSJZiIQFyDLobKmexQTl5pmHeHStLF6VDKuKT3Q4z1OE4EbMFKQEoZCg4nLY0H2JGK5YKR80_",
         "d":"AB0ls-pomOPX4LVRJoF6ZKS6h6L-1rzxxslafOs0xoXjtHsX7c13TaS7N_A91UbHILd8SqCwfIo1GADS76TyxGqP",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let privateEd25519 = try! JSONWebECPrivateKey(importing: Data(
        """
        {"kty":"OKP",
         "crv":"Ed25519",
         "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
         "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let publicEd25519 = try! JSONWebECPublicKey(importing: Data(
        """
        {"kty":"OKP",
         "crv":"Ed25519",
         "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
         "kid":"1"}
        """.utf8
    ), format: .jwk)
    
    static let publicRSA2048 = try! JSONWebRSAPublicKey(importing: Data(
        """
        {"kty":"RSA",
         "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB",
         "alg":"RS256",
         "kid":"2011-04-29"}
        """.utf8
    ), format: .jwk)
    
    static let privateRSA2048 = try! JSONWebRSAPrivateKey(importing: Data(
        """
        {"kty":"RSA",
         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB",
         "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
         "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
         "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
         "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
         "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
         "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
         "alg":"RS256",
         "kid":"2011-04-29"}
        """.utf8
    ), format: .jwk)
    
    static let symmetric = try! SymmetricKey(importing: Data(
        """
        {"kty":"oct",
         "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
         "kid":"HMAC key used in JWS spec Appendix A.1 example"}
        """.utf8
    ), format: .jwk)
    
    static let rsaCertificate = try! JSONDecoder().decode(Certificate.self, from: Data(
        """
        {"kty":"RSA",
         "use":"sig",
         "kid":"1b94c",
         "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
         "e":"AQAB",
         "x5c":
         ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]
         }
        """.utf8
    ))
}

enum RFC7520ExampleKeys {
    static let ecPublicKey: String = """
    {
      "kty": "EC",
      "kid": "bilbo.baggins@hobbiton.example",
      "use": "sig",
      "crv": "P-521",
      "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9\
    A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
      "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy\
    SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
    }
    """

    static let ecPrivateKey: String = """
    {
      "kty": "EC",
      "kid": "bilbo.baggins@hobbiton.example",
      "use": "sig",
      "crv": "P-521",
      "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9\
    A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
      "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy\
    SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
      "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb\
    KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
    }
    """

    static let rsaPublicKey: String = """
    {
      "kty": "RSA",
      "kid": "bilbo.baggins@hobbiton.example",
      "use": "sig",
      "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT\
    -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV\
    wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-\
    oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde\
    3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC\
    LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g\
    HdrNP5zw",
      "e": "AQAB"
    }
    """

    static let rsaPrivateKey: String = """
    {
      "kty": "RSA",
      "kid": "bilbo.baggins@hobbiton.example",
      "use": "sig",
      "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT\
    -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV\
    wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-\
    oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde\
    3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC\
    LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g\
    HdrNP5zw",
      "e": "AQAB",
      "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e\
    iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld\
    Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b\
    MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU\
    6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj\
    d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc\
    OpBrQzwQ",
      "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR\
    aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG\
    peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8\
    bUq0k",
      "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT\
    8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an\
    V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0\
    s7pFc",
      "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q\
    1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn\
    -RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX\
    59ehik",
      "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr\
    AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK\
    bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK\
    T1cYF8",
      "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N\
    ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh\
    jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP\
    z8aaI4"
    }
    """

    static let macSymmetricKey: String = """
    {
      "kty": "oct",
      "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
      "use": "sig",
      "alg": "HS256",
      "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
    }
    """

    static let encryptionSymmetricKey: String = """
    {
      "kty": "oct",
      "kid": "1e571774-2e08-40da-8308-e8d68773842d",
      "use": "enc",
      "alg": "A256GCM",
      "k": "AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"
    }
    """
}

extension String {
    var data: Data { Data(utf8) }
    
    var decoded: Data { Data(urlBase64Encoded: data) ?? Data(base64Encoded: data)! }
        
    var validatingKey: any JSONWebValidatingKey {
        get throws {
            guard let result = try AnyJSONWebKey(importing: data, format: .jwk).specialized() as? (any JSONWebValidatingKey) else {
                throw JSONWebKeyError.keyNotFound
            }
            return result
        }
    }
    
    var signingKey: any JSONWebSigningKey {
        get throws {
            guard let result = try AnyJSONWebKey(importing: data, format: .jwk).specialized() as? (any JSONWebSigningKey) else {
                throw JSONWebKeyError.keyNotFound
            }
            return result
        }
    }
}
