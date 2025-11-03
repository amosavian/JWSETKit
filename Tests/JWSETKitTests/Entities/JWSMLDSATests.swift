//
//  JWSMLDSATests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/17/23.
//

import Crypto
import Foundation
import Testing
@testable import JWSETKit

#if compiler(>=6.2) || !canImport(CryptoKit)
@Suite
#else
@Suite(.enabled(if: false))
#endif
struct JWSMLDSATests {
    let payload = try! ProtectedDataWebContainer(encoded: """
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4
    """.decoded)
    
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @Test
    func signatureMLDSA65() throws {
        let signature = """
        zmO9_0bLgJAegoVNymfRo4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAU\
        Zi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX\
        9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5r\
        OoHKsxOCAUZhTXKiASb3vk9lUASW0-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-\
        Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5o\
        rKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3\
        oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjtGOFSnUKlsnCeiZF-tNqTy1K\
        pJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiy\
        ZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvf\
        Qf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnxsvBOPiSLxAEdPo\
        Iuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqr\
        VcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRY\
        s-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFNfMP7S\
        9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QO\
        nkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJL\
        mmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06\
        ExdzBhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0k\
        e3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwI\
        HfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eB\
        EYrH20rmRP7G7kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PW\
        bx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn\
        58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_q\
        hvyrNjOx0Mdc-1PrwoWqpA9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3S\
        BjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QE\
        QsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZi\
        Aydwb8LX2QsY9Jr_NphGAMAqzrpkuaMyBd_pFTKMp9s0GYxwyG1ZD9uRuPI9i\
        mA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w\
        47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbA\
        e2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoWTr_k2t5KHnWolrSbFH7Us\
        m8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3\
        E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6m\
        q9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwMArSSDA3f8Qln\
        jdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pn\
        xsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsW\
        D2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZCHd1\
        fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8\
        Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37s\
        KKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbry\
        f3N5gtL-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-ltt\
        Gj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7\
        cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdn\
        MhqNSvH_Hx57oDphbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJ\
        mACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHt\
        sXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbK\
        ArPr2-Xpgk8cuZBRSAdmPNRdxCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsM\
        d95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAclxc\
        UGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3q\
        RA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOXPATvyRy34Ltrcg8tcgK0ftYqEWYp\
        AZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJa\
        JGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjD\
        Q6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV21QnqqAbtCzZ76UtEdmU\
        uEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-a\
        B4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZd\
        aRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9_ylvg8k_Eb\
        I2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVS\
        DBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYO\
        BpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJJ\
        3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJ\
        g0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_8\
        6zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2\
        vWner8o6jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9\
        Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_n\
        iBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hh\
        VfxLQ1AWLekWE9DZljCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_Z\
        rEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-L\
        rxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3\
        aj6v3guiKoJoLnV_9h8rUF6zorTWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJ\
        tPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMf\
        z8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-B\
        OaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0fnrgqDpO3RR3gINaZLRmeG0WI4w\
        WBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZE\
        zNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyP\
        tgAAAAAAAAAABgwVHCUv
        """.decoded
        let protected = "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0".decoded
        let keys = [ExampleKeys.publicMLDSA65, ExampleKeys.publicMLDSA87]
        let jws = try! JSONWebSignature(
            signatures: [.init(
                protected: protected,
                signature: signature
            )],
            payload: payload
        )
        #expect(throws: Never.self) { try jws.verifySignature(using: keys) }
    }
    
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @Test
    func signatureMLDSA87() throws {
        let signature = """
        hmMrKkUgZwGPQV_WUoXUVq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FA\
        uW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaL\
        lODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBX\
        GiuyGMLq-TSmXavOeiadtpp6iTUqJDBgQSYvPB6PvipeCPlQH2ZQi8qkraxsp\
        i0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPg\
        pGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZk\
        VdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrANbhOZG8O0BXgqow5Bqv_oRI\
        ztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmA\
        aDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVs\
        ePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2xA70Hp5C5VZIsi\
        5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEU\
        UTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8g\
        Mk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9WBibT\
        CkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6\
        mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8V\
        UGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeL\
        G_ZY7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg\
        0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQ\
        yiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7Ppy\
        yV8HsWfEjqVlAX56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2c\
        NjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsP\
        lFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-\
        PhPAkd61fgXsQZyS9N2jHmFUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneU\
        u84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvpl\
        wcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsX\
        uXDuqwaeb4KpGniHx-23nECgKG86N_1BBX8RRAvYnksxIIxIxgyrng-y44CV9\
        FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANA\
        JQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbL\
        LQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXrupgzQzzFefWyaRkIvC2MP\
        9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0O\
        nA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmm\
        d9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4_IcZGFbdcwp9\
        xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qb\
        C6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g\
        1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NXp06\
        -dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYv\
        EztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfg\
        yB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPP\
        NoY6-A4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wI\
        XmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeid\
        SdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBm\
        jZvTvItXL7f-eD0JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs\
        0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1A\
        SBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3ac\
        XhysGs40nqRzR9imvX9CBQYJZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBi\
        QwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-id\
        JGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4X\
        ubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw_GRbRwyODm3E-N5O3L_R-pva9fvl\
        PjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_\
        FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl\
        43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8Wi4KproenWyCjjzEjJQ\
        dWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2\
        XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_U\
        mc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLthfw4vmK3Yq\
        TAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDw\
        DRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_F\
        UaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCiq\
        29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNF\
        gMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9k\
        xuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2Ep\
        mhEqevSlXYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oH\
        zicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWn\
        rQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6\
        M7ZUiWLtxtMzas2sfAERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYN\
        EmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpj\
        WZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4\
        P9lGS1Ry-8rHCnMN7zXDp43TfyYhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_\
        dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIs\
        cdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2\
        q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z44sl3Exqb5L8pMYpDnZ7QW-Qb1\
        -S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNu\
        Vk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2\
        az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B_NGUasXvEWobqUb61\
        mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIP\
        hOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5h\
        sfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6VP-ci-n7\
        J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRsz\
        m_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3avU\
        HcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW\
        6Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2\
        LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61\
        rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng\
        5VDCX4hyb47LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLt\
        bsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92\
        wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnl\
        JBPp94Zvwh8sKLOpOd4qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ\
        0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7\
        h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KP\
        XKYDXQRbHElEhazMCYr2wnjx_Bx2ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6Y\
        PKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsq\
        uEt7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot\
        -BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0BdckywvAnzUGskWdCfP62dKdx\
        46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3\
        Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAu\
        K1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEcuVATyLtA0jKeyPt\
        E4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih\
        9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd\
        -jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0qTa4Eqr\
        lpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI0\
        5IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ\
        7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALG\
        SAlKzg7Qw
        """.decoded
        let protected = "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0".decoded
        let keys = [ExampleKeys.publicMLDSA65, ExampleKeys.publicMLDSA87]
        let jws = try! JSONWebSignature(
            signatures: [.init(
                protected: protected,
                signature: signature
            )],
            payload: payload
        )
        #expect(throws: Never.self) { try jws.verifySignature(using: keys) }
    }
}
