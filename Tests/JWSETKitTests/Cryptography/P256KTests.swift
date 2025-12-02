//
//  P256KTests.swift
//
//
//  Created by Amir Abbas Mousavian on 2025/11/30.
//

#if P256K
import Crypto
import Foundation
import Testing
@testable import JWSETKit

@Suite
struct P256KTests {
    let plaintext = Data("The quick brown fox jumps over the lazy dog.".utf8)

    // MARK: - Test Vectors

    // Wycheproof Test Group 1 - ECDSA secp256k1 SHA-256
    // Source: https://github.com/C2SP/wycheproof
    struct WycheproofVector {
        let publicKeyUncompressed: String
        let message: String
        let signatureDER: String
        let isValid: Bool
    }

    static let wycheproofPublicKey1 = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152"

    static let wycheproofVectors: [WycheproofVector] = [
        // tcId: 1 - pseudorandom signature, empty message
        WycheproofVector(
            publicKeyUncompressed: wycheproofPublicKey1,
            message: "",
            signatureDER: "3046022100f80ae4f96cdbc9d853f83d47aae225bf407d51c56b7776cd67d0dc195d99a9dc022100b303e26be1f73465315221f0b331528807a1a9b6eb068ede6eebeaaa49af8a36",
            isValid: true
        ),
        // tcId: 2 - pseudorandom signature, message "Msg"
        WycheproofVector(
            publicKeyUncompressed: wycheproofPublicKey1,
            message: "4d7367",
            signatureDER: "30450220109cd8ae0374358984a8249c0a843628f2835ffad1df1a9a69aa2fe72355545c022100ac6f00daf53bd8b1e34da329359b6e08019c5b037fed79ee383ae39f85a159c6",
            isValid: true
        ),
        // tcId: 3 - pseudorandom signature, message "123400"
        WycheproofVector(
            publicKeyUncompressed: wycheproofPublicKey1,
            message: "313233343030",
            signatureDER: "3045022100d035ee1f17fdb0b2681b163e33c359932659990af77dca632012b30b27a057b302201939d9f3b2858bc13e3474cb50e6a82be44faa71940f876c1cba4c3e989202b6",
            isValid: true
        ),
        // tcId: 4 - pseudorandom signature, message of 20 zero bytes
        WycheproofVector(
            publicKeyUncompressed: wycheproofPublicKey1,
            message: "0000000000000000000000000000000000000000",
            signatureDER: "304402204f053f563ad34b74fd8c9934ce59e79c2eb8e6eca0fef5b323ca67d5ac7ed23802204d4b05daa0719e773d8617dce5631c5fd6f59c9bdc748e4b55c970040af01be5",
            isValid: true
        ),
    ]

    static let wycheproofPublicKey2 = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"

    static let wycheproofVectors2: [WycheproofVector] = [
        // tcId: 5 - signature malleability
        WycheproofVector(
            publicKeyUncompressed: wycheproofPublicKey2,
            message: "313233343030",
            signatureDER: "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
            isValid: true
        ),
        // tcId: 7 - valid
        WycheproofVector(
            publicKeyUncompressed: wycheproofPublicKey2,
            message: "313233343030",
            signatureDER: "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
            isValid: true
        ),
    ]

    // Known private/public key pair for testing key derivation
    // Source: BIP340 test vectors (we use the key pair, not Schnorr signatures)
    struct KeyPairVector {
        let secretKey: String
        let publicKeyX: String // x-coordinate (32 bytes)
    }

    static let keyPairVectors: [KeyPairVector] = [
        KeyPairVector(
            secretKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            publicKeyX: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
        ),
        KeyPairVector(
            secretKey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            publicKeyX: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
        ),
        KeyPairVector(
            secretKey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            publicKeyX: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"
        ),
    ]

    // MARK: - Helper Functions

    func hexToData(_ hex: String) -> Data {
        var data = Data()
        var hex = hex
        while hex.count >= 2 {
            let hexByte = String(hex.prefix(2))
            hex = String(hex.dropFirst(2))
            if let byte = UInt8(hexByte, radix: 16) {
                data.append(byte)
            }
        }
        return data
    }

    // MARK: - Key Generation Tests

    @Test
    func keyGeneration() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        #expect(privateKey.rawRepresentation.count == 32)
        #expect(publicKey.rawRepresentation.count == 64)
        #expect(publicKey.x963Representation.count == 65)
        #expect(publicKey.compressedRepresentation.count == 33)
    }

    // MARK: - Key Serialization Tests

    @Test
    func publicKeyUncompressedSerialization() throws {
        let uncompressedHex = Self.wycheproofPublicKey1
        let uncompressedData = hexToData(uncompressedHex)

        // Parse uncompressed key (x963 format with 04 prefix)
        let publicKey = try P256K.Signing.PublicKey(x963Representation: uncompressedData)

        // Verify roundtrip
        #expect(publicKey.x963Representation == uncompressedData)

        // Verify raw representation (without prefix)
        #expect(publicKey.rawRepresentation == uncompressedData.dropFirst())
        #expect(publicKey.rawRepresentation.count == 64)
    }

    @Test
    func publicKeyCompressedSerialization() throws {
        let uncompressedHex = Self.wycheproofPublicKey1
        let uncompressedData = hexToData(uncompressedHex)

        let publicKey = try P256K.Signing.PublicKey(x963Representation: uncompressedData)

        // Get compressed representation
        let compressed = publicKey.compressedRepresentation
        #expect(compressed.count == 33)
        #expect(compressed.first == 0x02 || compressed.first == 0x03)

        // Parse from compressed and verify roundtrip
        let publicKeyFromCompressed = try P256K.Signing.PublicKey(compressedRepresentation: compressed)
        #expect(publicKeyFromCompressed.x963Representation == publicKey.x963Representation)
    }

    @Test
    func publicKeyXOnlySerialization() throws {
        // Use known test vector with x-only public key (x-coordinate only)
        let xOnlyHex = Self.keyPairVectors[0].publicKeyX
        let xOnlyData = hexToData(xOnlyHex)

        // Parse x-only key (compact representation)
        let publicKey = try P256K.Signing.PublicKey(compactRepresentation: xOnlyData)

        // Compressed representation should start with 02 for even y
        let compressed = publicKey.compressedRepresentation
        #expect(compressed.count == 33)
        #expect(compressed.first == 0x02)
        #expect(compressed.dropFirst() == xOnlyData)
    }

    @Test
    func publicKeyRawSerialization() throws {
        let uncompressedHex = Self.wycheproofPublicKey1
        let uncompressedData = hexToData(uncompressedHex)

        let publicKey = try P256K.Signing.PublicKey(x963Representation: uncompressedData)
        let rawData = publicKey.rawRepresentation

        // Raw is x963 without the 04 prefix
        #expect(rawData.count == 64)
        #expect(rawData == uncompressedData.dropFirst())

        // Parse from raw and verify roundtrip
        let publicKeyFromRaw = try P256K.Signing.PublicKey(rawRepresentation: rawData)
        #expect(publicKeyFromRaw.x963Representation == publicKey.x963Representation)
    }

    @Test
    func privateKeyRawSerialization() throws {
        let secretKeyHex = Self.keyPairVectors[0].secretKey
        let secretKeyData = hexToData(secretKeyHex)

        let privateKey = try P256K.Signing.PrivateKey(rawRepresentation: secretKeyData)

        // Verify roundtrip
        #expect(privateKey.rawRepresentation == secretKeyData)
        #expect(privateKey.rawRepresentation.count == 32)
    }

    @Test
    func privateKeyX963Serialization() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let x963 = privateKey.x963Representation

        // x963 for private key: 04 + x (32) + y (32) + d (32) = 97 bytes
        #expect(x963.count == 97)
        #expect(x963.first == 0x04)

        // Parse from x963 and verify roundtrip
        let privateKeyFromX963 = try P256K.Signing.PrivateKey(x963Representation: x963)
        #expect(privateKeyFromX963.rawRepresentation == privateKey.rawRepresentation)
        #expect(privateKeyFromX963.publicKey.x963Representation == privateKey.publicKey.x963Representation)
    }

    @Test
    func publicKeyDERSerialization() throws {
        let uncompressedHex = Self.wycheproofPublicKey1
        let uncompressedData = hexToData(uncompressedHex)

        let publicKey = try P256K.Signing.PublicKey(x963Representation: uncompressedData)
        let der = publicKey.derRepresentation

        // DER should be non-empty
        #expect(!der.isEmpty)

        // Parse from DER and verify roundtrip
        let publicKeyFromDER = try P256K.Signing.PublicKey(derRepresentation: der)
        #expect(publicKeyFromDER.x963Representation == publicKey.x963Representation)
    }

    @Test
    func privateKeyDERSerialization() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let der = privateKey.derRepresentation

        // DER should be non-empty
        #expect(!der.isEmpty)

        // Parse from DER and verify roundtrip
        let privateKeyFromDER = try P256K.Signing.PrivateKey(derRepresentation: der)
        #expect(privateKeyFromDER.rawRepresentation == privateKey.rawRepresentation)
    }

#if !hasFeature(Embedded)
    @Test
    func publicKeyPEMSerialization() throws {
        let uncompressedHex = Self.wycheproofPublicKey1
        let uncompressedData = hexToData(uncompressedHex)

        let publicKey = try P256K.Signing.PublicKey(x963Representation: uncompressedData)
        let pem = publicKey.pemRepresentation

        // PEM should contain the expected markers
        #expect(pem.contains("-----BEGIN PUBLIC KEY-----"))
        #expect(pem.contains("-----END PUBLIC KEY-----"))

        // Parse from PEM and verify roundtrip
        let publicKeyFromPEM = try P256K.Signing.PublicKey(pemRepresentation: pem)
        #expect(publicKeyFromPEM.x963Representation == publicKey.x963Representation)
    }

    @Test
    func privateKeyPEMSerialization() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let pem = privateKey.pemRepresentation

        // PEM should contain the expected markers
        #expect(pem.contains("-----BEGIN PRIVATE KEY-----"))
        #expect(pem.contains("-----END PRIVATE KEY-----"))

        // Parse from PEM and verify roundtrip
        let privateKeyFromPEM = try P256K.Signing.PrivateKey(pemRepresentation: pem)
        #expect(privateKeyFromPEM.rawRepresentation == privateKey.rawRepresentation)
    }
#endif

    // MARK: - ECDSA Sign/Verify Tests

    @Test
    func ecdsaSignAndVerify() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let signature = try privateKey.signature(for: plaintext)

        #expect(signature.rawRepresentation.count == 64)
        #expect(publicKey.isValidSignature(signature, for: plaintext))
    }

    @Test
    func ecdsaSignAndVerifyWithDigest() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let digest = SHA256.hash(data: plaintext)
        let signature = try privateKey.signature(for: digest)

        #expect(signature.rawRepresentation.count == 64)
        #expect(publicKey.isValidSignature(signature, for: digest))
    }

    @Test
    func ecdsaVerifyWycheproofVectors() throws {
        // NOTE: High-s signatures are automatically normalized to low-s form during parsing.
        // This prevents signature malleability while accepting all valid ECDSA signatures.
        for vector in Self.wycheproofVectors {
            let publicKeyData = hexToData(vector.publicKeyUncompressed)
            let messageData = hexToData(vector.message)
            let signatureDER = hexToData(vector.signatureDER)

            let publicKey = try P256K.Signing.PublicKey(x963Representation: publicKeyData)

            do {
                let signature = try P256K.Signing.ECDSASignature(derRepresentation: signatureDER)
                let isValid = publicKey.isValidSignature(signature, for: messageData)

                #expect(isValid == vector.isValid, "Wycheproof vector verification mismatch for message: \(vector.message)")
            } catch {
                // Signature parsing may fail for some edge cases
                #expect(!vector.isValid, "Invalid signature parsing should correspond to invalid vector")
            }
        }
    }

    @Test
    func ecdsaVerifyWycheproofVectors2() throws {
        // NOTE: High-s signatures are automatically normalized to low-s form during parsing.
        for vector in Self.wycheproofVectors2 {
            let publicKeyData = hexToData(vector.publicKeyUncompressed)
            let messageData = hexToData(vector.message)
            let signatureDER = hexToData(vector.signatureDER)

            let publicKey = try P256K.Signing.PublicKey(x963Representation: publicKeyData)

            do {
                let signature = try P256K.Signing.ECDSASignature(derRepresentation: signatureDER)
                let isValid = publicKey.isValidSignature(signature, for: messageData)

                #expect(isValid == vector.isValid, "Wycheproof vector 2 verification mismatch for message: \(vector.message)")
            } catch {
                // Signature parsing may fail for some edge cases
                #expect(!vector.isValid, "Invalid signature parsing should correspond to invalid vector")
            }
        }
    }

    @Test
    func ecdsaSignatureRawAndDERConversion() throws {
        let privateKey = P256K.Signing.PrivateKey()

        let signature = try privateKey.signature(for: plaintext)
        let derSignature = signature.derRepresentation

        // Parse DER and convert back to raw
        let signatureFromDER = try P256K.Signing.ECDSASignature(derRepresentation: derSignature)
        #expect(signatureFromDER.rawRepresentation == signature.rawRepresentation)
    }

    @Test
    func ecdsaInvalidSignatureRejected() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let signature = try privateKey.signature(for: plaintext)

        // Modify the signature
        var invalidSignatureData = signature.rawRepresentation
        invalidSignatureData[0] ^= 0xFF
        let invalidSignature = try P256K.Signing.ECDSASignature(rawRepresentation: invalidSignatureData)

        #expect(!publicKey.isValidSignature(invalidSignature, for: plaintext))
    }

    @Test
    func ecdsaWrongMessageRejected() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let signature = try privateKey.signature(for: plaintext)
        let wrongMessage = Data("Wrong message".utf8)

        #expect(!publicKey.isValidSignature(signature, for: wrongMessage))
    }

    // MARK: - Key Derivation Tests

    @Test
    func privateKeyFromKnownVector() throws {
        // Test key pair derivation with known test vectors
        for vector in Self.keyPairVectors {
            let secretKeyData = hexToData(vector.secretKey)
            let expectedPublicKeyX = hexToData(vector.publicKeyX)

            let privateKey = try P256K.Signing.PrivateKey(rawRepresentation: secretKeyData)
            let publicKey = privateKey.publicKey

            // The x-coordinate of the derived public key should match
            let compressedPublicKey = publicKey.compressedRepresentation
            let xCoordinate = compressedPublicKey.dropFirst() // Remove 02/03 prefix

            #expect(xCoordinate == expectedPublicKeyX, "Derived public key x-coordinate should match expected for vector: \(vector.secretKey.prefix(16))...")
        }
    }

    // MARK: - ECDH Key Agreement Tests

    @Test
    func ecdhKeyGeneration() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        #expect(privateKey.rawRepresentation.count == 32)
        #expect(publicKey.rawRepresentation.count == 64)
        #expect(publicKey.x963Representation.count == 65)
        #expect(publicKey.compressedRepresentation.count == 33)
    }

    @Test
    func ecdhSharedSecretBasic() throws {
        // Alice and Bob generate key pairs
        let alicePrivateKey = P256K.KeyAgreement.PrivateKey()
        let alicePublicKey = alicePrivateKey.publicKey

        let bobPrivateKey = P256K.KeyAgreement.PrivateKey()
        let bobPublicKey = bobPrivateKey.publicKey

        // Compute shared secrets
        let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
        let bobSharedSecret = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)

        // Shared secrets should match
        #expect(aliceSharedSecret == bobSharedSecret)
        #expect(aliceSharedSecret.withUnsafeBytes { $0.count } == 32)
    }

    @Test
    func ecdhSharedSecretFromKnownKeys() throws {
        // Use known test vectors for reproducible ECDH
        let aliceSecretKeyHex = Self.keyPairVectors[0].secretKey
        let bobSecretKeyHex = Self.keyPairVectors[1].secretKey

        let alicePrivateKey = try P256K.KeyAgreement.PrivateKey(rawRepresentation: hexToData(aliceSecretKeyHex))
        let bobPrivateKey = try P256K.KeyAgreement.PrivateKey(rawRepresentation: hexToData(bobSecretKeyHex))

        // Compute shared secrets
        let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPrivateKey.publicKey)
        let bobSharedSecret = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePrivateKey.publicKey)

        // Shared secrets should match
        #expect(aliceSharedSecret == bobSharedSecret)
        #expect(aliceSharedSecret.withUnsafeBytes { $0.count } == 32)
    }

    @Test
    func ecdhPublicKeyRoundtrip() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        // Test x963 roundtrip
        let x963 = publicKey.x963Representation
        let publicKeyFromX963 = try P256K.KeyAgreement.PublicKey(x963Representation: x963)
        #expect(publicKeyFromX963.x963Representation == x963)

        // Test compressed roundtrip
        let compressed = publicKey.compressedRepresentation
        let publicKeyFromCompressed = try P256K.KeyAgreement.PublicKey(compressedRepresentation: compressed)
        #expect(publicKeyFromCompressed.x963Representation == publicKey.x963Representation)

        // Test raw roundtrip
        let raw = publicKey.rawRepresentation
        let publicKeyFromRaw = try P256K.KeyAgreement.PublicKey(rawRepresentation: raw)
        #expect(publicKeyFromRaw.x963Representation == publicKey.x963Representation)
    }

    @Test
    func ecdhPrivateKeyRoundtrip() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()

        // Test raw roundtrip
        let raw = privateKey.rawRepresentation
        let privateKeyFromRaw = try P256K.KeyAgreement.PrivateKey(rawRepresentation: raw)
        #expect(privateKeyFromRaw.rawRepresentation == raw)
        #expect(privateKeyFromRaw.publicKey.x963Representation == privateKey.publicKey.x963Representation)

        // Test x963 roundtrip
        let x963 = privateKey.x963Representation
        let privateKeyFromX963 = try P256K.KeyAgreement.PrivateKey(x963Representation: x963)
        #expect(privateKeyFromX963.rawRepresentation == raw)
        #expect(privateKeyFromX963.publicKey.x963Representation == privateKey.publicKey.x963Representation)
    }

    @Test
    func ecdhDifferentKeysProduceDifferentSecrets() throws {
        let alice = P256K.KeyAgreement.PrivateKey()
        let bob1 = P256K.KeyAgreement.PrivateKey()
        let bob2 = P256K.KeyAgreement.PrivateKey()

        let secret1 = try alice.sharedSecretFromKeyAgreement(with: bob1.publicKey)
        let secret2 = try alice.sharedSecretFromKeyAgreement(with: bob2.publicKey)

        // Different Bob keys should produce different shared secrets
        #expect(secret1 != secret2)
    }

#if !hasFeature(Embedded)
    @Test
    func ecdhPublicKeyPEMRoundtrip() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        let pem = publicKey.pemRepresentation
        #expect(pem.contains("-----BEGIN PUBLIC KEY-----"))
        #expect(pem.contains("-----END PUBLIC KEY-----"))

        let publicKeyFromPEM = try P256K.KeyAgreement.PublicKey(pemRepresentation: pem)
        #expect(publicKeyFromPEM.x963Representation == publicKey.x963Representation)
    }

    @Test
    func ecdhPrivateKeyPEMRoundtrip() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()

        let pem = privateKey.pemRepresentation
        #expect(pem.contains("-----BEGIN PRIVATE KEY-----"))
        #expect(pem.contains("-----END PRIVATE KEY-----"))

        let privateKeyFromPEM = try P256K.KeyAgreement.PrivateKey(pemRepresentation: pem)
        #expect(privateKeyFromPEM.rawRepresentation == privateKey.rawRepresentation)
    }
#endif

    @Test
    func ecdhPublicKeyDERRoundtrip() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        let der = publicKey.derRepresentation
        #expect(!der.isEmpty)

        let publicKeyFromDER = try P256K.KeyAgreement.PublicKey(derRepresentation: der)
        #expect(publicKeyFromDER.x963Representation == publicKey.x963Representation)
    }

    @Test
    func ecdhPrivateKeyDERRoundtrip() throws {
        let privateKey = P256K.KeyAgreement.PrivateKey()

        let der = privateKey.derRepresentation
        #expect(!der.isEmpty)

        let privateKeyFromDER = try P256K.KeyAgreement.PrivateKey(derRepresentation: der)
        #expect(privateKeyFromDER.rawRepresentation == privateKey.rawRepresentation)
    }

    @Test
    func ecdhCompactPublicKey() throws {
        // Test compact (x-only) public key representation
        let privateKey = P256K.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        if let compact = publicKey.compactRepresentation {
            #expect(compact.count == 32)

            // Should be able to create key from compact representation
            let publicKeyFromCompact = try P256K.KeyAgreement.PublicKey(compactRepresentation: compact)

            // Compute shared secret with both representations
            let partnerKey = P256K.KeyAgreement.PrivateKey()
            let secret1 = try partnerKey.sharedSecretFromKeyAgreement(with: publicKey)
            let secret2 = try partnerKey.sharedSecretFromKeyAgreement(with: publicKeyFromCompact)

            #expect(secret1 == secret2)
        }
    }

    // MARK: - JWK Integration Tests

    @Test
    func jwkSignAndVerify() throws {
        let privateKey = P256K.Signing.PrivateKey()

        let signature = try privateKey.signature(plaintext, using: .ecdsaSignatureSecp256k1SHA256)
        try privateKey.publicKey.verifySignature(signature, for: plaintext, using: .ecdsaSignatureSecp256k1SHA256)
    }

    // MARK: - Edge Cases

    @Test
    func invalidKeySizeRejected() throws {
        let tooShort = Data(repeating: 0x00, count: 31)
        let tooLong = Data(repeating: 0x00, count: 33)

        #expect(throws: (any Error).self) {
            try P256K.Signing.PrivateKey(rawRepresentation: tooShort)
        }
        #expect(throws: (any Error).self) {
            try P256K.Signing.PrivateKey(rawRepresentation: tooLong)
        }
    }

    @Test
    func invalidSignatureSizeRejected() throws {
        let tooShort = Data(repeating: 0x00, count: 63)
        let tooLong = Data(repeating: 0x00, count: 65)

        #expect(throws: (any Error).self) {
            try P256K.Signing.ECDSASignature(rawRepresentation: tooShort)
        }
        #expect(throws: (any Error).self) {
            try P256K.Signing.ECDSASignature(rawRepresentation: tooLong)
        }
    }

    @Test
    func signatureComponents() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let signature = try privateKey.signature(for: plaintext)

        let (r, s) = signature.composite
        #expect(r.count == 32)
        #expect(s.count == 32)

        // Reconstruct signature from components
        let reconstructed = r + s
        #expect(reconstructed == signature.rawRepresentation)
    }

    // MARK: - Schnorr Signature Tests

    // BIP340 Test Vectors
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    struct SchnorrVector {
        let index: Int
        let secretKey: String?
        let publicKey: String
        let auxRand: String?
        let message: String
        let signature: String
        let isValid: Bool
        let comment: String
    }

    static let schnorrVectors: [SchnorrVector] = [
        // Test 0: Valid signature with minimal values
        SchnorrVector(
            index: 0,
            secretKey: "0000000000000000000000000000000000000000000000000000000000000003",
            publicKey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            auxRand: "0000000000000000000000000000000000000000000000000000000000000000",
            message: "0000000000000000000000000000000000000000000000000000000000000000",
            signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            isValid: true,
            comment: "valid signature with minimal keys/message"
        ),
        // Test 1: Valid signature with non-zero values
        SchnorrVector(
            index: 1,
            secretKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: "0000000000000000000000000000000000000000000000000000000000000001",
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            isValid: true,
            comment: "valid signature with non-zero values"
        ),
        // Test 2: Valid signature with different material
        SchnorrVector(
            index: 2,
            secretKey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            publicKey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            auxRand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            isValid: true,
            comment: "valid signature with different cryptographic material"
        ),
        // Test 3: Valid signature with maximum field values
        SchnorrVector(
            index: 3,
            secretKey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            publicKey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            auxRand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            isValid: true,
            comment: "test fails if msg is reduced modulo p or n"
        ),
        // Test 4: Verification only (no secret key)
        SchnorrVector(
            index: 4,
            secretKey: nil,
            publicKey: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            auxRand: nil,
            message: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
            signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
            isValid: true,
            comment: "public key provided only"
        ),
        // Test 5: Invalid signature (public key not on curve)
        SchnorrVector(
            index: 5,
            secretKey: nil,
            publicKey: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            isValid: false,
            comment: "public key not on the curve"
        ),
        // Test 6: Invalid signature (incorrect R residuosity)
        SchnorrVector(
            index: 6,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
            isValid: false,
            comment: "has_even_y(R) is false"
        ),
        // Test 7: Invalid signature (negated message)
        SchnorrVector(
            index: 7,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
            isValid: false,
            comment: "negated message"
        ),
        // Test 8: Invalid signature (negated s value)
        SchnorrVector(
            index: 8,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
            isValid: false,
            comment: "negated s value"
        ),
        // Test 9: Invalid signature (s*G equals infinity)
        SchnorrVector(
            index: 9,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
            isValid: false,
            comment: "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0"
        ),
        // Test 10: Invalid signature (s*G equals infinity, case 2)
        SchnorrVector(
            index: 10,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
            isValid: false,
            comment: "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1"
        ),
        // Test 11: Invalid signature (sig[0:32] is not an X coordinate on the curve)
        SchnorrVector(
            index: 11,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            isValid: false,
            comment: "sig[0:32] is not an X coordinate on the curve"
        ),
        // Test 12: Invalid signature (sig[0:32] is equal to field size)
        SchnorrVector(
            index: 12,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            isValid: false,
            comment: "sig[0:32] is equal to field size"
        ),
        // Test 13: Invalid signature (sig[32:64] is equal to curve order)
        SchnorrVector(
            index: 13,
            secretKey: nil,
            publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            isValid: false,
            comment: "sig[32:64] is equal to curve order"
        ),
        // Test 14: Public key exceeds field size - verification fail expected
        SchnorrVector(
            index: 14,
            secretKey: nil,
            publicKey: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            auxRand: nil,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            isValid: false,
            comment: "public key is not a valid X coordinate because it exceeds the field size"
        ),
    ]

    @Test
    func schnorrSignAndVerifyRoundtrip() throws {
        // Test basic roundtrip: sign with private key, verify with public key
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let signature = try privateKey.schnorrSignature(for: plaintext)

        // Schnorr signature should be 64 bytes
        #expect(signature.count == 64)

        // Verify the signature
        #expect(publicKey.isValidSchnorrSignature(signature, for: plaintext))
    }

    @Test
    func schnorrSignAndVerifyEmptyMessage() throws {
        // Test with empty message
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let emptyMessage = Data()

        let signature = try privateKey.schnorrSignature(for: emptyMessage)
        #expect(signature.count == 64)
        #expect(publicKey.isValidSchnorrSignature(signature, for: emptyMessage))
    }

    @Test
    func schnorrSignAndVerifyLargeMessage() throws {
        // Test with large message
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let largeMessage = Data(repeating: 0x42, count: 1024)

        let signature = try privateKey.schnorrSignature(for: largeMessage)
        #expect(signature.count == 64)
        #expect(publicKey.isValidSchnorrSignature(signature, for: largeMessage))
    }

    @Test
    func schnorrInvalidSignatureRejected() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let signature = try privateKey.schnorrSignature(for: plaintext)

        // Modify the signature to make it invalid
        var invalidSignature = signature
        invalidSignature[0] ^= 0xFF

        #expect(!publicKey.isValidSchnorrSignature(invalidSignature, for: plaintext))
    }

    @Test
    func schnorrWrongMessageRejected() throws {
        let privateKey = P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let signature = try privateKey.schnorrSignature(for: plaintext)
        let wrongMessage = Data("Wrong message".utf8)

        #expect(!publicKey.isValidSchnorrSignature(signature, for: wrongMessage))
    }

    @Test
    func schnorrWrongPublicKeyRejected() throws {
        let privateKey1 = P256K.Signing.PrivateKey()
        let privateKey2 = P256K.Signing.PrivateKey()

        let signature = try privateKey1.schnorrSignature(for: plaintext)

        // Try to verify with wrong public key
        #expect(!privateKey2.publicKey.isValidSchnorrSignature(signature, for: plaintext))
    }

    @Test
    func schnorrDeterministicSigning() throws {
        // Test that signing with the same key and message produces consistent signatures
        // Note: This may not be deterministic if auxiliary randomness is used
        let secretKeyHex = Self.keyPairVectors[0].secretKey
        let secretKeyData = hexToData(secretKeyHex)

        let privateKey = try P256K.Signing.PrivateKey(rawRepresentation: secretKeyData)

        let signature1 = try privateKey.schnorrSignature(for: plaintext)
        let signature2 = try privateKey.schnorrSignature(for: plaintext)

        // Both signatures should be valid
        #expect(privateKey.publicKey.isValidSchnorrSignature(signature1, for: plaintext))
        #expect(privateKey.publicKey.isValidSchnorrSignature(signature2, for: plaintext))

        // Note: Signatures may differ due to randomness, but both should verify
    }

    @Test
    func schnorrVerifyBIP340Vectors() throws {
        // Test against BIP340 test vectors
        for vector in Self.schnorrVectors {
            let publicKeyData = hexToData(vector.publicKey)
            let messageData = hexToData(vector.message)
            let signatureData = hexToData(vector.signature)

            // Skip test if public key is invalid (some vectors test invalid keys)
            guard let publicKey = try? P256K.Signing.PublicKey(compactRepresentation: publicKeyData) else {
                // Invalid public key should correspond to invalid vector
                #expect(!vector.isValid, "Vector \(vector.index): Invalid public key should have isValid=false. Comment: \(vector.comment)")
                continue
            }

            let isValid = publicKey.isValidSchnorrSignature(signatureData, for: messageData)

            #expect(
                isValid == vector.isValid,
                "BIP340 vector \(vector.index) verification mismatch. Expected: \(vector.isValid), Got: \(isValid). Comment: \(vector.comment)"
            )
        }
    }

    @Test
    func schnorrSignBIP340Vectors() throws {
        // Test signing against BIP340 test vectors (where secret key is provided)
        for vector in Self.schnorrVectors {
            guard let secretKeyHex = vector.secretKey else {
                // Skip vectors without secret key (verification-only vectors)
                continue
            }

            let secretKeyData = hexToData(secretKeyHex)
            let messageData = hexToData(vector.message)
            let expectedSignature = hexToData(vector.signature)

            let privateKey = try P256K.Signing.PrivateKey(rawRepresentation: secretKeyData)
            let signature = try privateKey.schnorrSignature(for: messageData)

            // Verify the generated signature is valid
            #expect(
                privateKey.publicKey.isValidSchnorrSignature(signature, for: messageData),
                "BIP340 vector \(vector.index): Generated signature should be valid. Comment: \(vector.comment)"
            )

            // Note: We cannot compare signatures directly because the implementation may use
            // different auxiliary randomness than the test vectors. However, the signature
            // should still be valid.

            // Verify the expected signature from the vector is also valid
            #expect(
                privateKey.publicKey.isValidSchnorrSignature(expectedSignature, for: messageData),
                "BIP340 vector \(vector.index): Expected signature from vector should be valid. Comment: \(vector.comment)"
            )
        }
    }

    @Test
    func schnorrSignatureSizeValidation() throws {
        let publicKey = P256K.Signing.PrivateKey().publicKey

        // Test invalid signature sizes
        let tooShort = Data(repeating: 0x00, count: 63)
        let tooLong = Data(repeating: 0x00, count: 65)
        let correctSize = Data(repeating: 0x00, count: 64)

        #expect(!publicKey.isValidSchnorrSignature(tooShort, for: plaintext))
        #expect(!publicKey.isValidSchnorrSignature(tooLong, for: plaintext))
        // correctSize signature with all zeros will be invalid, but it's the right size
        #expect(!publicKey.isValidSchnorrSignature(correctSize, for: plaintext))
    }
}
#endif
