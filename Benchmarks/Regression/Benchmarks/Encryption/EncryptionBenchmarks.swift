import Benchmark
import BenchmarkSupport
import Foundation
import JWSETKit

let benchmarks: @Sendable () -> Void = {
    Benchmark("encrypt-RSAOAEP-A256GCM") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: Fixtures.plaintext,
                keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
                keyEncryptionKey: Fixtures.rsaOAEPPrivateKey.publicKey,
                contentEncryptionAlgorithm: .aesEncryptionGCM256
            )))
        }
    }
    Benchmark("decrypt-RSAOAEP-A256GCM") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwe = try JSONWebEncryption(from: Fixtures.encryptedRSAOAEP)
            try blackHole(jwe.decrypt(using: Fixtures.rsaOAEPPrivateKey))
        }
    }
    Benchmark("encrypt-ECDHES-A256GCM") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: Fixtures.plaintext,
                keyEncryptingAlgorithm: .ecdhEphemeralStatic,
                keyEncryptionKey: Fixtures.ecdhPrivateKey.publicKey,
                contentEncryptionAlgorithm: .aesEncryptionGCM256
            )))
        }
    }
    Benchmark("decrypt-ECDHES-A256GCM") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwe = try JSONWebEncryption(from: Fixtures.encryptedECDH)
            try blackHole(jwe.decrypt(using: Fixtures.ecdhPrivateKey))
        }
    }
}
