//
//  CompressionTests.swift
//
//
//  Created by Amir Abbas Mousavian on 11/24/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct CompressionTests {
    let decompressed = "Data compression test. This text must be compressed.".data
    let deflateCompressed = "c0ksSVRIzs8tKEotLs7Mz1MoSS0u0VMIycgsBjIrShRyS4tLFJJS4WpSU/QA".decoded
    
    var compressors: [any JSONWebCompressor.Type]
    
    init() {
        var compressors: [any JSONWebCompressor.Type] = []
#if canImport(Compression)
        compressors.append(AppleCompressor<DeflateCompressionCodec>.self)
#endif
#if canImport(Czlib) || canImport(zlib)
        compressors.append(ZlibCompressor<DeflateCompressionCodec>.self)
#endif
        self.compressors = compressors
    }
    
    @Test
    func deflateCompression() throws {
        for deflateCompressor in compressors {
            let testCompressed = try deflateCompressor.compress(decompressed)
            #expect(testCompressed == deflateCompressed)
            #expect(testCompressed.count < decompressed.count)
        }
    }
    
    @Test
    func deflateDecompression() throws {
        for deflateCompressor in compressors {
            let testDecompressed = try deflateCompressor.decompress(deflateCompressed)
            #expect(testDecompressed == decompressed)
        }
    }
    
    @Test
    func compressionDecompression() throws {
        let length = Int.random(in: (1 << 17) ... (1 << 20)) // 128KB to 1MB
        let random = Data.random(length: length)
            .urlBase64EncodedData()
        for algorithm in JSONWebCompressionAlgorithm.registeredAlgorithms {
            guard let compressor = algorithm.compressor else { continue }
            let testCompressed = try compressor.compress(random)
            let testDecompressed = try compressor.decompress(testCompressed)
            #expect(testCompressed.count < random.count)
            #expect(Data(random) == testDecompressed)
        }
    }
}
