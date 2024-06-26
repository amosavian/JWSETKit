//
//  CompressionTests.swift
//
//
//  Created by Amir Abbas Mousavian on 11/24/23.
//

import XCTest
@testable import JWSETKit

final class CompressionTests: XCTestCase {
    let decompressed = "Data compression test. This text must be compressed.".data
    let deflateCompressed = "c0ksSVRIzs8tKEotLs7Mz1MoSS0u0VMIycgsBjIrShRyS4tLFJJS4WpSU/QA".decoded
    
    var deflateCompressor: (any JSONWebCompressor.Type)? {
        guard JSONWebCompressionAlgorithm.registeredAlgorithms.contains(.deflate) else { return nil }
        return JSONWebCompressionAlgorithm.deflate.compressor
    }
    
    func testDeflateCompression() throws {
        guard let deflateCompressor else { return }
        let testCompressed = try deflateCompressor.compress(decompressed)
        XCTAssertEqual(testCompressed, deflateCompressed)
        XCTAssertLessThan(testCompressed.count, decompressed.count)
    }
    
    func testDeflateDecompression() throws {
        guard let deflateCompressor else { return }
        let testDecompressed = try deflateCompressor.decompress(deflateCompressed)
        XCTAssertEqual(testDecompressed, decompressed)
    }
    
    func testCompressionDecompression() throws {
        let length = Int.random(in: (1 << 17) ... (1 << 20)) // 128KB to 1MB
        let random = (0 ..< length)
            .map { _ in UInt8.random(in: 0 ... 255) }
            .urlBase64EncodedData()
        for algorithm in JSONWebCompressionAlgorithm.registeredAlgorithms {
            guard let compressor = algorithm.compressor else { continue }
            let testCompressed = try compressor.compress(random)
            let testDecompressed = try compressor.decompress(testCompressed)
            XCTAssertLessThan(testCompressed.count, random.count)
            XCTAssertEqual(Data(random), testDecompressed)
        }
    }
}
