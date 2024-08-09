//
//  Compressor.swift
//
//
//  Created by Amir Abbas Mousavian on 5/1/24.
//

import Foundation
#if canImport(SWCompression)
import SWCompression

extension JSONWebCompressionAlgorithm {
    var swCompressor: some CompressionAlgorithm.Type {
        get throws {
            switch self {
            case .deflate:
                return Deflate.self
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    var swDecompressor: some DecompressionAlgorithm.Type {
        get throws {
            switch self {
            case .deflate:
                return Deflate.self
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
}

/// Compressor contain compress and decompress implementation using `Compression` framework.
public struct Compressor<Codec>: JSONWebCompressor, Sendable where Codec: CompressionCodec {
    public static func compress<D>(_ data: D) throws -> Data where D: DataProtocol {
        try Codec.algorithm.swCompressor.compress(data: Data(data))
    }
    
    public static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        try Codec.algorithm.swDecompressor.decompress(data: Data(data))
    }
}
#endif
