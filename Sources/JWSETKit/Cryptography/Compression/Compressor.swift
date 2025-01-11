//
//  Compressor.swift
//
//
//  Created by Amir Abbas Mousavian on 5/1/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#if canImport(SWCompression)
import SWCompression

extension JSONWebCompressionAlgorithm {
    var swCompressor: any CompressionAlgorithm.Type {
        get throws {
            switch self {
            case .deflate:
                return Deflate.self
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
    
    var swDecompressor: any DecompressionAlgorithm.Type {
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
struct Compressor<Codec>: JSONWebCompressor, Sendable where Codec: CompressionCodec {
    static func compress<D>(_ data: D) throws -> Data where D: DataProtocol {
        try Codec.algorithm.swCompressor.compress(data: Data(data))
    }
    
    static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        try Codec.algorithm.swDecompressor.decompress(data: Data(data))
    }
}
#endif
