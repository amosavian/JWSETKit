//
//  Apple.swift
//
//
//  Created by Amir Abbas Mousavian on 10/23/23.
//

#if canImport(Compression)
import Compression
import Foundation

extension JSONWebCompressionAlgorithm {
    var appleAlgorithm: Algorithm {
        get throws {
            switch self {
            case .deflate:
                return .zlib
            default:
                throw JSONWebKeyError.unknownAlgorithm
            }
        }
    }
}

/// Compressor contain compress and decompress implementation using `Compression` framework.
public struct AppleCompressor<Codec>: JSONWebCompressor, Sendable where Codec: CompressionCodec {
    public static func compress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var compressedData = Data()
        let filter = try OutputFilter(.compress, using: Codec.algorithm.appleAlgorithm) {
            compressedData.append($0 ?? .init())
        }
        
        // Compress the data
        try filter.write(data)
        try filter.finalize()
        return compressedData
    }
    
    public static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var data = Data(data)
        var decompressedData = Data()
        let filter = try InputFilter(.decompress, using: Codec.algorithm.appleAlgorithm) { count in
            defer { data = data.dropFirst(count) }
            return data.prefix(count)
        }
        
        // Decompress the data
        while let chunk = try filter.readData(ofLength: Codec.pageSize), !chunk.isEmpty {
            decompressedData.append(chunk)
        }
        
        return decompressedData
    }
}
#endif
