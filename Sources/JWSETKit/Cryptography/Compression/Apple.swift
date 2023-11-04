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
public struct AppleCompressor<Codec>: JSONWebCompressor where Codec: CompressionCodec {
    public static func compress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var result = Data()
        let outputFilter = try OutputFilter(.compress, using: Codec.algorithm.appleAlgorithm, writingTo: { data in
            if let data = data {
                result.append(data)
            }
        })
        
        var index = 0
        let bufferSize = data.count
        var buffer = [UInt8](repeating: 0, count: Codec.pageSize)
        
        while true {
            let rangeLength = min(Codec.pageSize, bufferSize - index)
            let startIndex = data.index(data.startIndex, offsetBy: index)
            let endIndex = data.index(startIndex, offsetBy: rangeLength)
            buffer.withUnsafeMutableBytes { bytes in
                index += data.copyBytes(to: bytes, from: startIndex ..< endIndex)
            }
            
            try outputFilter.write(rangeLength == Codec.pageSize ? buffer : .init(buffer.prefix(rangeLength)))
            
            if rangeLength == 0 {
                break
            }
        }
        return result.prefix(index)
    }
    
    public static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        let data = Data(data)
        var result = Data()
        var index = 0
        let bufferSize = data.count
        var buffer = Data(repeating: 0, count: Codec.pageSize)
        
        let inputFilter = try InputFilter(.decompress, using: Codec.algorithm.appleAlgorithm) { length -> Data in
            let rangeLength = min(length, bufferSize - index)
            let startIndex = data.index(data.startIndex, offsetBy: index)
            let endIndex = data.index(startIndex, offsetBy: rangeLength)
            buffer.withUnsafeMutableBytes {
                index += data.copyBytes(to: $0, from: startIndex ..< endIndex)
            }
            
            return rangeLength == Codec.pageSize ? buffer : buffer.prefix(rangeLength)
        }
        
        while let page = try inputFilter.readData(ofLength: Codec.pageSize) {
            result.append(page)
        }
        return result
    }
}
#endif
