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
        let data = Data(data)
        var result = Data()
        let outputFilter = try OutputFilter(.compress, using: Codec.algorithm.appleAlgorithm, writingTo: { data in
            if let data = data {
                result.append(data)
            }
        })
        
        var index = 0
        let bufferSize = data.count
        
        while true {
            let rangeLength = min(Codec.pageSize, bufferSize - index)
            
            let subdata = data.subdata(in: index ..< index + rangeLength)
            index += rangeLength
            
            try outputFilter.write(subdata)
            
            if rangeLength == 0 {
                break
            }
        }
        return result
    }
    
    public static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        let data = Data(data)
        var result = Data()
        var index = 0
        let bufferSize = data.count
        
        let inputFilter = try InputFilter(.decompress, using: Codec.algorithm.appleAlgorithm) { length -> Data in
            let rangeLength = min(length, bufferSize - index)
            let subdata = data.subdata(in: index ..< index + rangeLength)
            index += rangeLength
            
            return subdata
        }
        
        while let page = try inputFilter.readData(ofLength: Codec.pageSize) {
            result.append(page)
        }
        return result
    }
}
#endif
