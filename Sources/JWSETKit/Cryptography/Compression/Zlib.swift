//
//  Zlib.swift
//
//
//  Created by Amir Abbas Mousavian on 5/1/24.
//

#if canImport(Czlib)
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#if canImport(Czlib)
import Czlib
#elseif canImport(zlib)
import zlib
#endif

struct CompressionError: RawRepresentable, Error {
    var rawValue: Int32
    
    init(rawValue: Int32) {
        self.rawValue = rawValue
    }
    
    static let streamError = Self(rawValue: Z_STREAM_ERROR)
    static let dataError = Self(rawValue: Z_DATA_ERROR)
    static let memoryError = Self(rawValue: Z_MEM_ERROR)
    static let bufferError = Self(rawValue: Z_BUF_ERROR)
    static let versionError = Self(rawValue: Z_VERSION_ERROR)
}

/// Compressor contain compress and decompress implementation using `Compression` framework.
struct ZlibCompressor<Codec>: JSONWebCompressor, Sendable where Codec: CompressionCodec {
    static func compress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var s = z_stream()
        let status = deflateInit2_(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard status == Z_OK else {
            throw CompressionError(rawValue: status)
        }
        defer { deflateEnd(&s) }

        var compressed = Data()
        try data.withUnsafeBuffer { inBuf in
            s.next_in = .init(mutating: inBuf.baseAddress?.assumingMemoryBound(to: Bytef.self))
            s.avail_in = uInt(inBuf.count)
            let outBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Codec.pageSize)
            defer { outBuf.deallocate() }
            while s.avail_in > 0 {
                s.next_out = outBuf.baseAddress
                s.avail_out = uInt(outBuf.count)
                let status = deflate(&s, Z_NO_FLUSH)
                if status != Z_OK {
                    throw CompressionError(rawValue: status)
                }
                compressed.append(outBuf.baseAddress!, count: outBuf.count - Int(s.avail_out))
            }
        }
        let outBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Codec.pageSize)
        defer { outBuf.deallocate() }
        while true {
            s.next_out = outBuf.baseAddress
            s.avail_out = uInt(outBuf.count)
            let status = deflate(&s, Z_FINISH)
            compressed.append(outBuf.baseAddress!, count: outBuf.count - Int(s.avail_out))
            if status == Z_STREAM_END { break }
            if status != Z_OK {
                throw CompressionError(rawValue: status)
            }
        }
        return compressed
    }
    
    static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var s = z_stream()
        let status = inflateInit2_(&s, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard status == Z_OK else {
            throw CompressionError(rawValue: status)
        }
        defer { inflateEnd(&s) }

        var decompressed = Data()
        try data.withUnsafeBuffer { inBuf in
            s.next_in = .init(mutating: inBuf.baseAddress?.assumingMemoryBound(to: Bytef.self))
            s.avail_in = uInt(inBuf.count)
            let outBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Codec.pageSize)
            defer { outBuf.deallocate() }
            repeat {
                s.next_out = outBuf.baseAddress
                s.avail_out = uInt(outBuf.count)
                let status = inflate(&s, Z_NO_FLUSH)
                if status != Z_OK && status != Z_STREAM_END {
                    throw CompressionError(rawValue: status)
                }
                decompressed.append(outBuf.baseAddress!, count: outBuf.count - Int(s.avail_out))
            } while s.avail_out == 0
        }
        return decompressed
    }
}
#endif
