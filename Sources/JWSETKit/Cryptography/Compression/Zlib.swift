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

extension POSIXError {
    init(zlibStatus: Int32) {
        self = switch zlibStatus {
        case Z_ERRNO:
            POSIXError(.EIO, userInfo: [:])
        case Z_STREAM_ERROR,
            Z_DATA_ERROR,
        Z_VERSION_ERROR:
            POSIXError(.EINVAL, userInfo: [:])
        case Z_MEM_ERROR:
            POSIXError(.ENOMEM, userInfo: [:])
        case Z_BUF_ERROR:
            POSIXError(.ENOBUFS, userInfo: [:])
        default:
            POSIXError(.ECANCELED, userInfo: [:])
        }
    }
}

@discardableResult
private func zlibCall(_ handler: () -> Int32) throws -> Int32 {
    let status = handler()
    if status < Z_OK {
        throw POSIXError(zlibStatus: status)
    }
    return status
}


/// Compressor contain compress and decompress implementation using `Compression` framework.
struct ZlibCompressor<Codec>: JSONWebCompressor, Sendable where Codec: CompressionCodec {
    static func compress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var s = z_stream()
        try zlibCall {
            deflateInit2_(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        }
        defer { deflateEnd(&s) }
        let outBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Codec.pageSize)
        defer { outBuf.deallocate() }
        var compressed = Data()
        try data.withUnsafeBuffer { inBuf in
            s.next_in = .init(mutating: inBuf.baseAddress?.assumingMemoryBound(to: Bytef.self))
            s.avail_in = .init(inBuf.count)
            while s.avail_in > 0 {
                s.next_out = outBuf.baseAddress
                s.avail_out = uInt(outBuf.count)
                try zlibCall {
                    deflate(&s, Z_NO_FLUSH)
                }
                compressed.append(outBuf.baseAddress!, count: outBuf.count - Int(s.avail_out))
            }
        }
        outBuf.initialize(repeating: 0)
        var status = Z_OK
        while status != Z_STREAM_END {
            s.next_out = outBuf.baseAddress
            s.avail_out = .init(outBuf.count)
            status = try zlibCall {
                deflate(&s, Z_FINISH)
            }
            compressed.append(outBuf.baseAddress!, count: outBuf.count - Int(s.avail_out))
        }
        return compressed
    }
    
    static func decompress<D>(_ data: D) throws -> Data where D: DataProtocol {
        var s = z_stream()
        try zlibCall {
            inflateInit2_(&s, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
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
                try zlibCall {
                    inflate(&s, Z_NO_FLUSH)
                }
                decompressed.append(outBuf.baseAddress!, count: outBuf.count - Int(s.avail_out))
            } while s.avail_out == 0
        }
        return decompressed
    }
}
#endif
