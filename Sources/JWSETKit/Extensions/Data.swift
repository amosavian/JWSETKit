//
//  Data.swift
//
//
//  Created by Amir Abbas Mousavian on 4/10/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if swift(<6.2)
typealias SendableMetatype = Any
#endif

extension Data {
    init<T>(value: T) where T: FixedWidthInteger {
        var int = value
        self.init(bytes: &int, count: MemoryLayout<T>.size)
    }
    
    static func random(length: Int) -> Data {
        Data((0 ..< length).map { _ in UInt8.random(in: 0 ... 255) })
    }
}

extension DataProtocol {
    @inlinable
    var asContiguousBytes: any ContiguousBytes {
        if regions.count == 1, let data = regions.first {
            return data
        } else {
            return Data(self)
        }
    }
    
    @inlinable
    func withUnsafeBuffer<R>(_ body: (_ buffer: UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try withContiguousStorageIfAvailable {
            try body(UnsafeRawBufferPointer($0))
        } ?? Data(self).withUnsafeBytes(body)
    }
}

extension UnsafeMutableBufferPointer {
    fileprivate func copy<R: RangeExpression, D: DataProtocol>(from data: D, in range: R) -> Int where R.Bound == Int {
        data.copyBytes(to: UnsafeMutableBufferPointer(rebasing: self[range]))
    }
}

extension ContiguousBytes {
    mutating func setBytes<D: DataProtocol>(_ bytes: D) {
        withUnsafeBytes { buffer in
            UnsafeMutableRawBufferPointer(mutating: buffer).copyBytes(from: bytes.prefix(buffer.count))
        }
    }
}

extension [Data] {
    func joinedString(separator: Data) -> String {
        switch count {
        case 0:
            return ""
        case 1:
            return String(decoding: self[0], as: UTF8.self)
        default:
            let capacity = reduce(0) { $0 + $1.count } + (separator.count) * count
            return .init(unsafeUninitializedCapacity: capacity) { buffer in
                var index = 0
                for part in self {
                    index += buffer.copy(from: part, in: index...)
                    index += buffer.copy(from: separator, in: index...)
                }
                return index - separator.count
            }
        }
    }
}

infix operator =~=: ComparisonPrecedence

@inlinable
func =~= <LHS: Collection, RHS: Collection>(_ lhs: LHS, _ rhs: RHS) -> Bool where LHS.Element == UInt8, RHS.Element == UInt8 {
    guard lhs.count == rhs.count else {
        return false
    }

    return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
}
