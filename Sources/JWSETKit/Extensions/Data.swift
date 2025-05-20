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

infix operator =~=: ComparisonPrecedence

@inlinable
func =~= <LHS: Collection, RHS: Collection>(_ lhs: LHS, _ rhs: RHS) -> Bool where LHS.Element == UInt8, RHS.Element == UInt8 {
    guard lhs.count == rhs.count else {
        return false
    }

    return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
}
