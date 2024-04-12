//
//  Data.swift
//
//
//  Created by Amir Abbas Mousavian on 4/10/24.
//

import Foundation

extension Data {
    init<T>(value: T) where T: FixedWidthInteger {
        var int = value
        self.init(bytes: &int, count: MemoryLayout<T>.size)
    }
}

extension DataProtocol {
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
