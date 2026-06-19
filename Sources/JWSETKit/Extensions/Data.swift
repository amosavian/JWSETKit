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
            data
        } else {
            Data(self)
        }
    }
    
    @inlinable
    func withUnsafeBuffer<R>(_ body: (_ buffer: UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try withContiguousStorageIfAvailable {
            try body(UnsafeRawBufferPointer($0))
        } ?? Data(self).withUnsafeBytes(body)
    }
}

extension ContiguousBytes {
    @usableFromInline
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}

extension [Data] {
    func joinedData(separator: Data) -> Data {
        switch count {
        case 0:
            return .init()
        case 1:
            return self[0]
        default:
            var result = Data(capacity: reduce(0) { $0 + $1.count } + separator.count * (count - 1))
            for (offset, part) in enumerated() {
                if offset > 0 {
                    result.append(separator)
                }
                result.append(part)
            }
            return result
        }
    }
}

infix operator =~=: ComparisonPrecedence

@inlinable
func =~= (_ lhs: some Collection<UInt8>, _ rhs: some Collection<UInt8>) -> Bool {
    guard lhs.count == rhs.count else {
        return false
    }
    
    return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
}
