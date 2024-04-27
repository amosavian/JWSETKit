//
//  Lock.swift
//
//
//  Created by Amir Abbas Mousavian on 10/27/23.
//

import Foundation

final class ReadWriteLock: @unchecked Sendable {
    private let lock: UnsafeMutablePointer<pthread_rwlock_t>
    
    init() {
        self.lock = .allocate(capacity: 1)
        lock.initialize(to: pthread_rwlock_t())
        pthread_rwlock_init(lock, nil)
    }

    deinit {
        pthread_rwlock_destroy(lock)
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    enum LockType {
        case read, write
    }
    
    func lock(_ type: LockType) {
        switch type {
        case .read:
            pthread_rwlock_rdlock(lock)
        case .write:
            pthread_rwlock_wrlock(lock)
        }
    }
    
    func unlock() {
        pthread_rwlock_unlock(lock)
    }
    
    @discardableResult
    func withReadLock<R>(_ handler: () throws -> R) rethrows -> R {
        lock(.read)
        defer { unlock() }
        return try handler()
    }
    
    @discardableResult
    func withWriteLock<R>(_ handler: () throws -> R) rethrows -> R {
        lock(.write)
        defer { unlock() }
        return try handler()
    }
}

/// Synchronizing read and writes on a shared mutable property.
@dynamicMemberLookup
final class ReadWriteLockedValue<T>: @unchecked Sendable {
    private let lock = ReadWriteLock()
    private var _value: T
    
    var wrappedValue: T {
        get {
            lock.withReadLock { _value }
        }
        set {
            lock.withWriteLock { _value = newValue }
        }
    }

    init(wrappedValue: T) {
        lock.lock(.write)
        defer { lock.unlock() }
        self._value = wrappedValue
    }
    
    convenience init(_ wrappedValue: T) {
        self.init(wrappedValue: wrappedValue)
    }
    
    subscript<U>(dynamicMember keyPath: KeyPath<T, U>) -> U {
        wrappedValue[keyPath: keyPath]
    }
    
    subscript<U>(dynamicMember keyPath: WritableKeyPath<T, U>) -> U {
        get {
            wrappedValue[keyPath: keyPath]
        }
        set {
            wrappedValue[keyPath: keyPath] = newValue
        }
    }
}

extension ReadWriteLockedValue: Equatable where T: Equatable {
    static func == (lhs: ReadWriteLockedValue, rhs: ReadWriteLockedValue) -> Bool {
        lhs.wrappedValue == rhs.wrappedValue
    }
}

extension ReadWriteLockedValue: Hashable where T: Hashable {
    func hash(into hasher: inout Hasher) {
        hasher.combine(wrappedValue)
    }
}

extension ReadWriteLockedValue: Sequence where T: Sequence {
    func makeIterator() -> T.Iterator {
        wrappedValue.makeIterator()
    }
}

extension ReadWriteLockedValue: Collection where T: Collection {
    func index(after i: T.Index) -> T.Index {
        wrappedValue.index(after: i)
    }
    
    var startIndex: T.Index {
        wrappedValue.startIndex
    }
    
    var endIndex: T.Index {
        wrappedValue.endIndex
    }
    
    subscript(position: T.Index) -> T.Element {
        wrappedValue[position]
    }
    
    subscript(bounds: Range<T.Index>) -> T.SubSequence {
        wrappedValue[bounds]
    }
}

extension ReadWriteLockedValue: MutableCollection where T: MutableCollection {
    subscript(position: T.Index) -> T.Element {
        get {
            wrappedValue[position]
        }
        set {
            wrappedValue[position] = newValue
        }
    }
    
    subscript(bounds: Range<T.Index>) -> T.SubSequence {
        get {
            wrappedValue[bounds]
        }
        set {
            wrappedValue[bounds] = newValue
        }
    }
}

extension ReadWriteLockedValue: RangeReplaceableCollection where T: RangeReplaceableCollection {
    convenience init() {
        self.init(wrappedValue: T())
    }
    
    convenience init<S>(_ elements: S) where S : Sequence, T.Element == S.Element {
        self.init(wrappedValue: T(elements))
    }
    
    convenience init(repeating repeatedValue: T.Element, count: Int) {
        self.init(wrappedValue: T(repeating: repeatedValue, count: count))
    }
    
    func reserveCapacity(_ n: Int) {
        wrappedValue.reserveCapacity(n)
    }
    
    func replaceSubrange<C>(_ subrange: Range<T.Index>, with newElements: C) where C : Collection, T.Element == C.Element {
        wrappedValue.replaceSubrange(subrange, with: newElements)
    }
    
    func append(_ newElement: T.Element) {
        wrappedValue.append(newElement)
    }
    
    func append<S>(contentsOf newElements: S) where S : Sequence, T.Element == S.Element {
        wrappedValue.append(contentsOf: newElements)
    }
    
    func insert(_ newElement: T.Element, at i: T.Index) {
        wrappedValue.insert(newElement, at: i)
    }
    
    func insert<S>(contentsOf newElements: S, at i: T.Index) where S : Collection, T.Element == S.Element {
        wrappedValue.insert(contentsOf: newElements, at: i)
    }
    
    func removeSubrange(_ bounds: Range<T.Index>) {
        wrappedValue.removeSubrange(bounds)
    }
    
    func remove(at i: T.Index) -> T.Element {
        wrappedValue.remove(at: i)
    }
    
    func removeFirst() -> T.Element {
        wrappedValue.removeFirst()
    }
    
    func removeFirst(_ k: Int) {
        wrappedValue.removeFirst(k)
    }
    
    func removeAll(where shouldBeRemoved: (T.Element) throws -> Bool) rethrows {
        try wrappedValue.removeAll(where: shouldBeRemoved)
    }
    
    func removeAll(keepingCapacity keepCapacity: Bool) {
        wrappedValue.removeAll(keepingCapacity: keepCapacity)
    }
}

extension ReadWriteLockedValue: BidirectionalCollection where T: BidirectionalCollection {
    func index(before i: T.Index) -> T.Index {
        wrappedValue.index(before: i)
    }
}

extension ReadWriteLockedValue: RandomAccessCollection where T: RandomAccessCollection {}

extension ReadWriteLockedValue: LazySequenceProtocol where T: LazySequenceProtocol {}

extension ReadWriteLockedValue: LazyCollectionProtocol where T: LazyCollectionProtocol {}

extension ReadWriteLockedValue: ExpressibleByNilLiteral where T: ExpressibleByNilLiteral {
    convenience init(nilLiteral: ()) {
        self.init(wrappedValue: nil)
    }
}

extension ReadWriteLockedValue: ExpressibleByArrayLiteral where T: ExpressibleByArrayLiteral & RangeReplaceableCollection {
    convenience init(arrayLiteral elements: T.Element...) {
        self.init(wrappedValue: T(elements))
    }
}

extension ReadWriteLockedValue: ExpressibleByFloatLiteral where T: ExpressibleByFloatLiteral {
    convenience init(floatLiteral value: T.FloatLiteralType) {
        self.init(wrappedValue: T(floatLiteral: value))
    }
}

extension ReadWriteLockedValue: ExpressibleByIntegerLiteral where T: ExpressibleByIntegerLiteral {
    convenience init(integerLiteral value: T.IntegerLiteralType) {
        self.init(wrappedValue: T(integerLiteral: value))
    }
}

extension ReadWriteLockedValue: ExpressibleByUnicodeScalarLiteral where T: ExpressibleByUnicodeScalarLiteral {
    convenience init(unicodeScalarLiteral value: T.UnicodeScalarLiteralType) {
        self.init(wrappedValue: T(unicodeScalarLiteral: value))
    }
}

extension ReadWriteLockedValue: ExpressibleByExtendedGraphemeClusterLiteral where T: ExpressibleByExtendedGraphemeClusterLiteral {
    convenience init(extendedGraphemeClusterLiteral value: T.ExtendedGraphemeClusterLiteralType) {
        self.init(wrappedValue: T(extendedGraphemeClusterLiteral: value))
    }
}

extension ReadWriteLockedValue: ExpressibleByStringLiteral where T: ExpressibleByStringLiteral {
    convenience init(stringLiteral value: T.StringLiteralType) {
        self.init(wrappedValue: T(stringLiteral: value))
    }
}

extension ReadWriteLockedValue: ExpressibleByStringInterpolation where T: ExpressibleByStringInterpolation {
    convenience init(stringInterpolation: T.StringInterpolation) {
        self.init(wrappedValue: T(stringInterpolation: stringInterpolation))
    }
}

extension ReadWriteLockedValue: ExpressibleByBooleanLiteral where T: ExpressibleByBooleanLiteral {
    convenience init(booleanLiteral value: T.BooleanLiteralType) {
        self.init(wrappedValue: T(booleanLiteral: value))
    }
}

protocol DictionaryInitialzable: ExpressibleByDictionaryLiteral {
    init(elements: [(Key, Value)])
}

extension Dictionary: DictionaryInitialzable {
    init(elements: [(Key, Value)]) {
        self.init(uniqueKeysWithValues: elements)
    }
}

extension ReadWriteLockedValue: ExpressibleByDictionaryLiteral where T: ExpressibleByDictionaryLiteral & DictionaryInitialzable, T.Key: Hashable {
    convenience init(dictionaryLiteral elements: (T.Key, T.Value)...) {
        let elements = elements.map { ($0, $1) }
        self.init(wrappedValue: T(elements: elements))
    }
}

// Silence KeyPath concurrency-safe warning.
extension PartialKeyPath: @unchecked Sendable {}
