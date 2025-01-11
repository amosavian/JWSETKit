//
//  LockValue.swift
//
//
//  Created by Amir Abbas Mousavian on 4/29/24.
//

import Foundation

public protocol ReadWriteLockContext {
    static var getContext: Self { get }
    static var setContext: Self { get }
}

@frozen
public struct LockContextEmpty: ReadWriteLockContext {
    public static var getContext: LockContextEmpty {
        LockContextEmpty()
    }
    
    public static var setContext: LockContextEmpty {
        LockContextEmpty()
    }
}

public protocol Locking<Context>: Sendable {
    associatedtype Context
    
    init()
    func tryLock(_ context: Context) -> Bool
    func lock(_ context: Context) throws
    func unlock()
}

extension Locking {
    @inlinable
    public func withLock<R>(_ context: Context, _ handler: () throws -> R) throws -> R {
        try lock(context)
        defer { unlock() }
        return try handler()
    }
}

@frozen
public enum PthreadReadWriteContextLock: ReadWriteLockContext {
    case read
    case write
    
    @inlinable
    public static var getContext: PthreadReadWriteContextLock {
        .read
    }
    
    @inlinable
    public static var setContext: PthreadReadWriteContextLock {
        .write
    }
}

public final class PthreadReadWriteLock: Locking, @unchecked Sendable {
    private let lock: UnsafeMutablePointer<pthread_rwlock_t>
    
    public init() {
        self.lock = .allocate(capacity: 1)
        lock.initialize(to: pthread_rwlock_t())
        pthread_rwlock_init(lock, nil)
    }

    deinit {
        pthread_rwlock_destroy(lock)
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    public func tryLock(_ context: PthreadReadWriteContextLock) -> Bool {
        switch context {
        case .read:
            return pthread_rwlock_tryrdlock(lock) == 0
        case .write:
            return pthread_rwlock_trywrlock(lock) == 0
        }
    }
    
    public func lock(_ context: PthreadReadWriteContextLock) throws {
        let result: Int32
        switch context {
        case .read:
            result = pthread_rwlock_rdlock(lock)
        case .write:
            result = pthread_rwlock_wrlock(lock)
        }
        if result != 0 {
#if canImport(Darwin)
            throw POSIXError(.init(rawValue: result) ?? .ELAST)
#else
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(result))
#endif
        }
    }
    
    public func unlock() {
        pthread_rwlock_unlock(lock)
    }
}

public typealias PthreadReadWriteLockedValue<Value> = LockedValue<PthreadReadWriteContextLock, PthreadReadWriteLock, Value>

#if canImport(Darwin)
public final class OSUnfairLock: Locking, @unchecked Sendable {
    private let lock: os_unfair_lock_t
    
    public init() {
        self.lock = .allocate(capacity: 1)
        lock.initialize(to: os_unfair_lock())
    }

    deinit {
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    public func tryLock(_: LockContextEmpty) -> Bool {
        os_unfair_lock_trylock(lock)
    }
    
    public func lock(_: LockContextEmpty) {
        os_unfair_lock_lock(lock)
    }
    
    public func unlock() {
        os_unfair_lock_unlock(lock)
    }
}

public typealias OSUnfairLockedValue<Value> = LockedValue<LockContextEmpty, OSUnfairLock, Value>
#endif

public final class PthreadMutex: Locking, @unchecked Sendable {
    private let lock: UnsafeMutablePointer<pthread_mutex_t>
    
    public init() {
        self.lock = .allocate(capacity: 1)
        lock.initialize(to: pthread_mutex_t())
        pthread_mutex_init(lock, nil)
    }

    deinit {
        pthread_mutex_destroy(lock)
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    public func tryLock(_: LockContextEmpty) -> Bool {
        pthread_mutex_trylock(lock) == 0
    }
    
    public func lock(_: LockContextEmpty) {
        pthread_mutex_lock(lock)
    }
    
    public func unlock() {
        pthread_mutex_unlock(lock)
    }
}

public typealias PthreadMutexLockedValue<Value> = LockedValue<LockContextEmpty, PthreadMutex, Value>

/// Synchronizing read and writes on a shared mutable property.
@dynamicMemberLookup
public final class LockedValue<Context, Lock: Locking<Context>, Value>: @unchecked Sendable where Context: ReadWriteLockContext {
    private let lock = Lock()
    
    private var value: Value
    
    public var wrappedValue: Value {
        get {
            (try? lock.withLock(.getContext) {
                value
            }) ?? value
        }
        set {
            try? lock.withLock(.setContext) {
                value = newValue
            }
        }
    }
    
    public init(wrappedValue: Value) {
        self.value = wrappedValue
    }
    
    @inlinable
    public subscript<U>(dynamicMember keyPath: KeyPath<Value, U>) -> U {
        wrappedValue[keyPath: keyPath]
    }
    
    @inlinable
    public subscript<U>(dynamicMember keyPath: WritableKeyPath<Value, U>) -> U {
        get {
            wrappedValue[keyPath: keyPath]
        }
        set {
            wrappedValue[keyPath: keyPath] = newValue
        }
    }
    
    public func withLock<R>(_ context: Context, _ handler: (_ value: inout Value) throws -> R) throws -> R {
        try lock.withLock(context) {
            try handler(&value)
        }
    }
}

extension LockedValue: Equatable where Value: Equatable {
    @inlinable
    public static func == (lhs: LockedValue, rhs: LockedValue) -> Bool {
        lhs.wrappedValue == rhs.wrappedValue
    }
}

extension LockedValue: Comparable where Value: Comparable {
    @inlinable
    public static func < (lhs: LockedValue, rhs: LockedValue) -> Bool {
        lhs.wrappedValue < rhs.wrappedValue
    }
}

extension LockedValue: Hashable where Value: Hashable {
    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(wrappedValue)
    }
}

extension LockedValue: Sequence where Value: Sequence {
    @inlinable
    public func makeIterator() -> Value.Iterator {
        wrappedValue.makeIterator()
    }
    
    @inlinable
    public var underestimatedCounValue: Int {
        wrappedValue.underestimatedCount
    }
    
    @inlinable
    public func withContiguousStorageIfAvailable<R>(_ body: (UnsafeBufferPointer<Value.Element>) throws -> R) rethrows -> R? {
        try wrappedValue.withContiguousStorageIfAvailable(body)
    }
}

extension LockedValue: Collection where Value: Collection {
    @inlinable
    public func index(after i: Value.Index) -> Value.Index {
        wrappedValue.index(after: i)
    }
    
    @inlinable
    public var startIndex: Value.Index {
        wrappedValue.startIndex
    }
    
    @inlinable
    public var endIndex: Value.Index {
        wrappedValue.endIndex
    }
    
    @inlinable
    public subscript(position: Value.Index) -> Value.Element {
        wrappedValue[position]
    }
    
    @inlinable
    public subscript(bounds: Range<Value.Index>) -> Value.SubSequence {
        wrappedValue[bounds]
    }
}

extension LockedValue: MutableCollection where Value: MutableCollection {
    @inlinable
    public subscript(position: Value.Index) -> Value.Element {
        get {
            wrappedValue[position]
        }
        set {
            wrappedValue[position] = newValue
        }
    }
    
    @inlinable
    public subscript(bounds: Range<Value.Index>) -> Value.SubSequence {
        get {
            wrappedValue[bounds]
        }
        set {
            wrappedValue[bounds] = newValue
        }
    }
}

extension LockedValue: RangeReplaceableCollection where Value: RangeReplaceableCollection {
    @inlinable
    public convenience init() {
        self.init(wrappedValue: Value())
    }
    
    @inlinable
    public convenience init<S>(_ elements: S) where S: Sequence, Value.Element == S.Element {
        self.init(wrappedValue: Value(elements))
    }
    
    @inlinable
    public convenience init(repeating repeatedValue: Value.Element, count: Int) {
        self.init(wrappedValue: Value(repeating: repeatedValue, count: count))
    }
    
    @inlinable
    public func reserveCapacity(_ n: Int) {
        wrappedValue.reserveCapacity(n)
    }
    
    @inlinable
    public func replaceSubrange<C>(_ subrange: Range<Value.Index>, with newElements: C) where C: Collection, Value.Element == C.Element {
        wrappedValue.replaceSubrange(subrange, with: newElements)
    }
    
    @inlinable
    public func append(_ newElement: Value.Element) {
        wrappedValue.append(newElement)
    }
    
    @inlinable
    public func append<S>(contentsOf newElements: S) where S: Sequence, Value.Element == S.Element {
        wrappedValue.append(contentsOf: newElements)
    }
    
    @inlinable
    public func insert(_ newElement: Value.Element, at i: Value.Index) {
        wrappedValue.insert(newElement, at: i)
    }
    
    @inlinable
    public func insert<S>(contentsOf newElements: S, at i: Value.Index) where S: Collection, Value.Element == S.Element {
        wrappedValue.insert(contentsOf: newElements, at: i)
    }
    
    @inlinable
    public func removeSubrange(_ bounds: Range<Value.Index>) {
        wrappedValue.removeSubrange(bounds)
    }
    
    @inlinable
    public func remove(at i: Value.Index) -> Value.Element {
        wrappedValue.remove(at: i)
    }
    
    @inlinable
    public func removeFirst() -> Value.Element {
        wrappedValue.removeFirst()
    }
    
    @inlinable
    public func removeFirst(_ k: Int) {
        wrappedValue.removeFirst(k)
    }
    
    @inlinable
    public func removeAll(where shouldBeRemoved: (Value.Element) throws -> Bool) rethrows {
        try wrappedValue.removeAll(where: shouldBeRemoved)
    }
    
    @inlinable
    public func removeAll(keepingCapacity keepCapacity: Bool) {
        wrappedValue.removeAll(keepingCapacity: keepCapacity)
    }
}

extension LockedValue: BidirectionalCollection where Value: BidirectionalCollection {
    @inlinable
    public func index(before i: Value.Index) -> Value.Index {
        wrappedValue.index(before: i)
    }
}

extension LockedValue: RandomAccessCollection where Value: RandomAccessCollection {}

extension LockedValue: LazySequenceProtocol where Value: LazySequenceProtocol {}

extension LockedValue: LazyCollectionProtocol where Value: LazyCollectionProtocol {}

extension LockedValue: ExpressibleByNilLiteral where Value: ExpressibleByNilLiteral {
    @inlinable
    public convenience init(nilLiteral _: ()) {
        self.init(wrappedValue: nil)
    }
}

extension LockedValue: ExpressibleByArrayLiteral where Value: ExpressibleByArrayLiteral & RangeReplaceableCollection {
    @inlinable
    public convenience init(arrayLiteral elements: Value.Element...) {
        self.init(wrappedValue: Value(elements))
    }
}

extension LockedValue: ExpressibleByFloatLiteral where Value: ExpressibleByFloatLiteral {
    @inlinable
    public convenience init(floatLiteral value: Value.FloatLiteralType) {
        self.init(wrappedValue: Value(floatLiteral: value))
    }
}

extension LockedValue: ExpressibleByIntegerLiteral where Value: ExpressibleByIntegerLiteral {
    @inlinable
    public convenience init(integerLiteral value: Value.IntegerLiteralType) {
        self.init(wrappedValue: Value(integerLiteral: value))
    }
}

extension LockedValue: ExpressibleByUnicodeScalarLiteral where Value: ExpressibleByUnicodeScalarLiteral {
    @inlinable
    public convenience init(unicodeScalarLiteral value: Value.UnicodeScalarLiteralType) {
        self.init(wrappedValue: Value(unicodeScalarLiteral: value))
    }
}

extension LockedValue: ExpressibleByExtendedGraphemeClusterLiteral where Value: ExpressibleByExtendedGraphemeClusterLiteral {
    @inlinable
    public convenience init(extendedGraphemeClusterLiteral value: Value.ExtendedGraphemeClusterLiteralType) {
        self.init(wrappedValue: Value(extendedGraphemeClusterLiteral: value))
    }
}

extension LockedValue: ExpressibleByStringLiteral where Value: ExpressibleByStringLiteral {
    @inlinable
    public convenience init(stringLiteral value: Value.StringLiteralType) {
        self.init(wrappedValue: Value(stringLiteral: value))
    }
}

extension LockedValue: ExpressibleByStringInterpolation where Value: ExpressibleByStringInterpolation {
    @inlinable
    public convenience init(stringInterpolation: Value.StringInterpolation) {
        self.init(wrappedValue: Value(stringInterpolation: stringInterpolation))
    }
}

extension LockedValue: ExpressibleByBooleanLiteral where Value: ExpressibleByBooleanLiteral {
    @inlinable
    public convenience init(booleanLiteral value: Value.BooleanLiteralType) {
        self.init(wrappedValue: Value(booleanLiteral: value))
    }
}

public protocol DictionaryInitialzable: ExpressibleByDictionaryLiteral {
    init<S>(uniqueKeysWithValues keysAndValues: S) where S: Sequence, S.Element == (Key, Value)
}

extension Dictionary: DictionaryInitialzable {}

extension LockedValue: ExpressibleByDictionaryLiteral where Value: ExpressibleByDictionaryLiteral & DictionaryInitialzable, Value.Key: Hashable {
    @inlinable
    public convenience init(dictionaryLiteral elements: (Value.Key, Value.Value)...) {
        let elements = elements.map { ($0, $1) }
        self.init(wrappedValue: Value(uniqueKeysWithValues: elements))
    }
}

extension Swift.AnyKeyPath: @unchecked Swift.Sendable {}
