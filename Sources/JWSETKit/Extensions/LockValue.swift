//
//  LockValue.swift
//
//
//  Created by Amir Abbas Mousavian on 4/29/24.
//

import Collections
#if canImport(FoundationEssentials)
import FoundationEssentials
#if canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
import WinSDK
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Bionic)
import Bionic
#elseif canImport(WASILibc)
import WASILibc
#if canImport(pthread)
import pthread
#endif
#else
#error("Unable to identify your C library.")
#endif
#else
import Foundation
#endif

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

public protocol Locking<Context, Value>: Sendable {
    associatedtype Context
    associatedtype Value
    
    init(initialValue: consuming Value)
    func withLock<R>(_ context: Context, _ handler: (inout Value) throws -> R) rethrows -> R
    func withLockIfAvailable<R>(_ context: Context, _ handler: (inout Value) throws -> R) rethrows -> R?
}

#if canImport(pthread)
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

public final class PthreadReadWriteLock<Value>: Locking, @unchecked Sendable {
    @usableFromInline
    let lock: UnsafeMutablePointer<pthread_rwlock_t>
    
    private var value: Value
    
    public init(initialValue: consuming Value) {
        self.lock = .allocate(capacity: 1)
        self.value = initialValue
        lock.initialize(to: pthread_rwlock_t())
        pthread_rwlock_init(lock, nil)
    }
    
    deinit {
        pthread_rwlock_destroy(lock)
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    @inlinable
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
            throw POSIXError(POSIXError.Code(rawValue: result) ?? .ECANCELED, userInfo: [:])
        }
    }
    
    @inlinable
    public func unlock() {
        pthread_rwlock_unlock(lock)
    }
    
    public func withLock<R>(_ context: PthreadReadWriteContextLock, _ handler: (inout Value) throws -> R) rethrows -> R {
        try? lock(context)
        defer { unlock() }
        return try handler(&value)
    }
    
    public func withLockIfAvailable<R>(_ context: PthreadReadWriteContextLock, _ handler: (inout Value) throws -> R) rethrows -> R? {
        guard tryLock(context) else { return nil }
        defer { unlock() }
        return try handler(&value)
    }
}

public typealias PthreadReadWriteLockedValue<Value> = LockedValue<PthreadReadWriteContextLock, Value, PthreadReadWriteLock<Value>>
#endif

#if canImport(Darwin)
public final class OSUnfairLock<Value>: Locking, @unchecked Sendable {
    @usableFromInline
    let lock: os_unfair_lock_t
    
    private var value: Value
    
    public init(initialValue: consuming Value) {
        self.lock = .allocate(capacity: 1)
        self.value = initialValue
        lock.initialize(to: os_unfair_lock())
    }
    
    deinit {
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    @inlinable
    public func tryLock(_: LockContextEmpty) -> Bool {
        os_unfair_lock_trylock(lock)
    }
    
    @inlinable
    public func lock(_: LockContextEmpty) {
        os_unfair_lock_lock(lock)
    }
    
    @inlinable
    public func unlock() {
        os_unfair_lock_unlock(lock)
    }
    
    public func withLock<R>(_ context: LockContextEmpty, _ handler: (inout Value) throws -> R) rethrows -> R {
        lock(context)
        defer { unlock() }
        return try handler(&value)
    }
    
    public func withLockIfAvailable<R>(_ context: LockContextEmpty, _ handler: (inout Value) throws -> R) rethrows -> R? {
        guard tryLock(context) else { return nil }
        defer { unlock() }
        return try handler(&value)
    }
}

public typealias OSUnfairLockedValue<Value> = LockedValue<LockContextEmpty, Value, OSUnfairLock<Value>>
#endif

#if canImport(pthread)
public final class PthreadMutex<Value>: Locking, @unchecked Sendable {
    @usableFromInline
    let lock: UnsafeMutablePointer<pthread_mutex_t>
    
    private var value: Value

    public init(initialValue: consuming Value) {
        self.lock = .allocate(capacity: 1)
        self.value = initialValue
        lock.initialize(to: pthread_mutex_t())
        pthread_mutex_init(lock, nil)
    }
    
    deinit {
        pthread_mutex_destroy(lock)
        lock.deinitialize(count: 1)
        lock.deallocate()
    }
    
    @inlinable
    public func tryLock(_: LockContextEmpty) -> Bool {
        pthread_mutex_trylock(lock) == 0
    }
    
    @inlinable
    public func lock(_: LockContextEmpty) {
        pthread_mutex_lock(lock)
    }
    
    @inlinable
    public func unlock() {
        pthread_mutex_unlock(lock)
    }
    
    public func withLock<R>(_ context: LockContextEmpty, _ handler: (inout Value) throws -> R) rethrows -> R {
        lock(context)
        defer { unlock() }
        return try handler(&value)
    }
    
    public func withLockIfAvailable<R>(_ context: LockContextEmpty, _ handler: (inout Value) throws -> R) rethrows -> R? {
        guard tryLock(context) else { return nil }
        defer { unlock() }
        return try handler(&value)
    }
}

public typealias PthreadMutexLockedValue<Value> = LockedValue<LockContextEmpty, Value, PthreadMutex<Value>>
#else
public final class SingleThreadLock<Value>: Locking, @unchecked Sendable {
    private var value: Value

    public init(initialValue: consuming Value) {
        self.value = initialValue
    }
    
    @inlinable
    public func tryLock(_: LockContextEmpty) -> Bool {
        true
    }
    
    @inlinable
    public func lock(_: LockContextEmpty) {
        // No lock is needed
    }
    
    @inlinable
    public func unlock() {
        // No lock is needed
    }
    
    public func withLock<R>(_ context: LockContextEmpty, _ handler: (inout Value) throws -> R) rethrows -> R {
        lock(context)
        defer { unlock() }
        return try handler(&value)
    }
    
    public func withLockIfAvailable<R>(_ context: LockContextEmpty, _ handler: (inout Value) throws -> R) rethrows -> R? {
        guard tryLock(context) else { return nil }
        defer { unlock() }
        return try handler(&value)
    }
}
#endif

#if canImport(pthread)
public typealias AtomicValue = PthreadReadWriteLockedValue
#else
public typealias AtomicValue<Value> = LockedValue<LockContextEmpty, Value, SingleThreadLock<Value>>
#endif

/// Synchronizing read and writes on a shared mutable property.
@dynamicMemberLookup
public final class LockedValue<Context, Value, Lock: Locking<Context, Value>>: @unchecked Sendable where Context: ReadWriteLockContext {
    private let lock: Lock
    
    public init(wrappedValue: consuming Value) {
        self.lock = .init(initialValue: wrappedValue)
    }
    
    public var wrappedValue: Value {
        get {
            lock.withLock(.getContext) { value in
                value
            }
        }
        set {
            lock.withLock(.setContext) { value in
                value = newValue
            }
        }
    }
    
    @inlinable
    public subscript<U>(dynamicMember keyPath: SendableKeyPath<Value, U>) -> U {
        wrappedValue[keyPath: keyPath]
    }
    
    @inlinable
    public subscript<U>(dynamicMember keyPath: SendableWritableKeyPath<Value, U>) -> U {
        get {
            wrappedValue[keyPath: keyPath]
        }
        set {
            wrappedValue[keyPath: keyPath] = newValue
        }
    }
    
    public func withLock<R>(_ context: Context, _ handler: (_ value: inout Value) throws -> R) throws -> R {
        try lock.withLock(context, handler)
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
extension OrderedDictionary: DictionaryInitialzable {}

extension LockedValue: ExpressibleByDictionaryLiteral where Value: ExpressibleByDictionaryLiteral & DictionaryInitialzable, Value.Key: Hashable {
    @inlinable
    public convenience init(dictionaryLiteral elements: (Value.Key, Value.Value)...) {
        let elements = elements.map { ($0, $1) }
        self.init(wrappedValue: Value(uniqueKeysWithValues: elements))
    }
}
