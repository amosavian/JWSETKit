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

// Silence KeyPath concurrency-safe warning.
extension PartialKeyPath: @unchecked Sendable {}
