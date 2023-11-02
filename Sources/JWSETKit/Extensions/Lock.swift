//
//  Lock.swift
//
//
//  Created by Amir Abbas Mousavian on 10/27/23.
//

import Foundation

final class ReadWriteLock: Sendable {
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
    
    @discardableResult
    func withReadLock<R>(_ handler: () throws -> R) rethrows -> R {
        pthread_rwlock_rdlock(lock)
        defer { pthread_rwlock_unlock(lock) }
        return try handler()
    }
    
    @discardableResult
    func withWriteLock<R>(_ handler: () throws -> R) rethrows -> R {
        pthread_rwlock_wrlock(lock)
        defer { pthread_rwlock_unlock(lock) }
        return try handler()
    }
}

/// Synchronizing read and writes on a shared mutable property.
@propertyWrapper
public struct ReadWriteLocked<T> {
    private let lock = ReadWriteLock()
    private var _value: T
    
    public var wrappedValue: T {
        get {
            lock.withReadLock { _value }
        }
        set {
            lock.withWriteLock { _value = newValue }
        }
    }

    public init(wrappedValue: T) {
        self._value = wrappedValue
    }
}

extension ReadWriteLocked: Sendable where T: Sendable {}
