//
//  JSONPointer.swift
//  JWSETKit
//
//  JSON Pointer implementation per RFC 6901
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A JSON Pointer as defined in RFC 6901 for referencing specific values within a JSON document.
///
/// JSON Pointers use `/` as a separator and support both object keys and array indices.
/// Examples:
/// - `/email` - top-level "email" key
/// - `/address/street` - nested "street" within "address"
/// - `/nationalities/0` - first element of "nationalities" array
/// - `` (empty string) - references the entire document (root)
///
/// Special characters are escaped per RFC 6901:
/// - `~` is encoded as `~0`
/// - `/` is encoded as `~1`
public struct JSONPointer: Hashable, Sendable, RandomAccessCollection, CustomStringConvertible {
    /// A coding key component for JSON Pointer paths.
    public struct Component: CodingKey, Hashable, Sendable {
        public var stringValue: String
        public var intValue: Int?
        
        public init(stringValue: String) {
            self.stringValue = stringValue
            self.intValue = Int(stringValue)
        }
        
        public init(intValue: Int) {
            self.stringValue = String(intValue)
            self.intValue = intValue
        }
        
        public init(stringValue: String, intValue: Int?) {
            self.stringValue = stringValue
            self.intValue = intValue
        }
    }
    
    /// The path components after parsing.
    fileprivate let components: [Component]
    
    /// Whether this pointer references the root document (empty path).
    public var isRoot: Bool {
        components.isEmpty
    }
    
    /// The parent pointer, or nil if this is the root.
    public var parent: JSONPointer? {
        guard !components.isEmpty else { return nil }
        return JSONPointer(components: Array(components.dropLast()))
    }
    
    /// String representation in RFC 6901 format (e.g., "/address/street").
    public var description: String {
        guard !components.isEmpty else { return "" }
        return "/" + components.map { Self.escape($0.stringValue) }.joined(separator: "/")
    }
    
    public var startIndex: Int { components.startIndex }
    
    public var endIndex: Int { components.endIndex }
    
    public subscript(position: Int) -> Component {
        components[position]
    }
    
    public subscript(bounds: Range<Int>) -> JSONPointer {
        .init(components: Array(components[bounds]))
    }
    
    /// Creates an empty JSON Pointer referencing the root document.
    public init() {
        self.components = []
    }
    
    /// Creates a JSON Pointer from a string path per RFC 6901.
    ///
    /// - Parameter path: A JSON Pointer string (e.g., "/address/street" or "")
    /// - Note: An empty string references the root. Non-empty paths must start with `/`.
    public init(_ path: String) {
        if path.isEmpty {
            self.components = []
            return
        }
        
        // RFC 6901: A JSON Pointer is either empty or starts with '/'
        guard path.hasPrefix("/") else {
            // Invalid pointer, treat as single key
            self.components = [Self.parseComponent(path)]
            return
        }
        
        // Split by '/' and unescape each component
        let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        self.components = parts.map { Self.parseComponent(String($0)) }
    }
    
    /// Creates a JSON Pointer from an array of components.
    public init(components: [Component]) {
        self.components = components
    }
    
    /// Creates a JSON Pointer from an array of coding keys.
    public init(codingPath: [any CodingKey]) {
        self.components = codingPath.map { Component(stringValue: $0.stringValue, intValue: $0.intValue) }
    }
    
    /// Creates a JSON Pointer from a single key.
    init(key: String) {
        self.components = [Component(stringValue: key)]
    }
    
    public func index(before i: Int) -> Int {
        components.index(before: i)
    }
    
    public func index(after i: Int) -> Int {
        components.index(after: i)
    }
    
    public func index(_ i: Int, offsetBy distance: Int, limitedBy limit: Int) -> Int? {
        components.index(i, offsetBy: distance, limitedBy: limit)
    }
    
    /// Returns a new pointer by appending a component.
    public func appending(_ component: Component) -> JSONPointer {
        JSONPointer(components: components + [component])
    }
    
    /// Returns a new pointer by appending another pointer's components.
    public func appending(_ other: JSONPointer) -> JSONPointer {
        JSONPointer(components: components + other.components)
    }
    
    /// Returns whether this pointer is a prefix of (or equal to) another pointer.
    public func isPrefix(of other: JSONPointer) -> Bool {
        guard components.count <= other.components.count else { return false }
        return components == Array(other.components.prefix(components.count))
    }
    
    /// Returns the relative path from this pointer to a descendant, or nil if not a descendant.
    public func relativePath(to descendant: JSONPointer) -> JSONPointer? {
        guard isPrefix(of: descendant) else { return nil }
        return JSONPointer(components: Array(descendant.components.dropFirst(components.count)))
    }
        
    /// Unescapes a JSON Pointer token per RFC 6901.
    /// `~1` -> `/`, `~0` -> `~`
    private static func unescape(_ token: String) -> String {
        token
            .replacingOccurrences(of: "~1", with: "/")
            .replacingOccurrences(of: "~0", with: "~")
    }
    
    /// Escapes a string for use in a JSON Pointer per RFC 6901.
    /// `~` -> `~0`, `/` -> `~1`
    private static func escape(_ string: String) -> String {
        string
            .replacingOccurrences(of: "~", with: "~0")
            .replacingOccurrences(of: "/", with: "~1")
    }
    
    /// Parses a single path component.
    private static func parseComponent(_ token: String) -> Component {
        let unescaped = unescape(token)
        // Try to parse as array index
        if let index = Int(unescaped), index >= 0, String(index) == unescaped {
            return Component(intValue: index)
        }
        return Component(stringValue: unescaped)
    }
}

extension JSONPointer: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self.init(value)
    }
}

extension JSONPointer: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: Component...) {
        self.components = elements
    }
}

extension JSONPointer.Component: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self.init(stringValue: value)
    }
}

extension JSONPointer.Component: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(intValue: value)
    }
}

extension JSONPointer: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        self.init(string)
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension Set<JSONPointer> {
    public init<P: JSONWebContainerParameters>(_ container: P.Type) {
        self.init(container.keys.values.map(JSONPointer.init(key:)))
    }
}

extension JSONWebValueStorage {
    public subscript(pointer: JSONPointer) -> (any Sendable)? {
        get {
            value(at: pointer)
        }
        set {
            guard let newValue = newValue else {
                removeValue(at: pointer)
                return
            }
            switch newValue {
            case let value as any JSONWebFieldEncodable:
                setValue(value.jsonWebValue, at: pointer)
            default:
                setValue(newValue, at: pointer)
            }
        }
    }
    
    /// Gets value at the specified JSON Pointer path.
    ///
    /// - Parameter pointer: The JSON Pointer path to the value
    /// - Returns: The value at the path, or nil if not found
    private func value(at pointer: JSONPointer) -> (any Sendable)? {
        guard !pointer.isRoot else { return storage }
        return value(at: pointer.components, in: storage)
    }
    
    private func value(at components: [JSONPointer.Component], in current: any Sendable) -> (any Sendable)? {
        guard let first = components.first else { return current }
        let remaining = Array(components.dropFirst())
        
        if let index = first.intValue {
            // Array index access
            guard let array = current as? [any Sendable], array.indices.contains(index) else { return nil }
            return value(at: remaining, in: array[index])
        } else {
            // Object key access
            let key = first.stringValue
            if let dict = current as? [String: any Sendable], let next = dict[key] {
                return value(at: remaining, in: next)
            } else if let storage = current as? JSONWebValueStorage, let next = storage.storage[key] {
                return value(at: remaining, in: next)
            }
            return nil
        }
    }
    
    /// Sets value at the specified JSON Pointer path.
    ///
    /// - Parameters:
    ///   - value: The value to set
    ///   - pointer: The JSON Pointer path where to set the value
    /// - Throws: If the path is invalid or parent containers don't exist
    private mutating func setValue(_ value: any Sendable, at pointer: JSONPointer) {
        guard !pointer.isRoot else {
            if let dict = value as? [String: any Sendable] {
                storage = dict
            }
            return
        }
        setValue(value, at: pointer.components, in: &storage)
    }
    
    private func setValue(_ value: any Sendable, at components: [JSONPointer.Component], in current: inout [String: any Sendable]) {
        guard let first = components.first else { return }
        let remaining = Array(components.dropFirst())
        
        if remaining.isEmpty {
            current[first.stringValue] = value
        } else {
            // Navigate deeper
            let key = first.stringValue
            if remaining.first?.intValue != nil {
                // Next level is array
                var array = current[key] as? [any Sendable] ?? []
                setValue(value, at: remaining, inArray: &array)
                current[key] = array
            } else {
                // Next level is object
                var nested = current[key] as? [String: any Sendable] ?? [:]
                setValue(value, at: remaining, in: &nested)
                current[key] = nested
            }
        }
    }
    
    private func setValue(_ value: any Sendable, at components: [JSONPointer.Component], inArray array: inout [any Sendable]) {
        guard let first = components.first, let index = first.intValue, index >= 0 else {
            return
        }
        if !array.indices.contains(index) {
            let padding = [any Sendable](repeating: Data?.none, count: index - array.count + 1)
            array.append(contentsOf: padding)
        }
        let remaining = Array(components.dropFirst())
        
        if remaining.isEmpty {
            array[index] = value
        } else if remaining.first?.intValue != nil {
            var nested = array[index] as? [any Sendable] ?? []
            setValue(value, at: remaining, inArray: &nested)
            array[index] = nested
        } else {
            var nested = array[index] as? [String: any Sendable] ?? [:]
            setValue(value, at: remaining, in: &nested)
            array[index] = nested
        }
    }
    
    /// Removes value at the specified JSON Pointer path.
    ///
    /// - Parameter pointer: The JSON Pointer path to remove
    /// - Returns: The removed value, or nil if not found
    @discardableResult
    private mutating func removeValue(at pointer: JSONPointer) -> (any Sendable)? {
        guard !pointer.isRoot else {
            let old = storage
            storage = [:]
            return old
        }
        return removeValue(at: pointer.components, in: &storage)
    }
    
    private func removeValue(at components: [JSONPointer.Component], in current: inout [String: any Sendable]) -> (any Sendable)? {
        guard let first = components.first else { return nil }
        let remaining = Array(components.dropFirst())
        
        if remaining.isEmpty {
            return current.removeValue(forKey: first.stringValue)
        } else {
            let key = first.stringValue
            if var nested = current[key] as? [String: any Sendable] {
                let result = removeValue(at: remaining, in: &nested)
                current[key] = nested
                return result
            } else if var array = current[key] as? [any Sendable] {
                let result = removeValue(at: remaining, inArray: &array)
                current[key] = array
                return result
            }
            return nil
        }
    }
    
    private func removeValue(at components: [JSONPointer.Component], inArray array: inout [any Sendable]) -> (any Sendable)? {
        guard let first = components.first, let index = first.intValue, array.indices.contains(index) else {
            return nil
        }
        let remaining = Array(components.dropFirst())
        
        if remaining.isEmpty {
            return array.remove(at: index)
        } else if var nested = array[index] as? [String: any Sendable] {
            let result = removeValue(at: remaining, in: &nested)
            array[index] = nested
            return result
        } else if var nested = array[index] as? [any Sendable] {
            let result = removeValue(at: remaining, inArray: &nested)
            array[index] = nested
            return result
        }
        return nil
    }
    
    /// Returns all leaf paths in the storage.
    ///
    /// This traverses the entire structure and returns JSON Pointers to all leaf values
    /// (non-container values like strings, numbers, booleans, etc.)
    public func allPaths() -> [JSONPointer] {
        var paths: [JSONPointer] = []
        collectPaths(from: storage, prefix: .init(), into: &paths)
        return paths
    }
    
    /// Returns all top-level keys as JSON Pointers.
    public func topLevelPaths() -> [JSONPointer] {
        storage.keys.map(JSONPointer.init(key:))
    }
    
    private func collectPaths(from value: Any, prefix: JSONPointer, into paths: inout [JSONPointer]) {
        if let dict = value as? [String: Any] {
            if dict.isEmpty {
                paths.append(prefix)
            } else {
                for (key, nested) in dict {
                    collectPaths(from: nested, prefix: prefix.appending(.init(stringValue: key)), into: &paths)
                }
            }
        } else if let array = value as? [Any] {
            if array.isEmpty {
                paths.append(prefix)
            } else {
                for (index, nested) in array.enumerated() {
                    collectPaths(from: nested, prefix: prefix.appending(.init(intValue: index)), into: &paths)
                }
            }
        } else {
            paths.append(prefix)
        }
    }
}

extension JSONWebContainer {
    public subscript(pointer: JSONPointer) -> (any Sendable)? {
        storage[pointer]
    }
}

extension MutableJSONWebContainer {
    public subscript(pointer: JSONPointer) -> (any Sendable)? {
        get {
            storage[pointer]
        }
        set {
            storage[pointer] = newValue
        }
    }
}
