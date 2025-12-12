//
//  JSONPointerTests.swift
//
//
//  Created by Claude Code on 12/13/25.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct JSONPointerTests {

    // MARK: - Initialization Tests

    @Test
    func initEmpty() {
        let pointer = JSONPointer()
        #expect(pointer.isRoot)
        #expect(pointer.description == "")
        #expect(pointer.count == 0)
    }

    @Test
    func initFromEmptyString() {
        let pointer = JSONPointer("")
        #expect(pointer.isRoot)
        #expect(pointer.description == "")
    }

    @Test
    func initFromSimplePath() {
        let pointer = JSONPointer("/email")
        #expect(!pointer.isRoot)
        #expect(pointer.count == 1)
        #expect(pointer[0].stringValue == "email")
        #expect(pointer.description == "/email")
    }

    @Test
    func initFromNestedPath() {
        let pointer = JSONPointer("/address/street")
        #expect(pointer.count == 2)
        #expect(pointer[0].stringValue == "address")
        #expect(pointer[1].stringValue == "street")
        #expect(pointer.description == "/address/street")
    }

    @Test
    func initFromArrayIndexPath() {
        let pointer = JSONPointer("/nationalities/0")
        #expect(pointer.count == 2)
        #expect(pointer[0].stringValue == "nationalities")
        #expect(pointer[1].intValue == 0)
        #expect(pointer.description == "/nationalities/0")
    }

    @Test
    func initWithEscapedCharacters() {
        // Test ~0 -> ~ and ~1 -> /
        let pointer = JSONPointer("/a~0b")
        #expect(pointer[0].stringValue == "a~b")

        let pointer2 = JSONPointer("/a~1b")
        #expect(pointer2[0].stringValue == "a/b")

        let pointer3 = JSONPointer("/a~0~1b")
        #expect(pointer3[0].stringValue == "a~/b")
    }

    @Test
    func initFromInvalidPath() {
        // Path without leading slash is treated as single key
        let pointer = JSONPointer("email")
        #expect(pointer.count == 1)
        #expect(pointer[0].stringValue == "email")
    }

    @Test
    func initFromStringLiteral() {
        let pointer: JSONPointer = "/address/city"
        #expect(pointer.count == 2)
        #expect(pointer[0].stringValue == "address")
        #expect(pointer[1].stringValue == "city")
    }

    @Test
    func initFromArrayLiteral() {
        let pointer: JSONPointer = ["address", "city"]
        #expect(pointer.count == 2)
        #expect(pointer[0].stringValue == "address")
        #expect(pointer[1].stringValue == "city")
    }

    @Test
    func initFromCodingPath() {
        struct TestKey: CodingKey {
            var stringValue: String
            var intValue: Int?
            init(stringValue: String) {
                self.stringValue = stringValue
                self.intValue = nil
            }
            init?(intValue: Int) {
                self.stringValue = String(intValue)
                self.intValue = intValue
            }
        }

        let codingPath: [any CodingKey] = [TestKey(stringValue: "address"), TestKey(stringValue: "street")]
        let pointer = JSONPointer(codingPath: codingPath)
        #expect(pointer.count == 2)
        #expect(pointer[0].stringValue == "address")
        #expect(pointer[1].stringValue == "street")
    }

    // MARK: - Component Tests

    @Test
    func componentFromString() {
        let component = JSONPointer.Component(stringValue: "test")
        #expect(component.stringValue == "test")
        #expect(component.intValue == nil)
    }

    @Test
    func componentFromNumericString() {
        let component = JSONPointer.Component(stringValue: "42")
        #expect(component.stringValue == "42")
        #expect(component.intValue == 42)
    }

    @Test
    func componentFromInt() {
        let component = JSONPointer.Component(intValue: 5)
        #expect(component.stringValue == "5")
        #expect(component.intValue == 5)
    }

    @Test
    func componentFromStringLiteral() {
        let component: JSONPointer.Component = "test"
        #expect(component.stringValue == "test")
    }

    @Test
    func componentFromIntegerLiteral() {
        let component: JSONPointer.Component = 7
        #expect(component.intValue == 7)
    }

    // MARK: - Parent Tests

    @Test
    func parentOfRoot() {
        let pointer = JSONPointer()
        #expect(pointer.parent == nil)
    }

    @Test
    func parentOfSimplePath() {
        let pointer = JSONPointer("/email")
        #expect(pointer.parent?.isRoot == true)
    }

    @Test
    func parentOfNestedPath() {
        let pointer = JSONPointer("/address/street/number")
        let parent = pointer.parent
        #expect(parent?.description == "/address/street")
        #expect(parent?.parent?.description == "/address")
        #expect(parent?.parent?.parent?.isRoot == true)
    }

    // MARK: - Collection Tests

    @Test
    func subscriptRange() {
        let pointer = JSONPointer("/a/b/c/d")
        let subPointer = pointer[1..<3]
        #expect(subPointer.count == 2)
        #expect(subPointer[0].stringValue == "b")
        #expect(subPointer[1].stringValue == "c")
    }

    @Test
    func indexMethods() {
        let pointer = JSONPointer("/a/b/c")
        #expect(pointer.startIndex == 0)
        #expect(pointer.endIndex == 3)
        #expect(pointer.index(before: 2) == 1)
        #expect(pointer.index(after: 1) == 2)
        #expect(pointer.index(0, offsetBy: 2, limitedBy: 3) == 2)
        #expect(pointer.index(0, offsetBy: 5, limitedBy: 3) == nil)
    }

    // MARK: - Appending Tests

    @Test
    func appendComponent() {
        let pointer = JSONPointer("/address")
        let newPointer = pointer.appending(.init(stringValue: "city"))
        #expect(newPointer.description == "/address/city")
    }

    @Test
    func appendPointer() {
        let pointer1 = JSONPointer("/address")
        let pointer2 = JSONPointer("/street/number")
        let combined = pointer1.appending(pointer2)
        #expect(combined.description == "/address/street/number")
    }

    // MARK: - Prefix Tests

    @Test
    func isPrefixOfSelf() {
        let pointer = JSONPointer("/address/street")
        #expect(pointer.isPrefix(of: pointer))
    }

    @Test
    func isPrefixOfDescendant() {
        let parent = JSONPointer("/address")
        let child = JSONPointer("/address/street/number")
        #expect(parent.isPrefix(of: child))
        #expect(!child.isPrefix(of: parent))
    }

    @Test
    func rootIsPrefixOfAll() {
        let root = JSONPointer()
        let pointer = JSONPointer("/address/street")
        #expect(root.isPrefix(of: pointer))
    }

    // MARK: - Relative Path Tests

    @Test
    func relativePathToDescendant() {
        let parent = JSONPointer("/address")
        let child = JSONPointer("/address/street/number")
        let relative = parent.relativePath(to: child)
        #expect(relative?.description == "/street/number")
    }

    @Test
    func relativePathToNonDescendant() {
        let pointer1 = JSONPointer("/address")
        let pointer2 = JSONPointer("/email")
        #expect(pointer1.relativePath(to: pointer2) == nil)
    }

    @Test
    func relativePathToSelf() {
        let pointer = JSONPointer("/address")
        let relative = pointer.relativePath(to: pointer)
        #expect(relative?.isRoot == true)
    }

    // MARK: - Escape/Unescape Tests

    @Test
    func descriptionEscapesSpecialCharacters() {
        let pointer = JSONPointer(components: [
            .init(stringValue: "a~b"),
            .init(stringValue: "c/d"),
        ])
        #expect(pointer.description == "/a~0b/c~1d")
    }

    // MARK: - Codable Tests

    @Test
    func encodeDecode() throws {
        let original = JSONPointer("/address/street")
        let encoder = JSONEncoder()
        let data = try encoder.encode(original)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(JSONPointer.self, from: data)
        #expect(original == decoded)
    }

    @Test
    func encodeRoot() throws {
        let pointer = JSONPointer()
        let encoder = JSONEncoder()
        let data = try encoder.encode(pointer)
        let string = String(data: data, encoding: .utf8)
        #expect(string == "\"\"")
    }

    // MARK: - Hashable Tests

    @Test
    func hashableConformance() {
        let pointer1 = JSONPointer("/address/street")
        let pointer2 = JSONPointer("/address/street")
        let pointer3 = JSONPointer("/address/city")

        #expect(pointer1 == pointer2)
        #expect(pointer1 != pointer3)
        #expect(pointer1.hashValue == pointer2.hashValue)
    }

    @Test
    func setOfPointers() {
        var set = Set<JSONPointer>()
        set.insert("/email")
        set.insert("/address/street")
        set.insert("/email") // duplicate
        #expect(set.count == 2)
    }

    // MARK: - JSONWebValueStorage Integration Tests

    @Test
    func storageGetValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "name": "John",
            "address": [
                "street": "123 Main St",
                "city": "Springfield",
            ] as [String: any Sendable],
            "phones": ["555-1234", "555-5678"],
        ]

        let name: String? = storage[JSONPointer("/name")] as? String
        #expect(name == "John")

        let street: String? = storage[JSONPointer("/address/street")] as? String
        #expect(street == "123 Main St")

        let phone: String? = storage[JSONPointer("/phones/0")] as? String
        #expect(phone == "555-1234")
    }

    @Test
    func storageGetRoot() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["key": "value"]

        let root = storage[JSONPointer()]
        #expect((root as? [String: Any])?["key"] as? String == "value")
    }

    @Test
    func storageSetValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["address": ["city": "Old City"] as [String: any Sendable]]

        storage[JSONPointer("/address/city")] = "New City"
        #expect((storage.storage["address"] as? [String: any Sendable])?["city"] as? String == "New City")
    }

    @Test
    func storageSetNewNestedValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [:]

        storage[JSONPointer("/address/street")] = "123 Main St"
        let address = storage.storage["address"] as? [String: Any]
        #expect(address?["street"] as? String == "123 Main St")
    }

    @Test
    func storageSetArrayValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["items": ["a", "b", "c"]]

        storage[JSONPointer("/items/1")] = "X"
        let items = storage.storage["items"] as? [Any]
        #expect(items?[1] as? String == "X")
    }

    @Test
    func storageRemoveValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["name": "John", "email": "john@example.com"]

        storage[JSONPointer("/email")] = nil
        #expect(storage.storage["email"] == nil)
        #expect(storage.storage["name"] as? String == "John")
    }

    @Test
    func storageAllPaths() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "name": "John",
            "address": [
                "street": "123 Main St",
                "city": "Springfield",
            ] as [String: any Sendable],
        ]

        let paths = storage.allPaths()
        #expect(paths.count == 3) // name, address/street, address/city
    }

    @Test
    func storageTopLevelPaths() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "name": "John",
            "email": "john@example.com",
            "address": ["city": "Springfield"] as [String: any Sendable],
        ]

        let paths = storage.topLevelPaths()
        #expect(paths.count == 3)
    }

    // MARK: - Additional Coverage Tests

    @Test
    func storageSetNestedArrayValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["data": ["items": ["a", "b", "c"]] as [String: any Sendable]]

        // Set a nested array value
        storage[JSONPointer("/data/items/1")] = "X"
        let data = storage.storage["data"] as? [String: any Sendable]
        let items = data?["items"] as? [any Sendable]
        #expect(items?[1] as? String == "X")
    }

    @Test
    func storageSetValueInNewArray() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [:]

        // Create a new array path with index
        storage[JSONPointer("/items/0")] = "first"
        let items = storage.storage["items"] as? [any Sendable]
        #expect(items?.count == 1)
        #expect(items?[0] as? String == "first")
    }

    @Test
    func storageSetValueWithArrayPadding() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["items": ["a"]]

        // Set value at index beyond current array length (should pad)
        storage[JSONPointer("/items/3")] = "d"
        let items = storage.storage["items"] as? [any Sendable]
        #expect(items?.count == 4)
        #expect(items?[3] as? String == "d")
    }

    @Test
    func storageRemoveNestedValue() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "address": [
                "street": "123 Main St",
                "city": "Springfield",
            ] as [String: any Sendable],
        ]

        storage[JSONPointer("/address/city")] = nil
        let address = storage.storage["address"] as? [String: any Sendable]
        #expect(address?["city"] == nil)
        #expect(address?["street"] as? String == "123 Main St")
    }

    @Test
    func storageRemoveFromArray() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["items": ["a", "b", "c"]]

        storage[JSONPointer("/items/1")] = nil
        let items = storage.storage["items"] as? [any Sendable]
        #expect(items?.count == 2) // "b" removed, array shrinks
    }

    @Test
    func storageGetNonExistentPath() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["name": "John"]

        // Non-existent paths should return nil
        #expect(storage[JSONPointer("/email")] == nil)
        #expect(storage[JSONPointer("/address/street")] == nil)
        #expect(storage[JSONPointer("/items/0")] == nil)
    }

    @Test
    func storageGetFromNestedStorage() throws {
        var storage = JSONWebValueStorage()
        var nested = JSONWebValueStorage()
        nested.storage = ["city": "Springfield"]
        storage.storage = ["address": nested]

        let city = storage[JSONPointer("/address/city")] as? String
        #expect(city == "Springfield")
    }

    @Test
    func storageRemoveRoot() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["key": "value"]

        storage[JSONPointer()] = nil
        #expect(storage.storage.isEmpty)
    }

    @Test
    func storageSetRoot() throws {
        var storage = JSONWebValueStorage()
        storage.storage = ["old": "value"]

        storage[JSONPointer()] = ["new": "data"] as [String: any Sendable]
        #expect(storage.storage["new"] as? String == "data")
        #expect(storage.storage["old"] == nil)
    }

    @Test
    func storageAllPathsWithEmptyContainers() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "emptyDict": [:] as [String: any Sendable],
            "emptyArray": [] as [any Sendable],
            "value": "test",
        ]

        let paths = storage.allPaths()
        #expect(paths.count == 3) // emptyDict, emptyArray, value (all as leaf paths)
    }

    @Test
    func storageNestedArrayInArray() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "matrix": [
                ["a", "b"],
                ["c", "d"],
            ] as [[any Sendable]],
        ]

        let value = storage[JSONPointer("/matrix/1/0")] as? String
        #expect(value == "c")
    }

    @Test
    func storageRemoveFromNestedArray() throws {
        var storage = JSONWebValueStorage()
        storage.storage = [
            "data": [
                "items": ["a", "b", "c"],
            ] as [String: any Sendable],
        ]

        storage[JSONPointer("/data/items/1")] = nil
        let data = storage.storage["data"] as? [String: any Sendable]
        let items = data?["items"] as? [any Sendable]
        #expect(items?.count == 2)
    }

    @Test
    func setPointerFromContainerParameters() {
        // Test Set<JSONPointer> init from container parameters
        let paths = Set<JSONPointer>(JSONWebTokenClaimsRegisteredParameters.self)
        #expect(!paths.isEmpty)
        #expect(paths.contains("/iss"))
        #expect(paths.contains("/sub"))
    }
}
