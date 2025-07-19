//
//  KeyLookup.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_documentation(visibility: private)
public protocol JSONWebContainerParameters {
    static var keys: [SendablePartialKeyPath<Self>: String] { get }
    static var localizableKeys: [SendablePartialKeyPath<Self>] { get }
}

extension JSONWebContainerParameters {
    public static var localizableKeys: [SendablePartialKeyPath<Self>] { [] }
}

extension JSONWebContainer {
    @_documentation(visibility: private)
    public func stringKey<P: JSONWebContainerParameters, T>(_ keyPath: SendableKeyPath<P, T>) -> String {
        P.keys[keyPath] ?? keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    public func stringKey<P: JSONWebContainerParameters, T>(_ keyPath: SendableKeyPath<P, T>, force: Bool = false, locale: Locale) -> String {
        let key = P.keys[keyPath] ?? keyPath.name.jsonWebKey
        guard P.localizableKeys.contains(keyPath) else { return key }
        if force {
            return "\(key)#\(locale.bcp47)"
        } else {
            let locales = storage.storageKeys
                .filter { $0.hasPrefix(key + "#") }
                .map { $0.replacingOccurrences(of: key + "#", with: "", options: [.anchored]) }
                .map(Locale.init(identifier:))
            guard let bestLocale = locale.bestMatch(in: locales) else { return key }
            return "\(key)#\(bestLocale.identifier)"
        }
    }
}

extension AnyKeyPath {
    var name: String {
#if canImport(Darwin) || swift(>=6.0)
        // `components` never returns empty array.
        return String(String(reflecting: self).split(separator: ".").last!)
#else
        assertionFailure("KeyPath reflection does not work correctly on non-Apple platforms.\n" + String(reflecting: self).components(separatedBy: ".").last!)
        return ""
#endif
    }
}

extension String {
#if canImport(Foundation.NSRegularExpression)
    // The pattern is valid and it never fails.
    private static let regex = (try? NSRegularExpression(pattern: "([a-z0-9])([A-Z])", options: [])).unsafelyUnwrapped
#endif

    var snakeCased: String {
#if canImport(Foundation.NSRegularExpression)
        let range = NSRange(startIndex..., in: self)
        return Self.regex.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "$1_$2").lowercased()
#else
        var result = ""
        for (index, char) in enumerated() {
            let lastIndex = index > 0 ? self.index(startIndex, offsetBy: index - 1) : startIndex
            if char.isUppercase, index > 0, !self[lastIndex].isUppercase {
                result.append("_")
            }
            result.append(char.lowercased())
        }
        return result
#endif
    }
    
    @usableFromInline
    var jsonWebKey: String {
        snakeCased
            .replacingOccurrences(of: "is_", with: "", options: [.anchored])
            .replacingOccurrences(of: "_url", with: "", options: [.anchored, .backwards])
    }
}
