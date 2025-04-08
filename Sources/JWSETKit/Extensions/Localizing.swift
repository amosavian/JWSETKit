//
//  Localizing.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials

extension String {
    init(localizingKey _: String, value: String, locale _: Locale) {
        self = value
    }
    
    init(localizingKey _: String, value: String, locale: Locale, _ arguments: any CVarArg...) {
        self.init(format: value, locale: locale, arguments: arguments)
    }
    
    init(localizingKey _: String, value: String, locale: Locale, arguments: [any CVarArg]) {
        self.init(format: value, locale: locale, arguments: arguments)
    }
}
#else
import Foundation

extension Bundle {
    func forLocale(_ locale: Locale) -> Bundle {
        if let url = urls(forResourcesWithExtension: "stringsdict", subdirectory: nil, localization: locale.identifier)?.first?.baseURL {
            return Bundle(url: url) ?? .module
        } else if let url = Bundle.module.urls(forResourcesWithExtension: "stringsdict", subdirectory: nil, localization: locale.languageCode)?.first?.baseURL {
            return Bundle(url: url) ?? .module
        }
        return .module
    }
}

extension String {
    init(localizingKey key: String, value: String, locale: Locale) {
        let bundle: Bundle
        if locale != .autoupdatingCurrent, locale != .current {
            bundle = Bundle.module.forLocale(locale)
        } else {
            bundle = Bundle.module
        }
        self = bundle.localizedString(forKey: key, value: value, table: "")
    }
    
    init(localizingKey key: String, value: String, locale: Locale, _ arguments: any CVarArg...) {
        self = .init(format: .init(localizingKey: key, value: value, locale: locale), arguments: arguments)
    }
    
    init(localizingKey key: String, value: String, locale: Locale, arguments: [any CVarArg]) {
        self = .init(format: .init(localizingKey: key, value: value, locale: locale), arguments: arguments)
    }
}
#endif

extension Locale {
    @inlinable
    var languageIdentifier: String? {
#if canImport(Darwin)
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            return language.languageCode?.identifier
        } else {
            return languageCode
        }
#else
        return languageCode
#endif
    }
    
    @inlinable
    var countryCode: String? {
#if canImport(Darwin)
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            return region?.identifier
        } else {
            return regionCode
        }
#else
        return regionCode
#endif
    }
    
    @inlinable
    var writeScript: String? {
#if canImport(Darwin)
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            return language.script?.identifier
        } else {
            return scriptCode
        }
#else
        return scriptCode
#endif
    }
    
    @inlinable
    var bcp47: String {
#if canImport(Darwin)
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            return identifier(.bcp47)
        } else {
            return identifier.replacingOccurrences(of: "_", with: "-")
        }
#else
        return identifier.replacingOccurrences(of: "_", with: "-")
#endif
    }
    
    @inlinable
    init(bcp47: String) {
#if canImport(Darwin)
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            self.init(components: .init(identifier: bcp47))
        } else {
            self.init(identifier: bcp47.replacingOccurrences(of: "-", with: "_"))
        }
#else
        self.init(identifier: bcp47.replacingOccurrences(of: "-", with: "_"))
#endif
    }
    
    func bestMatch(in locales: [Locale]) -> Locale? {
        guard !locales.isEmpty, let languageIdentifier = languageIdentifier else { return nil }
        let matchedLanguages = locales.filter { $0.languageIdentifier == languageIdentifier }
        switch matchedLanguages.count {
        case 0:
            return nil
        case 1:
            return matchedLanguages[0]
        default:
            break
        }
        let matchedScript: [Locale]
        if let writeScript = writeScript {
            matchedScript = matchedLanguages.filter { $0.writeScript == writeScript }
            switch matchedScript.count {
            case 0:
                return matchedLanguages[0]
            case 1:
                return matchedScript[0]
            default:
                break
            }
        } else {
            matchedScript = matchedLanguages
        }
        if let countryCode = countryCode {
            let matchedCountry = matchedScript.filter { $0.countryCode == countryCode }
            switch matchedCountry.count {
            case 0:
                return matchedScript.first { $0.countryCode == nil } ?? matchedScript[0]
            default:
                return matchedCountry[0]
            }
        } else {
            return matchedScript[0]
        }
    }
}
