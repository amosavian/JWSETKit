//
//  Localizing.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation

extension Bundle {
    static func forLocale(_ locale: Locale) -> Bundle {
        if let url = Bundle.module.urls(forResourcesWithExtension: "stringsdict", subdirectory: nil, localization: jsonWebKeyLocale.identifier)?.first?.baseURL {
            return self.init(url: url) ?? .module
        } else if let url = Bundle.module.urls(forResourcesWithExtension: "stringsdict", subdirectory: nil, localization: jsonWebKeyLocale.languageCode)?.first?.baseURL {
            return self.init(url: url) ?? .module
        }
        return .module
    }
}

extension String {
    init(localizingKey key: String) {
        let bundle: Bundle
        if jsonWebKeyLocale != .autoupdatingCurrent, jsonWebKeyLocale != .current {
            bundle = .forLocale(jsonWebKeyLocale)
        } else {
            bundle = Bundle.module
        }
        self = bundle.localizedString(forKey: key, value: nil, table: nil)
    }
    
    init(localizingKey key: String, _ arguments: CVarArg...) {
        self = .init(format: .init(localizingKey: key), arguments: arguments)
    }
    
    init(localizingKey key: String, arguments: [CVarArg]) {
        self = .init(format: .init(localizingKey: key), arguments: arguments)
    }
}
