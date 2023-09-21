//
//  Localizing.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

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
    init(localizingKey key: String) {
        let bundle: Bundle
        if jsonWebKeyLocale != .autoupdatingCurrent, jsonWebKeyLocale != .current {
            bundle = Bundle.module.forLocale(jsonWebKeyLocale)
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
