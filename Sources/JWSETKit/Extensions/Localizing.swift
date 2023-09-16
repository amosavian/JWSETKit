//
//  Localizing.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation

extension String {
    init(localizingKey key: String) {
        self = NSLocalizedString(key, bundle: .module, comment: "")
    }
    
    init(localizingKey key: String, _ arguments: CVarArg...) {
        self = .init(format: .init(localizingKey: key), arguments: arguments)
    }
    
    init(localizingKey key: String, arguments: [CVarArg]) {
        self = .init(format: .init(localizingKey: key), arguments: arguments)
    }
}
