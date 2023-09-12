//
//  KeyLookup.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

extension String {
    var snakeCased: String {
        let pattern = "([a-z0-9])([A-Z])"
        let regex = try! NSRegularExpression(pattern: pattern, options: [])
        let range = NSRange(startIndex..., in: self)
        return regex.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "$1_$2").lowercased()
    }
    
    var jsonWebKey: String {
        snakeCased
            .replacingOccurrences(of: "is_", with: "", options: [.anchored])
            .replacingOccurrences(of: "_url", with: "", options: [.anchored, .backwards])
    }
}
