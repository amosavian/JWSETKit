//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
import UniformTypeIdentifiers

extension URLRequest {
    public var contentType: UTType? {
        get {
            (value(forHTTPHeaderField: "Content-Type")?
                .prefix(while: { $0 != Character(";") }))
            .map(String.init)
            .flatMap { .init(mimeType: $0) }
        }
        set {
            setValue(newValue?.preferredMIMEType, forHTTPHeaderField: "Content-Type")
        }
    }
}

extension HTTPURLResponse {
    public var contentType: UTType? {
        (mimeType?.prefix(while: { $0 != Character(";") }))
            .map(String.init)
            .flatMap { .init(mimeType: $0) }
    }
}
