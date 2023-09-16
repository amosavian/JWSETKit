//
//  ContentType.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers

extension URLRequest {
    /// Content type of body, set in `Content-Type` header.
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
    /// Content type of body, set in `Content-Type` header.
    public var contentType: UTType? {
        (mimeType?.prefix(while: { $0 != Character(";") }))
            .map(String.init)
            .flatMap { .init(mimeType: $0) }
    }
}
#endif
