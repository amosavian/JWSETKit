// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

extension [Platform] {
    static let darwin: [Platform] = [.macOS, .macCatalyst, .iOS, .tvOS, .watchOS, .visionOS]
    static let nonWasm: [Platform] = [.linux, .windows, .android, .openbsd]
    static let nonDarwin: [Platform] = nonWasm + [.wasi]
}

let package = Package(
    name: "JWSETKit",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .tvOS(.v14),
        .macCatalyst(.v14),
    ],
    products: [
        .library(
            name: "JWSETKit",
            targets: ["JWSETKit"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.4.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.14.0"),
        .package(url: "https://github.com/apple/swift-certificates", from: "1.12.0"),
    ],
    targets: [
        .systemLibrary(
            name: "Czlib",
            pkgConfig: "zlib",
            providers: [
                .apt(["zlib1g-dev"]),
                .brew(["zlib"]),
                .yum(["zlib-devel"]),
            ]
        ),
        .target(
            name: "JWSETKit",
            dependencies: [
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates", condition: .when(platforms: .darwin + .nonWasm)),
                // Linux support
                .product(name: "_CryptoExtras", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .byName(name: "Czlib", condition: .when(platforms: .nonWasm)),
            ],
            resources: [
                .process("PrivacyInfo.xcprivacy"),
            ],
            swiftSettings: [.enableUpcomingFeature("ExistentialAny")]
        ),
        .testTarget(
            name: "JWSETKitTests",
            dependencies: ["JWSETKit"]
        ),
    ]
)
