// swift-tools-version: 6.1
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
    traits: [
        "X509",
        "P256K",
        .default(enabledTraits: []),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.4.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.15.0"),
        .package(url: "https://github.com/apple/swift-certificates", from: "1.13.0"),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.21.1"),
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
                .product(name: "X509", package: "swift-certificates", condition: .when(platforms: .darwin + .nonWasm, traits: ["X509"])),
                .product(name: "P256K", package: "swift-secp256k1", condition: .when(traits: ["P256K"])),
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
