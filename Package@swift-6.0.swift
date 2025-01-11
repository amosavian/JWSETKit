// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

extension [Platform] {
    static let darwin: [Platform] = [.macOS, .macCatalyst, .iOS, .tvOS, .watchOS, .visionOS]
    static let nonDarwin: [Platform] = [.linux, .android, .windows, .wasi, .openbsd]
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
        .package(url: "https://github.com/Flight-School/AnyCodable", .upToNextMajor(from: "0.6.7")),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMajor(from: "1.3.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.10.0")),
        .package(url: "https://github.com/apple/swift-certificates", .upToNextMajor(from: "1.6.1")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.8.4")),
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
                "AnyCodable",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                // Linux support
                .product(name: "_CryptoExtras", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .product(name: "CryptoSwift", package: "CryptoSwift", condition: .when(platforms: .nonDarwin)),
                .byName(name: "Czlib"),
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
