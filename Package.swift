// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

extension [Platform] {
    static let darwin: [Platform] = [.macOS, .macCatalyst, .iOS, .tvOS, .watchOS, .custom("visionos")]
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
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "JWSETKit",
            targets: ["JWSETKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Flight-School/AnyCodable", .upToNextMajor(from: "0.6.7")),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.1.0")),
        .package(url: "https://github.com/apple/swift-certificates", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.8.0")),
        // Plugins
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.52.8"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "JWSETKit",
            dependencies: [
                "AnyCodable",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .product(name: "_CryptoExtras", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "CryptoSwift", package: "CryptoSwift", condition: .when(platforms: .nonDarwin)),
            ],
            swiftSettings: [
                .unsafeFlags([
                    "-Xfrontend", "-warn-concurrency",
                    "-Xfrontend", "-enable-actor-data-race-checks",
                ], .when(platforms: .darwin))
            ]),
        .testTarget(
            name: "JWSETKitTests",
            dependencies: ["JWSETKit"]),
    ]
)
