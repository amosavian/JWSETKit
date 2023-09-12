// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

extension [Platform] {
    static let nonDarwin: [Platform] = [.linux, .android, .openbsd, .wasi, .windows]
}

let package = Package(
    name: "JWSETKit",
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
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.50.4"),
        .package(url: "https://github.com/Flight-School/AnyCodable", .upToNextMajor(from: "0.6.7")),
        .package(url: "https://github.com/apple/swift-asn1.git", "0.6.0"..<"1.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "2.6.0")),
        .package(url: "https://github.com/apple/swift-certificates", .upToNextMajor(from: "0.6.0")),
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
            ]),
        .testTarget(
            name: "JWSETKitTests",
            dependencies: ["JWSETKit"]),
    ]
)
