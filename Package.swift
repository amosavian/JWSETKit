// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

extension [Platform] {
    static let darwin: [Platform] = [.macOS, .macCatalyst, .iOS, .tvOS, .watchOS, .custom("visionos")]
    static let nonDarwin: [Platform] = [.linux, .windows, .android, .wasi, .openbsd]
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
        .package(url: "https://github.com/apple/swift-collections.git", .upToNextMinor(from: "1.2.0")),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMajor(from: "1.4.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.12.3")),
        .package(url: "https://github.com/apple/swift-certificates", .upToNextMajor(from: "1.10.0")),
        .package(url: "https://github.com/swiftlang/swift-testing.git", .upToNextMajor(from: "0.11.0")),
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
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                // Linux support
                .product(name: "_CryptoExtras", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .byName(name: "Czlib", condition: .when(platforms: .nonDarwin)),
            ],
            resources: [
                .process("PrivacyInfo.xcprivacy"),
            ]
        ),
        .testTarget(
            name: "JWSETKitTests",
            dependencies: [
                "JWSETKit",
                .product(name: "Testing", package: "swift-testing"),
            ]
        ),
    ]
)
