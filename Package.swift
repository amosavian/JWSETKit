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
        .library(
            name: "JWSETKit",
            targets: ["JWSETKit"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/Flight-School/AnyCodable", .upToNextMajor(from: "0.6.7")),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMajor(from: "1.1.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.3.0")),
        .package(url: "https://github.com/apple/swift-certificates", .upToNextMajor(from: "1.2.0")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.8.2")),
        .package(url: "https://github.com/tsolomko/SWCompression.git", .upToNextMajor(from: "4.8.6")),
    ],
    targets: [
        .target(
            name: "JWSETKit",
            dependencies: [
                "AnyCodable",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
                // Linux support
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .product(name: "_CryptoExtras", package: "swift-crypto", condition: .when(platforms: .nonDarwin)),
                .product(name: "CryptoSwift", package: "CryptoSwift", condition: .when(platforms: .nonDarwin)),
                .product(name: "SWCompression", package: "SWCompression", condition: .when(platforms: .nonDarwin)),
            ],
            resources: [
                .process("PrivacyInfo.xcprivacy"),
            ]
        ),
        .testTarget(
            name: "JWSETKitTests",
            dependencies: ["JWSETKit"]
        ),
    ],
    swiftLanguageVersions: [.v5]
)

for target in package.targets {
    var swiftSettings: [SwiftSetting] = [
        .enableExperimentalFeature("StrictConcurrency=complete"),
    ]
#if swift(>=5.9)
    swiftSettings.append(.enableUpcomingFeature("ExistentialAny"))
#endif
    target.swiftSettings = swiftSettings
}
