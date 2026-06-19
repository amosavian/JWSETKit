// swift-tools-version: 6.1
import PackageDescription

/// jose-swift (beatt83) side of the comparison, in its OWN package. jose-swift pins
/// swift-crypto < 4.0.0, which conflicts with JWSETKit's >= 4.5.0, so it MUST be isolated —
/// it cannot co-resolve with the JWSETKit package. If jose-swift fails to resolve/build on a
/// given toolchain, its row is simply absent from the comparison (noted in ../../README.md).
/// Its JWE and JWS-sign APIs are synchronous; only `JWT.verify` is async (bridged in-target).
let package = Package(
    name: "JOSESwiftSide",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    dependencies: [
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.4.0"),
        .package(url: "https://github.com/beatt83/jose-swift.git", from: "6.0.0"),
        // jose-swift's RSA JWE uses CryptoSwift's `RSA` type; depend on it directly to build the
        // RSA-OAEP-256 recipient key. Already in the resolved graph via jose-swift.
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", "1.8.0" ..< "2.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "JOSESwiftComparison",
            dependencies: [
                .product(name: "jose-swift", package: "jose-swift"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/JOSESwiftComparison",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
