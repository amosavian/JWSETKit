// swift-tools-version: 6.1
import PackageDescription

/// JWSETKit side of the competitive comparison, in its OWN package so JWSETKit never shares
/// a resolution graph with jwt-kit's swift-crypto BoringSSL/CryptoExtras configuration. Run
/// alongside the jwt-kit package and compare the printed tables. See ../../README.md.
///
/// The `X509` trait is enabled so JWSETKit's RSA paths use swift-crypto's BoringSSL `_RSA`
/// backend (matching jwt-kit) rather than Apple `SecKey` — making the RS256 / JWE-RSA-OAEP rows a
/// like-for-like backend comparison. swift-certificates brings BoringSSL in transitively on Darwin.
let package = Package(
    name: "JWSETKitComparison",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    dependencies: [
        .package(path: "../../..", traits: ["X509"]),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.4.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "JWSETKitComparison",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/JWSETKitComparison",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
