// swift-tools-version: 6.1
import PackageDescription

/// jwt-kit side of the competitive comparison, in its OWN package so its swift-crypto
/// BoringSSL / CryptoExtras configuration never collides with JWSETKit's. Run alongside the
/// JWSETKit package and compare the printed tables. See ../../README.md.
let package = Package(
    name: "JWTKitComparison",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    dependencies: [
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.4.0"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.5.0"),
        // swift-crypto declared directly so the benchmark can construct an RSA key via
        // `_RSA.Signing.PrivateKey` (CryptoExtras) and wrap it for jwt-kit. Range matches
        // jwt-kit's own (4.1.0 ..< 5.0.0) so the two co-resolve to one version.
        .package(url: "https://github.com/apple/swift-crypto.git", "4.1.0" ..< "5.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "JWTKitComparison",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/JWTKitComparison",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
