// swift-tools-version: 6.1
import PackageDescription

/// Regression benchmark suite for JWSETKit.
///
/// This is a SEPARATE package from the JWSETKit library so it can declare the macOS 13 /
/// iOS 16 floor that ordo-one/package-benchmark requires, without raising JWSETKit's own
/// macOS 12 / iOS 15 support. It carries no competitor dependencies — run it with:
///
///     swift package --package-path Benchmarks/Regression benchmark
///
let package = Package(
    name: "Regression",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    dependencies: [
        // `X509` is enabled so the RSA paths use swift-crypto's BoringSSL backend (`_RSA`) — the
        // same backend jwt-kit uses and the faster one for signing — rather than Apple `SecKey`.
        // (HTTP and P256K stay off; those trees aren't exercised here and are costly to compile.)
        .package(path: "../..", traits: ["X509"]),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.4.0"),
        // swift-crypto is a transitive dependency of JWSETKit; declared directly so the
        // benchmarks can construct `SymmetricKey` for HS256 fixtures.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
    ],
    targets: [
        .target(
            name: "BenchmarkSupport",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Benchmarks/BenchmarkSupport"
        ),
        .executableTarget(
            name: "Signing",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                "BenchmarkSupport",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/Signing",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
        .executableTarget(
            name: "Serialization",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                "BenchmarkSupport",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/Serialization",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
        .executableTarget(
            name: "Encryption",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                "BenchmarkSupport",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/Encryption",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
        .executableTarget(
            name: "Advanced",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                "BenchmarkSupport",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/Advanced",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
        // Decomposes the ES256 sign pipeline into its stages to locate where time/allocations
        // go relative to a minimal key-in-hand signer (see Benchmarks/README.md › Profiling).
        .executableTarget(
            name: "Profiling",
            dependencies: [
                .product(name: "JWSETKit", package: "JWSETKit"),
                .product(name: "Crypto", package: "swift-crypto"),
                "BenchmarkSupport",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/Profiling",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
