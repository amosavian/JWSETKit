// swift-tools-version: 6.1
import PackageDescription

/// EUDI SD-JWT (eu-digital-identity-wallet/eudi-lib-sdjwt-swift) side of the comparison, in its
/// OWN package. The EUDI library is built on jose-swift, which pins swift-crypto < 4.0.0 — the same
/// conflict that isolates the jose-swift side — so it cannot co-resolve with the JWSETKit package
/// and MUST live in its own SwiftPM package. If it fails to resolve/build on a given toolchain, its
/// SD-JWT rows are simply absent from the comparison (noted in ../../README.md).
///
/// jose-swift is depended on directly (alongside the EUDI lib) so the benchmark can import
/// `JSONWebSignature` for the `JWK` signing key and `DefaultJWSHeaderImpl`, matching the joseswift
/// side's key construction. `SDJWTIssuer.issue` is `async`; the issue rows are native `async`
/// benchmark closures.
let package = Package(
    name: "EUDISDJWTSide",
    platforms: [
        .macOS(.v14),
        .iOS(.v16),
    ],
    dependencies: [
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.4.0"),
        .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-sdjwt-swift.git", from: "0.14.0"),
        .package(url: "https://github.com/beatt83/jose-swift.git", from: "6.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "EUDISDJWTComparison",
            dependencies: [
                .product(name: "eudi-lib-sdjwt-swift", package: "eudi-lib-sdjwt-swift"),
                .product(name: "jose-swift", package: "jose-swift"),
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/EUDISDJWTComparison",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
