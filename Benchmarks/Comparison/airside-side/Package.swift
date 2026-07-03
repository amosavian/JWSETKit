// swift-tools-version: 6.1
import PackageDescription

/// airsidemobile/JOSESwift side of the comparison, in its OWN package. This is a DIFFERENT library
/// from the beatt83 "jose-swift" side (../joseswift-side) — same JOSE standards, unrelated codebase.
/// JOSESwift is Apple-only: every asymmetric key is a Security-framework `SecKey` and signing runs
/// through `SecKeyCreateSignature`, so this side builds and runs ONLY on Apple platforms — it is
/// simply absent from Linux comparison runs (noted in ../../README.md). JOSESwift declares no
/// dependencies of its own, so it would co-resolve with JWSETKit cleanly; it lives in its own
/// package purely to keep every comparison side symmetric and independently runnable.
let package = Package(
    name: "AirsideJOSESwiftSide",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    dependencies: [
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.4.0"),
        .package(url: "https://github.com/airsidemobile/JOSESwift.git", from: "3.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "AirsideJOSESwiftComparison",
            dependencies: [
                .product(name: "JOSESwift", package: "JOSESwift"),
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/AirsideJOSESwiftComparison",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
