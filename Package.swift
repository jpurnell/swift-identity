// swift-tools-version: 6.2
// legibility:description: Subjects and the credentials that prove them — who is asking, and are they still allowed to be here.
//
// 6.2, not the 6.4 `swift package init` wrote from the local toolchain. The deploy host runs
// Swift 6.3.3, and the first intended consumer is deployed there; a tools-version above the
// target's compiler is a resolution failure on the machine that matters, discovered late.

import PackageDescription

let package = Package(
    name: "SwiftIdentity",
    // Declared, rather than left to the toolchain's default floor.
    //
    // Without this the package inherited whatever minimum the local toolchain
    // happened to use, and `SHA256.hash(data:)` — macOS 10.15 or newer — compiled
    // on a 6.4 toolchain and failed on the 6.3.3 one the deploy host runs. It built
    // here for three days and could never have built there, and nothing said so
    // until something was actually deployed.
    //
    // 14 rather than 10.15: every consumer is a macOS 14 service, and a floor lower
    // than anything that uses it is a claim nobody checks.
    //
    // iOS 17 and visionOS 1 since 0.7.0, to match SwiftCLIKit, the first consumer that runs on
    // them; both were built before being declared. Their Swift runtimes carry Unicode 15.0,
    // which is why the passphrase canonicalization is pinned there.
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .visionOS(.v1),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftIdentity",
            targets: ["SwiftIdentity"]
        ),
        // Shipped, not internal: a store written in another package runs this same bar.
        .library(
            name: "SwiftIdentityConformance",
            targets: ["SwiftIdentityConformance"]
        ),
    ],
    dependencies: [
        // Credential digests. Present from the first line of code, so that "nothing is stored
        // in the clear" is true of the reference implementation too — a reference that cheats
        // teaches the wrong thing to whoever copies it.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        // Seeded generators for the test targets, and only for them. Absent from every
        // non-test target on purpose: reproducibility is `SplitMix64`'s guarantee, and
        // unpredictability is the contract of everything this package mints.
        .package(url: "https://github.com/jpurnell/SwiftDeterminism.git", from: "1.1.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
    ],
    targets: [
        .target(
            name: "SwiftIdentity",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                // PBKDF2 lives here rather than in `Crypto`. The underscore marks the module as
                // not-yet-stable API, not the algorithm as unfit — and the alternative is
                // CommonCrypto, which is Darwin-only and would make the passphrase path stop
                // existing on Linux rather than merely being slower there.
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .target(
            name: "SwiftIdentityConformance",
            dependencies: [
                "SwiftIdentity",
                .product(name: "Crypto", package: "swift-crypto"),
                // PBKDF2 lives here rather than in `Crypto`. The underscore marks the module as
                // not-yet-stable API, not the algorithm as unfit — and the alternative is
                // CommonCrypto, which is Darwin-only and would make the passphrase path stop
                // existing on Linux rather than merely being slower there.
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .testTarget(
            name: "SwiftIdentityTests",
            dependencies: [
                "SwiftIdentity",
                "SwiftIdentityConformance",
                .product(name: "SwiftDeterminism", package: "SwiftDeterminism"),
            ],
            // Read by path from the test sources' own directory, not bundled: they're the
            // reference the tests are checked against, and a bundle copy could go stale.
            exclude: ["Requirements", "Vectors"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
    ]
)
