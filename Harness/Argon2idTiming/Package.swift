// swift-tools-version: 6.2
//
// The timing half of the Argon2id gate (amendment §9): this package's Argon2id against the
// phc-winner-argon2 reference, at deployment parameters, in a release build.
//
// A package of its own, outside the main one: SwiftPM never looks here when the root package
// builds, and nothing in the root depends on it. It depends on the root by path, so it times
// exactly the sources in this checkout. Run from the package root:
//
//     swift run -c release --package-path Harness/Argon2idTiming argon2id-timing
//
// The results are recorded by hand in `Harness/Argon2id/TIMING.md`, with the machine and date.

import PackageDescription

let package = Package(
    name: "Argon2idTiming",
    platforms: [
        .macOS(.v14),
    ],
    dependencies: [
        .package(name: "SwiftIdentity", path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "argon2id-timing",
            dependencies: [
                .product(name: "SwiftIdentity", package: "SwiftIdentity"),
            ],
            path: "Sources/Argon2idTiming"
        ),
    ]
)
