// swift-tools-version: 6.0
//
// The second independent reference for the Argon2id gate (amendment §9): mimiclone/argon2-swift,
// a pure-Swift Argon2 with its own BLAKE2b. It wraps no C: its only FFI is a secure-wipe call.
//
// A package of its own, and NEVER a dependency of SwiftIdentity: SwiftPM never looks here when
// the root package builds. `generate.py`, beside this file, draws the seeded cases, runs the
// executable below over them, and writes `Tests/SwiftIdentityTests/Vectors/argon2id-argon2-swift.txt`.
//
// Pinned to an exact revision, the commit tagged v1.0.4, so the reference can't move under the
// vectors it produced. The revision is also written into the vectors file's header.

import PackageDescription

let package = Package(
    name: "Argon2idSwift",
    // argon2-swift declares macOS 15.
    platforms: [
        .macOS(.v15),
    ],
    dependencies: [
        .package(
            url: "https://github.com/mimiclone/argon2-swift.git",
            revision: "0f6581ee4051a9160f735e9b4b7f47431151b89d"
        ),
    ],
    targets: [
        .executableTarget(
            name: "argon2-swift-tags",
            dependencies: [
                .product(name: "SwiftArgon2", package: "argon2-swift"),
            ],
            path: "Sources/Argon2SwiftTags"
        ),
    ]
)
