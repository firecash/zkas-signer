// swift-tools-version:5.9
import PackageDescription

// ZKas key custody and payment authorization for iOS.
//
// The binary targets point at XCFrameworks in this project's GitLab package registry
// (public, anonymous download; mirrored at https://zkas.info/downloads/ios/), so
// consumers get prebuilt libraries without a Rust toolchain. Both are built on the Linux
// build box without Xcode (mobile/README.md and walletd-mobile/README.md, "iOS"). The
// commit that changes a url and checksum below is the one tagged, so the tag a consumer
// resolves always carries the checksum of the artifact it names.
//
//   ZkasMobile  the device half: keys, viewing key, verify-and-sign (small)
//   ZkasEngine  the whole wallet daemon on loopback ("run on this phone"; large)
//
// mobile-v0.1.3's XCFramework was lost with the GitHub account; 0.1.4 is its rebuild
// from this tree (same API), published 2026-11-07.
let package = Package(
    name: "ZkasMobile",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "ZkasMobile", targets: ["ZkasMobile"]),
        .library(name: "ZkasEngine", targets: ["ZkasEngine"]),
    ],
    targets: [
        .binaryTarget(
            name: "ZkasMobileFFI",
            url: "https://gitlab.com/api/v4/projects/88003612/packages/generic/zkas-mobile/0.1.4/ZkasMobile.xcframework.zip",
            checksum: "7b90380e3ddfdabc0442f71bfb333eeae4f0d98fc71e260abfebbc0c7d065fb8"
        ),
        .target(
            name: "ZkasMobile",
            dependencies: ["ZkasMobileFFI"],
            path: "Sources/ZkasMobile"
        ),
        // The on-device wallet engine: zkas-walletd on loopback. Versions are dated; the
        // MANIFEST beside each zip names the zkas-rusty and zkas-signer revisions it holds.
        // An app also links Security, SystemConfiguration, libresolv and libc++.
        .binaryTarget(
            name: "ZkasEngineFFI",
            url: "https://gitlab.com/api/v4/projects/88003612/packages/generic/zkas-engine-ios/2026-11-07/ZkasEngine.xcframework.zip",
            checksum: "a05f8b826dc69cc57dfa735d36ce866ed47696924428b1224ca78300a7995cbd"
        ),
        .target(
            name: "ZkasEngine",
            dependencies: ["ZkasEngineFFI"],
            path: "Sources/ZkasEngine",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedLibrary("resolv"),
                .linkedLibrary("c++"),
            ]
        ),
    ]
)
