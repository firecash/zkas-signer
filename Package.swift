// swift-tools-version:5.9
import PackageDescription

// ZKas key custody and payment authorization for iOS.
//
// The binary target points at an XCFramework in this project's GitLab package
// registry, so consumers get a prebuilt library without a Rust toolchain. The
// `publish` job in .gitlab-ci.yml rewrites the url and checksum below, then tags the
// commit it wrote them into — so the tag a consumer resolves always carries the
// checksum of the artifact that tag published.
//
// NOTE (2026-10-23): the mobile-v0.1.3 XCFramework was hosted on GitHub, which is
// gone with the suspended account, and no copy survived. The URL below is where the
// re-published 0.1.3 build will live; until the publish job runs, it does not resolve.
let package = Package(
    name: "ZkasMobile",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "ZkasMobile", targets: ["ZkasMobile"])
    ],
    targets: [
        .binaryTarget(
            name: "ZkasMobileFFI",
            url: "https://gitlab.com/api/v4/projects/88003612/packages/generic/zkas-mobile/0.1.3/ZkasMobile.xcframework.zip",
            checksum: "5b4d7bedc9fc8f8458334515f944739f9b619cfc71f9bd0f87f4f0ab6c2e40a2"
        ),
        .target(
            name: "ZkasMobile",
            dependencies: ["ZkasMobileFFI"],
            path: "Sources/ZkasMobile"
        )
    ]
)
