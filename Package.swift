// swift-tools-version:5.9
import PackageDescription

// ZKas key custody and payment authorization for iOS.
//
// The binary target points at an XCFramework attached to a GitHub release, so
// consumers get a prebuilt library without a Rust toolchain. The release job in
// .github/workflows/mobile.yml rewrites the url and checksum below, then tags the
// commit it wrote them into — so the tag a consumer resolves always carries the
// checksum of the artifact that tag published.
let package = Package(
    name: "ZkasMobile",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "ZkasMobile", targets: ["ZkasMobile"])
    ],
    targets: [
        .binaryTarget(
            name: "ZkasMobileFFI",
            url: "https://github.com/firecash/zkas-signer/releases/download/mobile-v0.1.2/ZkasMobile.xcframework.zip",
            checksum: "281d8e109defc4712290285f30719fa96c1ad08f7caef17d6fa270e6257016cc"
        ),
        .target(
            name: "ZkasMobile",
            dependencies: ["ZkasMobileFFI"],
            path: "Sources/ZkasMobile"
        )
    ]
)
