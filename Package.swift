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
            url: "https://github.com/firecash/zkas-signer/releases/download/mobile-v0.1.1/ZkasMobile.xcframework.zip",
            checksum: "8739736326857025f21997acbf73f3348d00ff0d589f3d7011440d16b20b75d7"
        ),
        .target(
            name: "ZkasMobile",
            dependencies: ["ZkasMobileFFI"],
            path: "Sources/ZkasMobile"
        )
    ]
)
