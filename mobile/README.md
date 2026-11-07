# zkas-mobile

Swift and Kotlin bindings for ZKas key custody and payment authorization.

This is a **binding, not an implementation**. Every function calls
`firecash-signer` — the crate the ZKas wallet itself signs with — so a phone and
the wallet derive the same keys and produce the same signatures by construction.
A second implementation of key derivation would be a second chance to derive an
address nobody can spend from.

## It does not prove, by design

Building the Halo 2 proof costs ~0.79 core-seconds **per note spent**; a ten-note
payment is ~8 core-seconds of sustained CPU. The daemon proves. This device
**verifies** the resulting bundle pays exactly what the user asked, and only then
signs.

    1. Signer::from_secret            on device
    2. viewing_key() -> POST /api/wallet/watch     the daemon can now SEE, not spend
    3. POST /api/wallet/prepare       daemon returns an UNSIGNED bundle
    4. verify_and_sign_payment(...)   on device — the security boundary
    5. POST /api/wallet/submit        with those signatures

There is deliberately **no "just sign this" call**. A raw spend-authorization
signature over a bundle nobody checked is a blind signature, which is what step 4
exists to prevent.

## Where the key belongs

iOS Keychain or Android Keystore. Never `UserDefaults`, `SharedPreferences`, or a
file. `Signer` zeroizes its own copy on drop — it cannot clean up a copy the app
made elsewhere.

## Build

    cargo test                                    # parity + behaviour
    cargo build --release
    cargo run --bin uniffi-bindgen -- generate \
      --library target/release/libzkas_mobile.so \
      --language swift --out-dir bindings/swift
    cargo run --bin uniffi-bindgen -- generate \
      --library target/release/libzkas_mobile.so \
      --language kotlin --out-dir bindings/kotlin

Verified building for `aarch64-linux-android` and `aarch64-apple-ios`. Linking a
shippable `cdylib`/`staticlib` needs the Android NDK and Xcode toolchains; the
`cargo check`/`build` above needs neither.

## Use it

Every release ships a release AAR, an `ZkasMobile.xcframework.zip`, a Maven package
in this project's GitLab Maven registry, and a SwiftPM pin. CI proves each release on a real Android
emulator (`device` job) before anything is published.

**Android (Gradle):**

    repositories {
      maven {
        url = uri("https://gitlab.com/api/v4/projects/88003612/packages/maven") // public, no credentials
      }
    }
    dependencies { implementation("info.zkas:zkas-mobile:0.1.3") }

or drop `zkas-mobile-release.aar` from the release straight into `libs/`.

**iOS (SwiftPM):** add `https://zkas.info/code/signer` at tag
`mobile-v0.1.4` — the root `Package.swift` pins that release's XCFramework by
checksum.

Since `mobile-v0.1.3` the bindings are built on the Zakura Common Orchard stack
(zakura-orchard), the same crates the node and daemon run. Keys, addresses and
signatures are byte-identical to earlier releases — upgrading changes nothing a
verifier can observe.

## Status

Published: tag `mobile-v0.1.3` (AAR + Maven package); its XCFramework was lost with the GitHub account and `mobile-v0.1.4` (2026-11-07) republishes it, built on the Linux build box without Xcode, in the GitLab package registry and at https://zkas.info/downloads/ios/mobile/0.1.4/.
Its binaries were hosted on GitHub and were lost with the suspended account on
2026-10-23; they are being re-published to GitLab by the `publish` CI job (manual
pipeline, `PUBLISH=true MOBILE_VERSION=0.1.3`), until which the Maven coordinate and
the SwiftPM binary do not resolve. Maven Central is pending a Sonatype account. 12 tests, all four CI jobs
(test, android, ios, device) gate every release.
