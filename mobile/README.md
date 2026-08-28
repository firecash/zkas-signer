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

## Status

Working library, generated bindings, 8 tests. Not yet published to SwiftPM or
Maven, and no XCFramework/AAR packaging — see `MOBILE-LIBS.md` in the wallet repo.
