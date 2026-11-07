# zkas-walletd-mobile

The **ZKas wallet engine, embedded** — `zkas-walletd` running in-process on a phone,
exactly as the Tauri desktop shell runs it. Cross-compiles to Android (arm64-v8a,
armeabi-v7a, x86_64) and iOS. UniFFI exposes these calls:

- `start(node_addr, wallet_dir, secret?) -> u16` — binds a loopback port, runs the
  engine against a public node's gRPC, returns the port. The WebView then talks to
  `http://127.0.0.1:<port>`.
- `stop()` — graceful shutdown.
- `port() -> u16` — current port, 0 if stopped.

The seed and full viewing key never leave the device: the engine pulls compact block
records from the node and trial-decrypts locally; our servers see only what a block
explorer sees. No rocksdb, no OpenSSL (ring + rustls) — that is what makes the whole
node-client + Halo2 proving stack cross-compile cleanly.

## Build (Android arm64, no cargo-ndk — it panics on NDK r26)

    NDK=<ndk>; T=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
    CC_aarch64_linux_android=$T/aarch64-linux-android24-clang \
    AR_aarch64_linux_android=$T/llvm-ar \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$T/aarch64-linux-android24-clang \
    cargo build --target aarch64-linux-android --release

Kotlin bindings: `cargo run --bin uniffi-bindgen -- generate --library <the .so> --language kotlin --out-dir bindings/kotlin`

## iOS: `ZkasEngine.xcframework`, built on Linux without Xcode

The engine is pure Rust plus one assembly file, so the three Apple static libraries can be
built on a Linux box with only `rustup target add aarch64-apple-ios aarch64-apple-ios-sim
x86_64-apple-ios` and clang; nothing from an Apple SDK is compiled. What made that possible:

- **TLS is gated per target in `zkas-rusty`** (`zkas-walletd/Cargo.toml`): everywhere else the
  daemon uses rustls, whose providers (`ring`, `aws-lc-sys`) compile C against the platform
  headers; for `target_os = "ios"` it uses `reqwest` with `native-tls`, i.e. the system's
  Security.framework, and the `--serve-public` HTTPS listener (axum-server + rcgen) is not
  built in: the engine serves `127.0.0.1` only, which is all a phone needs.
- **A stub linker** for the three iOS targets (`CARGO_TARGET_AARCH64_APPLE_IOS_LINKER` etc.):
  a dependency declares a `cdylib` that rustc insists on linking, and the static library we
  ship never uses it. The stub writes an empty output and exits 0.
- **clang as the assembler** for `zakura-pasta-curves`' armv8 field multiplication
  (`CC_aarch64_apple_ios=clang`, `AR_aarch64_apple_ios=llvm-ar`, `SDKROOT=` an empty
  directory): assembling needs no SDK headers.

```sh
# Linux, with ../../rusty-kaspa beside this repo (the path dependencies above).
for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo rustc --release --lib --target $t --crate-type staticlib
done
cargo build --release --lib && cargo build --release --bin uniffi-bindgen
target/release/uniffi-bindgen generate --library target/release/libzkas_walletd_mobile.so \
  --language swift --out-dir swift
# Device slice: target/aarch64-apple-ios/release/libzkas_walletd_mobile.a
# Simulator slice: llvm-lipo -create the -sim and x86_64 libraries into one.
# Headers: swift/zkas_walletd_mobileFFI.h + the modulemap renamed module.modulemap.
# Write the xcframework's Info.plist by hand (two AvailableLibraries entries) — or run
# `xcodebuild -create-xcframework` where Xcode exists; the result is the same tree.
```

An app links the xcframework plus the generated `zkas_walletd_mobile.swift`, and
additionally `Security.framework`, `SystemConfiguration.framework`, `libresolv` and `libc++`
(the wallet's `ios/ZkasEngine/ZkasEngine.podspec` does exactly this). Published builds:
`https://zkas.info/downloads/ios/engine/<version>/` with `ZkasEngine.xcframework.zip`, the
Swift file and a `MANIFEST` of revisions and SHA-256s; the wallet repo's
`scripts/fetch-ios-engine.sh` installs one.

On iOS the engine behaves as on Android: `start(node, walletDir, nil, socks)` binds a free
loopback port and returns it; `setMemoryBudgetMb` before `start` sizes its caches;
`releaseMemory()` on a memory warning; `stop()` flushes checkpoints. There is no TLS
self-hosting and no background execution beyond what iOS grants the app.
