# zkas-walletd-mobile

The **ZKas wallet engine, embedded** — `zkas-walletd` running in-process on a phone,
exactly as the Tauri desktop shell runs it. Cross-compiles to Android (arm64-v8a,
armeabi-v7a, x86_64) and iOS. UniFFI exposes three calls:

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
