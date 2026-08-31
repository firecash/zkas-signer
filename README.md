# zkas-signer

Client-side Orchard key primitives for [ZKas](https://github.com/firecash/zkas-rusty),
compiled to WebAssembly. It runs entirely on the user's device — in a browser or a Capacitor
mobile app — and **keys never leave the page**.

It deliberately excludes the Halo 2 proving circuit, so it stays small (~368 KiB wasm) and does
only what needs a private key:

- `new_wallet(network)` → a fresh random seed + its `firecash:` shielded address
- `address_from_seed(seed_hex, network)` → derive the address for an existing seed
- `sign(seed_hex, network, message)` → prove control of an address (emits `fvk‖sig` hex,
  interoperable with the `shielded-pay` CLI and the mining-pool claim verifier)
- `verify(address, message, signature_hex)` → verify a signature

Building a shielded **transaction** needs the proving circuit and is intentionally **not** here:
under Orchard's prove/sign split, a spend is proven server-side (viewing key only) and signed
here (spend key only), so a server can never spend.

## Who uses it

- **[firecash-paper-wallet](https://github.com/firecash/firecash-paper-wallet)** — an offline,
  single-file cold-storage generator (this crate's wasm inlined as base64).
- **[zkas-wallet](https://github.com/firecash/zkas-wallet)** — the web/mobile wallet's
  on-device "Local" tools (cold-wallet generation + signing).

## Build

```bash
cargo test                                        # native unit tests
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/firecash_signer.wasm
node paper-wallet/build.mjs                        # assemble the offline paper wallet
```

## Reproducible build / verification

The offline paper wallet inlines `pkg/firecash_signer_bg.wasm` as base64. To confirm the wallet
you're running was built from this source, rebuild and compare the wasm hash:

```
sha256(firecash_signer_bg.wasm) = ea0ec55a2cef0bb7f3cd6ce80b0e5c218693e0e97be49c80a73587b1eefcd409
```

(Reproducibility depends on matching Rust / wasm-bindgen versions; this hash is from
wasm-bindgen 0.2.100 on a release build.)

## License

MIT OR Apache-2.0.
