# zkas-chat-identity

Chat identity and event signing for ZKas: the wallet's recovery phrase → a
standard [Nostr](https://nips.nostr.com/) key, plus NIP-01 event construction,
BIP-340 signing, verification, and NIP-13 proof of work.

## It cannot touch money, by construction

This is deliberately **not** part of `firecash-signer`. Chat needs secp256k1,
HMAC and bech32; the money signer uses none of them. Putting them there would
widen the dependency surface of the code that signs payments, and grow the WASM
every wallet loads, to serve a feature many wallets never enable.

So this crate has **no dependency** on `kaspa-shielded-core`, `orchard`,
`zkas-signer`, `kaspa-addresses`, `halo2` or `zip32` — a `cargo tree` check is
part of the review. It cannot derive a spending key, build a bundle, or sign a
payment. A bug in here costs someone a chat pseudonym; it cannot cost them coins.

It is a sibling of `mobile/`, which is its own `[workspace]` root, so it is never
compiled into the published AAR or XCFramework.

## One seed, no signup

Identities follow [NIP-06](https://nips.nostr.com/6):
`m/44'/1237'/<account>'/0/0`. The consequence worth stating plainly: **a ZKas
recovery phrase typed into Damus or Amethyst yields the same identity.** No
signup, nothing new to back up, portable by default, and automatic on any device
that already holds the seed.

`account` doubles as the **per-room pseudonym** index — stable enough inside a
room that others can block you, unlinkable between rooms.

Wallets predating recovery phrases hold a raw 64-hex seed with no BIP-39 seed
behind it, so there is no NIP-06 answer for them. Rather than invent a second
derivation, that secret is expanded under a permanent domain tag into the *same*
BIP-32 code. Those identities are flagged `is_nip06 = false`, because they are
**not** portable to other clients and the UI should say so.

## API

| Function | Purpose |
|---|---|
| `chat_identity(secret, account)` | seed or phrase → `{privkey_hex, pubkey_hex, nsec, npub, is_nip06}` |
| `sign_chat_event(secret, account, kind, tags_json, content, created_at, difficulty, max_ms)` | sign, optionally mining PoW first |
| `sign_chat_event_with_key(privkey_hex, …)` | same, for an **imported** Nostr identity |
| `verify_chat_event(json)` | checks the id **and** the signature |
| `npub_to_hex` / `hex_to_npub` / `nsec_to_hex` | NIP-19; needed for block lists and mentions |
| `pubkey_for_key(privkey_hex)` | x-only pubkey for an imported key |
| `event_difficulty(id_hex)` | leading zero bits, for filtering |

## Choosing a proof-of-work difficulty

Measured on one server core: **~450,000 hashes/s**. A phone in WASM is roughly
2–5× slower.

| difficulty | expected hashes | server (mean) | phone (mean, est.) |
|---|---|---|---|
| 12 | 4,096 | ~0.01 s | ~0.02–0.05 s |
| 16 | 65,536 | ~0.15 s | ~0.3–0.75 s |
| 18 | 262,144 | ~0.6 s | ~1.2–3 s |
| 20 | 1,048,576 | ~2.3 s | ~5–12 s |

**Those are means, not costs.** PoW time is geometrically distributed and the
tail is long — one measured run at difficulty 16 needed 266,179 hashes, 4× the
expectation. Whatever you pick, some messages take several times longer, at
random. Mine off the UI thread, pass a real `max_ms`, and prefer 12–16 over 20.

And treat PoW as a *floor*, not the spam defence: at 450k hashes/s, difficulty 16
still lets one core emit ~7 messages/s. Per-identity rate limiting is what bounds
a spammer; PoW just makes identities cost something to use.

## What is verified

Everything below is a test, not a claim:

- **NIP-06** — both official vectors.
- **BIP-340** — five official vectors plus a rejection case.
- **Cross-client interop** — two real third-party events (fixtures from
  `nbd-wtf/go-nostr`), ids and signatures produced elsewhere, verify here. One
  carries tags and JSON-inside-JSON content, so quote and backslash escaping is
  exercised.
- **NIP-19** — round trip against the official vector; rejects a wrong prefix, a
  mutated checksum, bech32m, and a non-key.
- **Tampering** — content, timestamp, kind, pubkey and a swapped signature are
  all rejected.
- **NIP-01 escaping** — exactly the seven escapes, unicode left alone.
- **PoW** — reaches the target, commits the target in the nonce tag, gives up on
  deadline; a `debug_assert` proves the mining fast path produces the same id as
  the canonical serializer.

```
cargo test                 # debug: fast-path equivalence asserted
cargo test --release
cargo clippy --all-targets # 0 warnings
cargo build --release --target wasm32-unknown-unknown
cargo test --release -- --ignored --nocapture bench_mining
```

## Two serializers, on purpose

NIP-01 fixes the bytes an **id** is hashed over: no whitespace, and exactly seven
escapes (`\n \" \\ \r \t \b \f`). A general JSON encoder cannot produce that —
`serde_json` escapes other control characters as `\uXXXX`, which NIP-01 does not
permit, so an event containing `0x01` would get an id no other client computes.

The **wire** object is the opposite: it must be valid RFC 8259 JSON, where those
characters *must* be `\uXXXX`. Parsing normalises them back, so a receiver
recomputing the id from the parsed fields gets the same id.

So the canonical form is hand-written and used only for the id; `serde_json`
produces the wire form and parses untrusted input, and never produces the
canonical form.
