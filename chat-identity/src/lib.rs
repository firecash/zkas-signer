//! Chat identity for ZKas: the wallet's recovery phrase → a standard Nostr key.
//!
//! # Why this is its own crate
//!
//! The money signer (`firecash-signer`) derives spending keys and authorises
//! payments. Chat needs secp256k1, HMAC and bech32 — none of which the money
//! signer uses. Adding them there would widen the dependency surface of the code
//! that signs payments, and grow the WASM that every wallet loads, to serve a
//! feature many wallets will never enable.
//!
//! So this crate is deliberately separate and deliberately small:
//!
//! * it does **not** depend on `kaspa-shielded-core`, `orchard`, or `zkas-signer`;
//! * it **cannot** derive an Orchard spending key, build a bundle, or sign a payment;
//! * the money signer does not depend on it, so adding chat changes nothing about
//!   how a payment is produced or verified.
//!
//! A bug in here can cost someone a chat pseudonym. By construction it cannot cost
//! them coins.
//!
//! # What it derives
//!
//! [NIP-06](https://nips.nostr.com/6): `m/44'/1237'/<account>'/0/0` over BIP-32,
//! which is what every Nostr client uses. The consequence is worth stating plainly:
//! **a ZKas recovery phrase typed into Damus or Amethyst yields the same identity.**
//! The user signs up for nothing, backs up nothing new, and is portable by default.
//!
//! `account` doubles as the per-room pseudonym index, so a stable-but-unlinkable
//! identity per room needs no additional mechanism — just a different account.

pub mod event;

use bech32::{ToBase32, Variant};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{NonZeroScalar, Scalar, SecretKey};
use sha2::Sha512;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 hardened-index offset.
const HARDENED: u32 = 0x8000_0000;

/// SLIP-44 coin type for Nostr, fixed by NIP-06. Not ours to choose.
const NOSTR_COIN_TYPE: u32 = 1237;

/// Domain tag for wallets that predate recovery phrases.
///
/// A legacy wallet's secret is a raw 32-byte Orchard spending key with no BIP-39
/// seed behind it, so there is no NIP-06-compatible answer for it. Rather than
/// invent a second derivation, we expand that secret into 64 bytes under a tag
/// that exists nowhere else and feed it to the *same* BIP-32 code below.
///
/// The tag matters: it guarantees this output cannot coincide with any other
/// derivation from the same bytes. **It is permanent** — changing it would move
/// every legacy user's chat identity.
const LEGACY_DOMAIN: &[u8] = b"zkas-chat-identity-v1";

/// A derived chat identity. Mirrors what every Nostr client expects.
#[wasm_bindgen]
#[derive(Clone)]
pub struct ChatIdentity {
    privkey_hex: String,
    pubkey_hex: String,
    nsec: String,
    npub: String,
    nip06: bool,
}

#[wasm_bindgen]
impl ChatIdentity {
    /// 32-byte secret key, hex. **Treat exactly like a private key.**
    #[wasm_bindgen(getter)]
    pub fn privkey_hex(&self) -> String {
        self.privkey_hex.clone()
    }
    /// 32-byte x-only public key, hex — the Nostr `pubkey` field.
    #[wasm_bindgen(getter)]
    pub fn pubkey_hex(&self) -> String {
        self.pubkey_hex.clone()
    }
    /// NIP-19 `nsec1…`. Secret.
    #[wasm_bindgen(getter)]
    pub fn nsec(&self) -> String {
        self.nsec.clone()
    }
    /// NIP-19 `npub1…`. Public; this is the handle others block or follow.
    #[wasm_bindgen(getter)]
    pub fn npub(&self) -> String {
        self.npub.clone()
    }
    /// True when this came from a recovery phrase and is therefore the *standard*
    /// NIP-06 identity, portable to any Nostr client. False for a legacy raw-seed
    /// wallet, whose identity is ZKas-specific (see [`LEGACY_DOMAIN`]).
    #[wasm_bindgen(getter)]
    pub fn is_nip06(&self) -> bool {
        self.nip06
    }
}

/// Derive the chat identity for `account` from the user's secret.
///
/// `secret` is whatever the wallet already holds: a BIP-39 recovery phrase, or a
/// legacy 64-hex seed. `account` is the NIP-06 account index, and doubles as the
/// per-room pseudonym index.
///
/// This accepts the same secret the money signer accepts, and that is the point —
/// one phrase, no second thing to back up. It reads the secret and returns a
/// secp256k1 key; it has no code path that could produce a spending key.
#[wasm_bindgen]
pub fn chat_identity(secret: &str, account: u32) -> Result<ChatIdentity, String> {
    let s = secret.trim();
    if s.is_empty() {
        return Err("enter your recovery phrase".to_string());
    }

    // A 64-hex string is unambiguously the legacy raw seed; BIP-39 words are never
    // hex. This is the same discriminator the money signer uses, kept identical so
    // one secret never means two different things.
    let (mut seed, nip06) = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut raw = hex::decode(s).map_err(|e| format!("seed is not hex: {e}"))?;
        let expanded = legacy_seed(&raw)?;
        raw.zeroize();
        (expanded, false)
    } else {
        (phrase_seed(s)?, true)
    };

    let result = derive_nip06(&seed, account);
    seed.zeroize();
    let sk = result?;

    Ok(encode_identity(sk, nip06))
}

/// BIP-39 phrase → 64-byte seed, normalised the way the rest of the wallet does it
/// (whitespace collapsed, lowercased) so a phrase typed across lines still works.
fn phrase_seed(phrase: &str) -> Result<Vec<u8>, String> {
    let cleaned = phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let mnemonic = bip39::Mnemonic::parse_normalized(&cleaned)
        .map_err(|e| format!("that is not a valid recovery phrase: {e}"))?;
    // No BIP-39 passphrase: NIP-06 test vectors assume the empty passphrase, and a
    // wallet that used one for its spending key would still want one chat identity.
    Ok(mnemonic.to_seed_normalized("").to_vec())
}

/// Legacy raw seed → 64 bytes, under a tag used nowhere else.
fn legacy_seed(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() != 32 {
        return Err("seed must be exactly 32 bytes (64 hex chars)".to_string());
    }
    let mut mac = HmacSha512::new_from_slice(LEGACY_DOMAIN).map_err(|_| "hmac key".to_string())?;
    mac.update(raw);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Walk `m/44'/1237'/account'/0/0` and return the leaf secret key.
fn derive_nip06(seed: &[u8], account: u32) -> Result<SecretKey, String> {
    let (mut key, mut chain) = master(seed)?;
    for index in [44 | HARDENED, NOSTR_COIN_TYPE | HARDENED, account | HARDENED, 0, 0] {
        let (k, c) = ckd_priv(&key, &chain, index)?;
        // `k256`'s Scalar is `Copy`, so intermediate nodes cannot be reliably
        // wiped here; they live and die on the stack. The seed, which is the part
        // worth protecting, IS zeroized by the caller.
        key = k;
        chain = c;
    }
    Ok(key.into_secret_key())
}

/// A BIP-32 private node: the scalar plus its chain code.
struct Node(NonZeroScalar);

impl Node {
    fn bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }
    fn into_secret_key(self) -> SecretKey {
        SecretKey::from(self.0)
    }
    /// Compressed SEC1 public key, as BIP-32's `serP(point(k))`.
    fn public_compressed(&self) -> [u8; 33] {
        let pk = SecretKey::from(self.0).public_key();
        let point = pk.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }
}

/// BIP-32 master node from a seed.
fn master(seed: &[u8]) -> Result<(Node, [u8; 32]), String> {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| "hmac key".to_string())?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    split(&i).ok_or_else(|| "invalid master key from seed".to_string())
}

/// BIP-32 CKDpriv. Hardened when `index >= 2^31`.
fn ckd_priv(parent: &Node, chain: &[u8; 32], index: u32) -> Result<(Node, [u8; 32]), String> {
    let mut mac = HmacSha512::new_from_slice(chain).map_err(|_| "hmac key".to_string())?;
    if index >= HARDENED {
        mac.update(&[0u8]);
        mac.update(&parent.bytes());
    } else {
        mac.update(&parent.public_compressed());
    }
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();

    // ki = (IL + kpar) mod n, invalid if IL >= n or ki == 0.
    let mut il_bytes = [0u8; 32];
    il_bytes.copy_from_slice(&i[..32]);
    let il = Scalar::from_repr_vartime(il_bytes.into())
        .ok_or_else(|| "derived scalar out of range".to_string())?;
    let child = il + parent.0.as_ref();
    let child = NonZeroScalar::new(child)
        .into_option()
        .ok_or_else(|| "derived key is zero".to_string())?;

    let mut chain_out = [0u8; 32];
    chain_out.copy_from_slice(&i[32..]);
    Ok((Node(child), chain_out))
}

/// Split an HMAC-SHA512 output into (scalar, chain code), rejecting out-of-range.
fn split(i: &[u8]) -> Option<(Node, [u8; 32])> {
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&i[..32]);
    let scalar = Scalar::from_repr_vartime(sk_bytes.into())?;
    let nz = NonZeroScalar::new(scalar).into_option()?;
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&i[32..]);
    Some((Node(nz), chain))
}

/// Secret key → the four representations a client needs.
fn encode_identity(sk: SecretKey, nip06: bool) -> ChatIdentity {
    let priv_bytes: [u8; 32] = sk.to_bytes().into();
    // Nostr public keys are x-only: the 32-byte x coordinate, no parity byte.
    let point = sk.public_key().to_encoded_point(true);
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&point.as_bytes()[1..33]);

    ChatIdentity {
        privkey_hex: hex::encode(priv_bytes),
        pubkey_hex: hex::encode(pub_bytes),
        // NIP-19 uses bech32, NOT bech32m.
        nsec: bech32::encode("nsec", priv_bytes.to_base32(), Variant::Bech32)
            .expect("static hrp is valid"),
        npub: bech32::encode("npub", pub_bytes.to_base32(), Variant::Bech32)
            .expect("static hrp is valid"),
        nip06,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two official NIP-06 vectors, verbatim from <https://nips.nostr.com/6>.
    ///
    /// These are the whole point of the crate: if we derive even one byte
    /// differently, a user's phrase yields one identity here and another in every
    /// other Nostr client — the exact "second implementation of key derivation"
    /// failure MOBILE-LIBS warned about.
    #[test]
    fn nip06_official_vectors() {
        let cases = [
            (
                "leader monkey parrot ring guide accident before fence cannon height naive bean",
                "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
                "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp",
                "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
                "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu",
            ),
            (
                "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade",
                "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
                "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
                "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
                "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h",
            ),
        ];
        for (phrase, sk, nsec, pk, npub) in cases {
            let id = chat_identity(phrase, 0).expect("derives");
            assert_eq!(id.privkey_hex(), sk, "private key for {phrase}");
            assert_eq!(id.pubkey_hex(), pk, "public key for {phrase}");
            assert_eq!(id.nsec(), nsec, "nsec for {phrase}");
            assert_eq!(id.npub(), npub, "npub for {phrase}");
            assert!(id.is_nip06());
        }
    }

    /// Phrase formatting must not change the identity, or a user who retypes their
    /// phrase with different capitalisation loses their handle.
    #[test]
    fn phrase_normalisation_is_stable() {
        let canonical =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let messy = "  Leader   MONKEY parrot\nring guide accident before fence cannon height naive BEAN ";
        assert_eq!(
            chat_identity(canonical, 0).unwrap().npub(),
            chat_identity(messy, 0).unwrap().npub()
        );
    }

    /// Per-room pseudonyms: a different account must give an unrelated identity,
    /// which is what stops two rooms being cross-referenced.
    #[test]
    fn accounts_are_distinct() {
        let p = "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let a = chat_identity(p, 0).unwrap();
        let b = chat_identity(p, 1).unwrap();
        let c = chat_identity(p, 2).unwrap();
        assert_ne!(a.npub(), b.npub());
        assert_ne!(b.npub(), c.npub());
        assert_ne!(a.npub(), c.npub());
    }

    /// A legacy raw-seed wallet still gets a usable, stable identity — flagged as
    /// non-NIP-06 so the UI can be honest that it is not portable to other clients.
    #[test]
    fn legacy_seed_is_supported_and_flagged() {
        let seed = "ab".repeat(32);
        let id = chat_identity(&seed, 0).unwrap();
        assert!(!id.is_nip06());
        assert_eq!(id.privkey_hex().len(), 64);
        assert!(id.npub().starts_with("npub1"));
        // Deterministic.
        assert_eq!(id.npub(), chat_identity(&seed, 0).unwrap().npub());
        // And distinct per account, like the phrase path.
        assert_ne!(id.npub(), chat_identity(&seed, 1).unwrap().npub());
    }

    /// The legacy expansion must not collide with treating the same bytes as a
    /// BIP-32 seed directly — that is what the domain tag is for.
    #[test]
    fn legacy_domain_separation_holds() {
        let raw = [0xabu8; 32];
        let tagged = legacy_seed(&raw).unwrap();
        let untagged_key = derive_nip06(&raw, 0).unwrap();
        let tagged_key = derive_nip06(&tagged, 0).unwrap();
        assert_ne!(tagged_key.to_bytes(), untagged_key.to_bytes());
    }

    #[test]
    fn rejects_garbage() {
        assert!(chat_identity("", 0).is_err());
        assert!(chat_identity("not a real phrase at all", 0).is_err());
        // 64 chars but not hex → treated as a phrase, and rejected as one.
        assert!(chat_identity(&"z".repeat(64), 0).is_err());
        // Wrong-length hex is not silently accepted.
        assert!(chat_identity(&"ab".repeat(16), 0).is_err());
    }
}
