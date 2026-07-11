//! `firecash-signer` — client-side Orchard key primitives for FireCash.
//!
//! Compiled to WebAssembly, this runs entirely in the user's browser / device:
//! it turns a 32-byte seed into a `firecash:` shielded address and signs/verifies
//! ownership messages, **without** the Halo 2 proving circuit. That keeps the WASM
//! small and lets keys never leave the device — the basis for the paper wallet,
//! the on-device mobile signer, and non-custodial web-wallet claims.
//!
//! It deliberately does **not** build shielded *transactions* (that needs the
//! proving circuit); a spend is proven server-side (viewing key only) and signed
//! here (spend key only), per Orchard's prove/sign split.
//!
//! ## Interop
//! `sign` emits `fvk ‖ sig` hex exactly as the `shielded-pay` CLI does, and
//! `verify` accepts the same, so signatures round-trip with the node tooling and
//! the mining pool's signature-authenticated claim.
//!
//! Errors are returned as `String` (surfaced to JS as a thrown value), which keeps
//! the API dependency-light and the native unit tests ergonomic.

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_shielded_core::message::{
    fvk_bytes_from_seed, sign_message, sign_spend_auth_from_seed, verify_message, FVK_LEN, SIG_LEN,
};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use wasm_bindgen::prelude::*;

/// A freshly generated wallet: the secret seed and its public address.
#[wasm_bindgen(getter_with_clone)]
pub struct Wallet {
    /// 32-byte spending seed, hex-encoded. **This is the secret** — whoever holds
    /// it controls the funds.
    pub seed_hex: String,
    /// The `firecash:` shielded address derived from the seed.
    pub address: String,
}

/// A message signature asserting control of an address.
#[wasm_bindgen(getter_with_clone)]
pub struct Signature {
    /// The address the signature asserts control of.
    pub address: String,
    /// `fvk ‖ sig`, hex-encoded (96 + 64 bytes). Discloses viewing capability by
    /// design — the FVK binds the signature to the address.
    pub signature_hex: String,
}

fn prefix_from(network: &str) -> Result<Prefix, String> {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(Prefix::Mainnet),
        "testnet" => Ok(Prefix::Testnet),
        "devnet" => Ok(Prefix::Devnet),
        "simnet" => Ok(Prefix::Simnet),
        other => Err(format!("unknown network: {other}")),
    }
}

fn parse_seed(seed_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(seed_hex.trim()).map_err(|e| format!("seed is not hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| "seed must be exactly 32 bytes (64 hex chars)".to_string())
}

fn parse32(hex_str: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("{what} is not hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{what} must be exactly 32 bytes"))
}

fn address_string(prefix: Prefix, raw: &[u8; 43]) -> String {
    // `String::from(&Address)` yields the bare bech32; `Display` would append a tag.
    String::from(&Address::new(prefix, Version::ShieldedOrchard, raw))
}

/// Generate a brand-new wallet: a random 32-byte seed (browser CSPRNG) and its
/// `firecash:` address. Retries the negligibly-rare case where a random seed is
/// not a valid Orchard spending key.
#[wasm_bindgen]
pub fn new_wallet(network: &str) -> Result<Wallet, String> {
    let prefix = prefix_from(network)?;
    loop {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("CSPRNG failed: {e}"))?;
        if let Some(raw) = address_bytes_from_seed(seed) {
            return Ok(Wallet { seed_hex: hex::encode(seed), address: address_string(prefix, &raw) });
        }
    }
}

/// Derive the `firecash:` address for an existing seed on a network.
#[wasm_bindgen]
pub fn address_from_seed(seed_hex: &str, network: &str) -> Result<String, String> {
    let prefix = prefix_from(network)?;
    let seed = parse_seed(seed_hex)?;
    let raw = address_bytes_from_seed(seed)
        .ok_or_else(|| "seed is not a valid Orchard spending key".to_string())?;
    Ok(address_string(prefix, &raw))
}

/// Sign `message`, proving control of the seed's address on `network`. The
/// returned `signature_hex` is `fvk ‖ sig`, interoperable with `shielded-pay` and
/// the mining-pool claim verifier.
#[wasm_bindgen]
pub fn sign(seed_hex: &str, network: &str, message: &str) -> Result<Signature, String> {
    let prefix = prefix_from(network)?;
    let seed = parse_seed(seed_hex)?;
    let tag = prefix.to_string();
    let signed = sign_message(seed, tag.as_bytes(), message.as_bytes(), rand::rngs::OsRng)
        .ok_or_else(|| "seed is not a valid Orchard spending key".to_string())?;
    let mut blob = Vec::with_capacity(FVK_LEN + SIG_LEN);
    blob.extend_from_slice(&signed.fvk);
    blob.extend_from_slice(&signed.sig);
    Ok(Signature { address: address_string(prefix, &signed.address), signature_hex: hex::encode(blob) })
}

/// Verify that `signature_hex` (`fvk ‖ sig`) proves control of `address` over
/// `message`. Returns `true` iff valid. The network is taken from the address
/// prefix, matching how the signature was produced.
#[wasm_bindgen]
pub fn verify(address: &str, message: &str, signature_hex: &str) -> Result<bool, String> {
    let addr = Address::try_from(address.trim()).map_err(|e| format!("invalid address: {e}"))?;
    let tag = addr.prefix.to_string();
    let raw = orchard_recipient_bytes(&addr)
        .ok_or_else(|| "address is not a shielded Orchard address".to_string())?;

    let blob = hex::decode(signature_hex.trim()).map_err(|e| format!("signature is not hex: {e}"))?;
    if blob.len() != FVK_LEN + SIG_LEN {
        return Err(format!("signature must be {} bytes (fvk||sig); got {}", FVK_LEN + SIG_LEN, blob.len()));
    }
    let fvk: [u8; FVK_LEN] = blob[..FVK_LEN].try_into().expect("checked length");
    let sig: [u8; SIG_LEN] = blob[FVK_LEN..].try_into().expect("checked length");

    Ok(verify_message(&raw, tag.as_bytes(), message.as_bytes(), &fvk, &sig).is_ok())
}

/// The wallet's full viewing key (`ak ‖ nk ‖ rivk`, 96 bytes) as hex, derived from
/// the seed on-device. Send this to the daemon's non-custodial `/prepare` endpoint so
/// it can scan watch-only and build the payment proof. Grants viewing, not spend.
#[wasm_bindgen]
pub fn fvk_hex(seed_hex: &str) -> Result<String, String> {
    let seed = parse_seed(seed_hex)?;
    let fvk = fvk_bytes_from_seed(seed).ok_or_else(|| "seed is not a valid Orchard spending key".to_string())?;
    Ok(hex::encode(fvk))
}

/// Device half of a **non-custodial payment**. Given the wallet seed and, from the
/// server's `prepare` response, a spend's `alpha` randomizer and the payment `sighash`,
/// returns the 64-byte RedPallas spend-auth signature (hex). The seed never leaves the
/// device; the server applies this signature and broadcasts. No proving circuit.
#[wasm_bindgen]
pub fn sign_spend_auth(seed_hex: &str, alpha_hex: &str, sighash_hex: &str) -> Result<String, String> {
    let seed = parse_seed(seed_hex)?;
    let alpha = parse32(alpha_hex, "alpha")?;
    let sighash = parse32(sighash_hex, "sighash")?;
    let sig = sign_spend_auth_from_seed(seed, alpha, sighash).ok_or_else(|| "invalid seed or alpha".to_string())?;
    Ok(hex::encode(sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_wallet_roundtrips_address() {
        let w = new_wallet("mainnet").unwrap();
        assert!(w.address.starts_with("firecash:"), "got {}", w.address);
        // Re-deriving from the seed yields the same address (deterministic).
        let again = address_from_seed(&w.seed_hex, "mainnet").unwrap();
        assert_eq!(w.address, again);
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let w = new_wallet("mainnet").unwrap();
        let sig = sign(&w.seed_hex, "mainnet", "i control this address").unwrap();
        assert_eq!(sig.address, w.address);
        assert!(verify(&w.address, "i control this address", &sig.signature_hex).unwrap());
    }

    #[test]
    fn wrong_message_fails_verify() {
        let w = new_wallet("mainnet").unwrap();
        let sig = sign(&w.seed_hex, "mainnet", "message A").unwrap();
        assert!(!verify(&w.address, "message B", &sig.signature_hex).unwrap());
    }

    #[test]
    fn other_seed_cannot_forge() {
        let victim = new_wallet("mainnet").unwrap();
        let attacker = new_wallet("mainnet").unwrap();
        let atk_sig = sign(&attacker.seed_hex, "mainnet", "pay me").unwrap();
        // Attacker's signature does not verify against the victim's address.
        assert!(!verify(&victim.address, "pay me", &atk_sig.signature_hex).unwrap());
    }

    #[test]
    fn testnet_address_prefix() {
        let w = new_wallet("testnet").unwrap();
        assert!(w.address.starts_with("firecashtest:"), "got {}", w.address);
    }

    #[test]
    fn bad_seed_length_is_error() {
        assert!(address_from_seed("abcd", "mainnet").is_err());
        assert!(sign("abcd", "mainnet", "x").is_err());
    }

    #[test]
    fn unknown_network_is_error() {
        assert!(new_wallet("bitcoin").is_err());
    }
}
