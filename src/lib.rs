//! `zkas-signer` — client-side Orchard key primitives for ZKas.
//!
//! Compiled to WebAssembly, this runs entirely in the user's browser / device:
//! it turns a 32-byte seed into a `zkas:` shielded address and signs/verifies
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
    /// The `zkas:` shielded address derived from the seed.
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
/// `zkas:` address. Retries the negligibly-rare case where a random seed is
/// not a valid Orchard spending key.
#[wasm_bindgen]
pub fn new_wallet(network: &str) -> Result<Wallet, String> {
    let prefix = prefix_from(network)?;
    loop {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("CSPRNG failed: {e}"))?;
        if let Some(raw) = address_bytes_from_seed(seed) {
            return Ok(Wallet {
                seed_hex: hex::encode(seed),
                address: address_string(prefix, &raw),
            });
        }
    }
}

/// Derive the `zkas:` address for an existing seed on a network.
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
    Ok(Signature {
        address: address_string(prefix, &signed.address),
        signature_hex: hex::encode(blob),
    })
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

    let blob =
        hex::decode(signature_hex.trim()).map_err(|e| format!("signature is not hex: {e}"))?;
    if blob.len() != FVK_LEN + SIG_LEN {
        return Err(format!(
            "signature must be {} bytes (fvk||sig); got {}",
            FVK_LEN + SIG_LEN,
            blob.len()
        ));
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
    let fvk = fvk_bytes_from_seed(seed)
        .ok_or_else(|| "seed is not a valid Orchard spending key".to_string())?;
    Ok(hex::encode(fvk))
}

/// Device half of a **non-custodial payment**. Given the wallet seed and, from the
/// server's `prepare` response, a spend's `alpha` randomizer and the payment `sighash`,
/// returns the 64-byte RedPallas spend-auth signature (hex). The seed never leaves the
/// device; the server applies this signature and broadcasts. No proving circuit.
#[wasm_bindgen]
pub fn sign_spend_auth(
    seed_hex: &str,
    alpha_hex: &str,
    sighash_hex: &str,
) -> Result<String, String> {
    let seed = parse_seed(seed_hex)?;
    let alpha = parse32(alpha_hex, "alpha")?;
    let sighash = parse32(sighash_hex, "sighash")?;
    let sig = sign_spend_auth_from_seed(seed, alpha, sighash)
        .ok_or_else(|| "invalid seed or alpha".to_string())?;
    Ok(hex::encode(sig))
}

/// The ZKas mainnet genesis hash — the shielded sighash's network domain. Pinned
/// here (not taken from the server) so a malicious daemon cannot make the device sign
/// for a different chain, and cannot alter the domain the sighash binds to. Must match
/// `MAINNET_PARAMS.genesis.hash` in consensus.
// ZKas mainnet reset (2026-07-26, Bitcoin-anchored fair-launch), genesis
// b63f7fe8e50402af34790265e299bb1ba63e943b91a59a670e5971b7a9e84e6f.
// MUST equal `MAINNET_PARAMS.genesis.hash` in consensus (zkas-rusty, genesis.rs).
const MAINNET_GENESIS: [u8; 32] = [
    0xb6, 0x3f, 0x7f, 0xe8, 0xe5, 0x04, 0x02, 0xaf, 0x34, 0x79, 0x02, 0x65, 0xe2, 0x99, 0xbb, 0x1b, 0xa6, 0x3e, 0x94, 0x3b, 0x91,
    0xa5, 0x9a, 0x67, 0x0e, 0x59, 0x71, 0xb7, 0xa9, 0xe8, 0x4e, 0x6f,
];

/// The `shielded_sighash_context` of the payment transaction a bundle is carried in —
/// the bytes `payment_tx(vec![]).shielded_sighash_context()` produces. Deterministic
/// and network-independent (transaction version + empty envelope), pinned so the device
/// recomputes the exact sighash the node will check.
const PAYMENT_TX_CONTEXT: &[u8] = &[
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn parse43(hex_str: &str, name: &str) -> Result<[u8; 43], String> {
    let b = hex::decode(hex_str.trim()).map_err(|_| format!("{name} is not valid hex"))?;
    b.try_into().map_err(|_| format!("{name} must be 43 bytes"))
}

/// **The anti-blind-signing entry point** for the non-custodial send.
///
/// Given the server's `prepare` response, this VERIFIES on the device — using only the
/// wallet's own viewing key — that the unsigned `bundle_hex` really pays `to` the amount
/// `amount_sompi`, with any other output being change back to this wallet, and that the
/// fee the bundle actually pays (its public value balance — **never** a number the
/// server reported) is positive and at most `max_fee_sompi`. Without that ceiling a
/// malicious daemon could burn the wallet's entire change as "fee" — collectable by a
/// miner, plausibly the daemon's own pool — while every commitment check still passed.
/// Only if all of that holds does it recompute the sighash **from the verified bundle
/// itself** (never trusting a server-supplied hash or network domain) and return
/// the RedPallas spend-auth signatures.
///
/// `disclosure_json` is the `disclosure` array from `prepare`, `alphas_json` its
/// `spend_auth` array (`[{index, alpha}]`). A malicious server cannot get a signature
/// for anything but the payment the user asked for: any lie fails a note or value
/// commitment here, and a bundle that dodges the checks won't match the sighash this
/// function signs. Returns `[{index, sig}]` JSON on success, or throws with the reason.
#[wasm_bindgen]
pub fn verify_and_sign_payment(
    seed_hex: &str,
    network: &str,
    to_address: &str,
    amount_sompi: u64,
    max_fee_sompi: u64,
    bundle_hex: &str,
    disclosure_json: &str,
    alphas_json: &str,
) -> Result<String, String> {
    use kaspa_shielded_core::bundle::ShieldedBundle;
    use kaspa_shielded_core::payment_check::ActionDisclosure;
    use zkas_signer::{ClaimedIntent, PaymentIntent, PreparedPayment, SoftwareSigner, SpendAuthRequest};

    let seed = parse_seed(seed_hex)?;
    // Decode the recipient from the address the USER typed — never from the server —
    // so the device binds the payment to the intended destination.
    let to_addr = Address::try_from(to_address.trim())
        .map_err(|e| format!("invalid recipient address: {e}"))?;
    let to = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| "recipient is not a shielded Orchard address".to_string())?;

    let genesis = match network {
        "mainnet" => MAINNET_GENESIS,
        other => {
            return Err(format!(
                "unknown network {other}; only mainnet is pinned for on-device verification"
            ))
        }
    };

    let bundle_bytes =
        hex::decode(bundle_hex.trim()).map_err(|_| "bundle_hex is not valid hex".to_string())?;
    let bundle = ShieldedBundle::from_bytes(&bundle_bytes)
        .map_err(|e| format!("bundle_hex does not decode: {e:?}"))?;

    // Parse the server's disclosure.
    #[derive(serde::Deserialize)]
    struct Disc {
        spend_value: u64,
        out_value: u64,
        out_recipient: String,
        out_rseed: String,
        rcv: String,
    }
    let discs: Vec<Disc> =
        serde_json::from_str(disclosure_json).map_err(|e| format!("bad disclosure json: {e}"))?;
    let disclosure: Vec<ActionDisclosure> = discs
        .into_iter()
        .map(|d| {
            Ok(ActionDisclosure {
                spend_value: d.spend_value,
                out_value: d.out_value,
                out_recipient: parse43(&d.out_recipient, "out_recipient")?,
                out_rseed: parse32(&d.out_rseed, "out_rseed")?,
                rcv: parse32(&d.rcv, "rcv")?,
            })
        })
        .collect::<Result<_, String>>()?;

    #[derive(serde::Deserialize)]
    struct AlphaReq {
        index: usize,
        alpha: String,
    }
    #[derive(serde::Serialize)]
    struct SigOut {
        index: usize,
        sig: String,
    }
    let reqs: Vec<AlphaReq> =
        serde_json::from_str(alphas_json).map_err(|e| format!("bad spend_auth json: {e}"))?;
    let spend_auth = reqs
        .into_iter()
        .map(|request| {
            Ok(SpendAuthRequest {
                action_index: request.index,
                alpha: parse32(&request.alpha, "alpha")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // All security policy lives in the shared SDK signer. This WASM crate only
    // decodes the existing JSON/hex compatibility format and encodes the result.
    // In this compatibility path the "claims" are the user's own inputs plus the
    // fee the bundle itself pays, so the signer's claims-vs-intent cross-check is
    // trivially satisfied; the checks that bite are the commitment checks and the
    // max-fee ceiling.
    let signer = SoftwareSigner::new(seed).map_err(|e| e.to_string())?;
    let bundle_fee = u64::try_from(bundle.value_balance).unwrap_or(0);
    let prepared = PreparedPayment {
        version: PreparedPayment::VERSION,
        network_domain: genesis,
        tx_context: PAYMENT_TX_CONTEXT.to_vec(),
        bundle,
        disclosure,
        spend_auth,
        claimed: ClaimedIntent {
            recipient: to,
            amount: amount_sompi,
            fee: bundle_fee,
        },
    };
    let intent = PaymentIntent {
        recipient: to,
        amount: amount_sompi,
        max_fee: max_fee_sompi,
    };
    let signatures = signer
        .verify_and_sign(&genesis, &intent, &prepared)
        .map_err(|e| e.to_string())?;
    let out: Vec<SigOut> = signatures
        .into_iter()
        .map(|signature| SigOut {
            index: signature.action_index,
            sig: hex::encode(signature.signature),
        })
        .collect();
    serde_json::to_string(&out).map_err(|e| format!("serialize sigs: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_wallet_roundtrips_address() {
        let w = new_wallet("mainnet").unwrap();
        assert!(w.address.starts_with("zkas:"), "got {}", w.address);
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
        assert!(w.address.starts_with("zkastest:"), "got {}", w.address);
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
