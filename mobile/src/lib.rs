//! ZKas for iOS and Android — key custody and payment authorization.
//!
//! This is a binding, not an implementation. Every function here calls
//! `firecash-signer`, the crate the ZKas wallet itself signs with, so a phone and
//! the wallet derive the same keys and produce the same signatures by
//! construction. A second implementation of key derivation would be a second
//! chance to derive an address nobody can spend from.
//!
//! ## What this library does NOT do: proving
//!
//! Building the Halo 2 proof for a shielded payment costs roughly 0.79
//! core-seconds PER NOTE SPENT, so a ten-note payment is about eight
//! core-seconds of sustained CPU. That belongs on the wallet daemon, and the
//! protocol is built that way: the daemon proves, and this device VERIFIES the
//! resulting bundle pays exactly what the user asked before authorizing it.
//!
//! So the flow an app implements is:
//!
//! 1. `Signer::from_secret` — on device, from the user's phrase or key.
//! 2. `viewing_key()` → `POST /api/wallet/watch` — the daemon can now see this
//!    wallet's notes. It cannot spend them.
//! 3. `POST /api/wallet/prepare` — the daemon returns an UNSIGNED bundle.
//! 4. `verify_and_sign_payment(...)` — on device. This is the security boundary.
//! 5. `POST /api/wallet/submit` — with the signatures from step 4.
//!
//! ## Where the key belongs
//!
//! In the iOS Keychain or the Android Keystore. Never in `UserDefaults`,
//! `SharedPreferences`, or a file. `Signer` zeroizes its copy when dropped, which
//! is all a library can do — it cannot clean up a copy the app made elsewhere.

use std::sync::Arc;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SignerError {
    /// The underlying signer refused the input. Safe to show: it never contains
    /// key material.
    ///
    /// The field is `reason`, not `message`. UniFFI turns this into a Kotlin
    /// class extending Exception, which already declares `message` — naming it
    /// that produces a conflicting declaration that fails the Kotlin build while
    /// Swift compiles happily, so the clash only shows up on one platform.
    #[error("{reason}")]
    Signer { reason: String },
}

fn err(reason: String) -> SignerError {
    SignerError::Signer { reason }
}

/// A newly generated wallet. Both fields are returned once and never again.
#[derive(uniffi::Record)]
pub struct GeneratedWallet {
    /// The 12-word BIP-39 recovery phrase. **This is the secret.** It restores
    /// the wallet anywhere, forever.
    pub mnemonic: String,
    /// The `zkas:` shielded address the phrase derives.
    pub address: String,
}

/// Holds a spending key and authorizes payments with it.
///
/// Construct it once per session from Keychain/Keystore material and let it drop
/// when done; the key is zeroized on drop.
#[derive(uniffi::Object)]
pub struct Signer {
    /// A recovery phrase or a 64-hex key. Held as `Zeroizing` so it is wiped when
    /// this object is dropped rather than left in freed memory.
    secret: Zeroizing<String>,
}

#[uniffi::export]
impl Signer {
    /// From a 12-word recovery phrase or a legacy 64-character hex key.
    ///
    /// Validated immediately by deriving an address, so a typo fails here rather
    /// than at the moment someone tries to spend.
    #[uniffi::constructor]
    pub fn from_secret(secret: String, network: String) -> Result<Arc<Self>, SignerError> {
        let signer = Self { secret: Zeroizing::new(secret.trim().to_owned()) };
        signer.address(network)?;
        Ok(Arc::new(signer))
    }

    /// The `zkas:` address that receives funds. Public — safe to display, print
    /// and share.
    pub fn address(&self, network: String) -> Result<String, SignerError> {
        let hex = self.account_key()?;
        firecash_signer::address_from_seed(&hex, &network).map_err(err)
    }

    /// The 96-byte full viewing key, hex-encoded — what a wallet service needs to
    /// find this wallet's notes.
    ///
    /// Handing it over discloses every amount and memo this wallet ever receives,
    /// forever, and cannot be revoked without moving the funds. It carries no
    /// spending authority.
    pub fn viewing_key(&self) -> Result<String, SignerError> {
        let hex = self.account_key()?;
        firecash_signer::fvk_hex(&hex).map_err(err)
    }

    /// Sign a message, proving control of this wallet's address without spending.
    /// Returns `fvk ‖ sig` hex, which discloses viewing capability by design.
    pub fn sign_message(&self, network: String, message: String) -> Result<String, SignerError> {
        let hex = self.account_key()?;
        firecash_signer::sign(&hex, &network, &message).map(|s| s.signature_hex).map_err(err)
    }

    /// Authorize a payment the daemon prepared — the security boundary of the
    /// whole protocol.
    ///
    /// This reconstructs the bundle, checks it pays exactly `to_address` and
    /// `amount_sompi` with everything else returning as change, checks the fee is
    /// within `max_fee_sompi`, recomputes the sighash from the bundle it just
    /// CHECKED, and only then signs. A daemon that returns a payment to itself is
    /// refused here.
    ///
    /// Pass the recipient and amount the USER entered, never values echoed back
    /// by the daemon — that is what makes the check meaningful.
    ///
    /// There is deliberately no "just sign this" call in this library. A raw
    /// spend-authorization signature over a bundle nobody checked is a blind
    /// signature, and it is exactly what this step exists to prevent.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_sign_payment(
        &self,
        network: String,
        to_address: String,
        amount_sompi: u64,
        max_fee_sompi: u64,
        bundle_hex: String,
        disclosure_json: String,
        alphas_json: String,
    ) -> Result<String, SignerError> {
        let hex = self.account_key()?;
        firecash_signer::verify_and_sign_payment(
            &hex,
            &network,
            &to_address,
            amount_sompi,
            max_fee_sompi,
            &bundle_hex,
            &disclosure_json,
            &alphas_json,
        )
        .map_err(err)
    }

    /// The 64-hex key this signer actually signs with.
    ///
    /// A phrase is the DEVICE master and account 0 is its first wallet, which is
    /// the same rule the wallet applies — so a phrase yields the same address
    /// here as it does there. A 64-hex secret is already a key and is used as-is.
    fn account_key(&self) -> Result<String, SignerError> {
        let s: &str = &self.secret;
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(s.to_owned());
        }
        firecash_signer::account_seed_hex(s, 0).map_err(err)
    }
}

/// Generate a new wallet: a 12-word recovery phrase and its address.
///
/// Twelve words is not a shortcut. An Orchard key lives on the Pallas curve,
/// whose ~128-bit security caps what any seed can buy; a longer phrase would be
/// more to write down for no more strength.
#[uniffi::export]
pub fn generate_wallet(network: String) -> Result<GeneratedWallet, SignerError> {
    let w = firecash_signer::new_wallet_mnemonic(&network).map_err(err)?;
    Ok(GeneratedWallet { mnemonic: w.mnemonic, address: w.address })
}

/// True for a valid BIP-39 phrase — checksum included, so a mistyped word is
/// caught before it becomes an empty wallet.
#[uniffi::export]
pub fn is_valid_mnemonic(phrase: String) -> bool {
    firecash_signer::is_valid_mnemonic(&phrase)
}

/// The address of one account of a phrase, without handling the key.
///
/// Accounts are `m/32'/111111'/account'`. Useful for showing a user their
/// accounts, or discovering which ones have history, without deriving keys.
#[uniffi::export]
pub fn account_address(phrase: String, network: String, account: u32) -> Result<String, SignerError> {
    firecash_signer::account_address(&phrase, &network, account).map_err(err)
}

/// Check a signature made by `Signer::sign_message` against an address.
/// Needs no key, so it is safe to run anywhere.
#[uniffi::export]
pub fn verify_message(address: String, message: String, signature_hex: String) -> Result<bool, SignerError> {
    firecash_signer::verify(&address, &message, &signature_hex).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "mainnet";

    /// The one piece of logic in this crate that is NOT just a call through:
    /// deciding which key a secret signs with. Everything else is delegated to
    /// `firecash-signer`, so it cannot drift; this can, and a drift here means a
    /// phone showing an address the wallet cannot spend from.
    #[test]
    fn a_phrase_signs_with_account_zero_exactly_as_the_wallet_does() {
        let w = generate_wallet(NET.into()).unwrap();
        let signer = Signer::from_secret(w.mnemonic.clone(), NET.into()).unwrap();

        // The wallet stores accountSeedHex(phrase, 0) and signs with it.
        let wallet_key = firecash_signer::account_seed_hex(&w.mnemonic, 0).unwrap();
        let wallet_address = firecash_signer::address_from_seed(&wallet_key, NET).unwrap();

        assert_eq!(signer.address(NET.into()).unwrap(), wallet_address);
        // And the address generation itself agrees, by a third route.
        assert_eq!(w.address, wallet_address);
        assert_eq!(account_address(w.mnemonic, NET.into(), 0).unwrap(), wallet_address);
    }

    /// A 64-hex secret is already a spending key. Deriving an account FROM it
    /// would produce a different, empty wallet — the failure mode is silent, so
    /// it is pinned.
    #[test]
    fn a_legacy_hex_key_is_used_as_is_and_never_derived_from() {
        let key = "ab".repeat(32);
        let signer = Signer::from_secret(key.clone(), NET.into()).unwrap();
        assert_eq!(
            signer.address(NET.into()).unwrap(),
            firecash_signer::address_from_seed(&key, NET).unwrap()
        );
        // Uppercase is the same key, not a different wallet.
        let upper = Signer::from_secret(key.to_uppercase(), NET.into()).unwrap();
        assert_eq!(upper.address(NET.into()).unwrap(), signer.address(NET.into()).unwrap());
    }

    #[test]
    fn a_phrase_and_its_derived_key_are_the_same_wallet() {
        let w = generate_wallet(NET.into()).unwrap();
        let derived = firecash_signer::account_seed_hex(&w.mnemonic, 0).unwrap();
        let from_phrase = Signer::from_secret(w.mnemonic, NET.into()).unwrap();
        let from_key = Signer::from_secret(derived, NET.into()).unwrap();
        assert_eq!(from_phrase.address(NET.into()).unwrap(), from_key.address(NET.into()).unwrap());
        assert_eq!(from_phrase.viewing_key().unwrap(), from_key.viewing_key().unwrap());
    }

    #[test]
    fn accounts_are_different_wallets() {
        let w = generate_wallet(NET.into()).unwrap();
        let a0 = account_address(w.mnemonic.clone(), NET.into(), 0).unwrap();
        let a1 = account_address(w.mnemonic, NET.into(), 1).unwrap();
        assert_ne!(a0, a1, "account 1 must not collide with account 0");
    }

    #[test]
    fn the_viewing_key_is_96_bytes_and_carries_no_spending_power() {
        let w = generate_wallet(NET.into()).unwrap();
        let fvk = Signer::from_secret(w.mnemonic, NET.into()).unwrap().viewing_key().unwrap();
        assert_eq!(fvk.len(), 192, "a full viewing key is 96 bytes, hex-encoded");
        assert!(fvk.chars().all(|c| c.is_ascii_hexdigit()));
        // It is not a secret this library will accept as one.
        assert!(Signer::from_secret(fvk, NET.into()).is_err());
    }

    #[test]
    fn a_signed_message_verifies_against_the_address() {
        let w = generate_wallet(NET.into()).unwrap();
        let signer = Signer::from_secret(w.mnemonic, NET.into()).unwrap();
        let address = signer.address(NET.into()).unwrap();
        let sig = signer.sign_message(NET.into(), "hello".into()).unwrap();
        assert!(verify_message(address.clone(), "hello".into(), sig.clone()).unwrap());
        // A different message must not verify against the same signature.
        assert!(!verify_message(address, "hell0".into(), sig).unwrap());
    }

    #[test]
    fn a_bad_secret_fails_at_construction_not_at_spend_time() {
        assert!(Signer::from_secret("not a phrase at all".into(), NET.into()).is_err());
        assert!(Signer::from_secret("".into(), NET.into()).is_err());
        // 63 hex characters: a truncated key, which must not be treated as a phrase.
        assert!(Signer::from_secret("a".repeat(63), NET.into()).is_err());
    }

    /// The authorization path, which had no test at all — in this crate or in
    /// firecash-signer, whose thirteen tests cover derivation, addresses and
    /// message signing and never touch it.
    ///
    /// These cover the REFUSALS, and that is the half that protects money: every
    /// one of them must return an error rather than a signature. A bug that
    /// signs something malformed is the same class of bug as one that signs a
    /// payment to an attacker.
    ///
    /// What is still missing, and cannot be faked: the positive path, and the
    /// case that matters most — a well-formed bundle that pays SOMEONE ELSE must
    /// be refused. Both need a real prepared bundle from a funded wallet, so they
    /// belong in an integration test against a daemon, not here.
    mod authorization {
        use super::*;

        fn signer() -> Arc<Signer> {
            Signer::from_secret("ab".repeat(32), NET.into()).unwrap()
        }

        fn attempt(network: &str, to: &str, bundle: &str, disclosure: &str, alphas: &str) -> Result<String, SignerError> {
            signer().verify_and_sign_payment(
                network.into(), to.into(), 1_000, 10_000,
                bundle.into(), disclosure.into(), alphas.into(),
            )
        }

        const ADDR: &str = "zkas:p8a4neush78c56rcqraed3esy280ar2xatee3zucz39hyyxgjz80ph6mfj0430v4r3ek6qgj8dkk0ll";

        /// Asserting the REASON, not just that something failed. Four `is_err()`
        /// checks can all be passing for one reason — and one of them was: the
        /// disclosure case never reached disclosure parsing, it died earlier on
        /// the bundle, so it asserted a refusal it never tested.
        fn refusal(r: Result<String, SignerError>, expect: &str) {
            match r {
                Ok(_) => panic!("signed something it should have refused"),
                Err(e) => {
                    let m = format!("{e}");
                    assert!(m.contains(expect), "refused, but for the wrong reason: {m}");
                }
            }
        }

        #[test]
        fn an_unknown_network_is_refused_rather_than_signed_against_the_wrong_chain() {
            // The sighash is domain-separated by genesis. Signing against the
            // wrong one produces a signature valid on a chain the user did not
            // mean to pay on. Checked before the bundle, so this is reachable.
            refusal(attempt("testnet", ADDR, "00", "[]", "[]"), "unknown network");
            refusal(attempt("", ADDR, "00", "[]", "[]"), "unknown network");
            refusal(attempt("bitcoin", ADDR, "00", "[]", "[]"), "unknown network");
        }

        #[test]
        fn a_recipient_that_is_not_a_shielded_address_is_refused() {
            refusal(attempt(NET, "not-an-address", "00", "[]", "[]"), "recipient address");
            refusal(attempt(NET, "", "00", "[]", "[]"), "recipient address");
            // Right shape, wrong checksum.
            let mut bad = ADDR.to_owned();
            bad.pop();
            bad.push('q');
            refusal(attempt(NET, &bad, "00", "[]", "[]"), "recipient address");
        }

        #[test]
        fn a_malformed_bundle_is_refused() {
            refusal(attempt(NET, ADDR, "zz", "[]", "[]"), "bundle_hex");     // not hex
            refusal(attempt(NET, ADDR, "00ff", "[]", "[]"), "bundle_hex");   // hex, not a bundle
            refusal(attempt(NET, ADDR, "", "[]", "[]"), "bundle_hex");
        }

        // NOT TESTED HERE, deliberately: the disclosure and alpha parsing, the
        // check that the bundle pays the stated recipient and amount, and the fee
        // ceiling. All of them sit BEHIND bundle decoding, so no input built from
        // strings can reach them — an attempt to test them here only re-tests the
        // bundle parser while appearing to cover the payment check.
        //
        // They need a real prepared bundle from a funded wallet, which makes them
        // an integration test against a daemon. That is the gap, and it is the
        // half that matters most: a well-formed bundle paying SOMEONE ELSE must be
        // refused, and nothing here proves it is.

        #[test]
        fn nothing_here_ever_returns_a_signature() {
            // The point of the whole group: not one malformed input produces
            // something an app could submit.
            for (n, t, b, d, a) in [
                ("testnet", ADDR, "00", "[]", "[]"),
                (NET, "nope", "00", "[]", "[]"),
                (NET, ADDR, "zz", "[]", "[]"),
                (NET, ADDR, "00", "x", "[]"),
            ] {
                assert!(attempt(n, t, b, d, a).is_err(), "signed a malformed request: {n} {t} {b} {d} {a}");
            }
        }
    }

    #[test]
    fn mnemonic_validation_checks_the_checksum() {
        // Fixed vectors, not a random phrase with one word swapped. A 12-word
        // BIP-39 phrase carries only FOUR checksum bits, so a random substitution
        // still validates about one time in sixteen — an assertion that it always
        // fails is a test that fails ~6% of the time forever. CI found it on the
        // second run.
        //
        // The canonical all-zero-entropy vector, and the same words with the
        // final one changed so the checksum no longer matches.
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let broken = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(is_valid_mnemonic(valid.into()));
        assert!(!is_valid_mnemonic(broken.into()), "the BIP-39 checksum must reject this");
        // Not a phrase at all.
        assert!(!is_valid_mnemonic("hello world".into()));
        // And whatever we generate is always valid.
        assert!(is_valid_mnemonic(generate_wallet(NET.into()).unwrap().mnemonic));
    }
}
