package info.zkas.mobile

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.zkas_mobile.Signer
import uniffi.zkas_mobile.SignerException
import uniffi.zkas_mobile.accountAddress
import uniffi.zkas_mobile.generateWallet
import uniffi.zkas_mobile.isValidMnemonic
import uniffi.zkas_mobile.verifyMessage

/**
 * Runs on a real Android runtime, which is the only thing that proves the FFI
 * works at all.
 *
 * Everything else about this library is verified by Rust unit tests on Linux and
 * by "it compiled". Neither touches JNA loading the .so out of the APK, symbol
 * resolution, or the generated Kotlin marshalling values across the boundary — so
 * an UnsatisfiedLinkError or a mismatched signature would look exactly like a
 * green build.
 */
@RunWith(AndroidJUnit4::class)
class FfiSmokeTest {

    @Test
    fun theNativeLibraryLoadsAndAnswers() {
        // The first call is the one that dlopens libzkas_mobile.so through JNA.
        val wallet = generateWallet("mainnet")
        assertNotNull(wallet.address)
        assertTrue("expected a zkas: address, got ${wallet.address}", wallet.address.startsWith("zkas:"))
        assertEquals("a new wallet is a 12-word phrase", 12, wallet.mnemonic.split(" ").size)
    }

    @Test
    fun derivationMatchesWhatTheWalletWouldDo() {
        val wallet = generateWallet("mainnet")
        val signer = Signer.fromSecret(wallet.mnemonic, "mainnet")
        // A phrase signs with account 0 — the same rule the ZKas wallet applies.
        assertEquals(wallet.address, signer.address("mainnet"))
        assertEquals(wallet.address, accountAddress(wallet.mnemonic, "mainnet", 0u))
    }

    @Test
    fun aViewingKeyCrossesTheBoundaryIntact() {
        val signer = Signer.fromSecret(generateWallet("mainnet").mnemonic, "mainnet")
        val fvk = signer.viewingKey()
        assertEquals("a full viewing key is 96 bytes, hex-encoded", 192, fvk.length)
        assertTrue(fvk.all { it.isDigit() || it in 'a'..'f' })
    }

    @Test
    fun signAndVerifyRoundTripThroughNative() {
        val wallet = generateWallet("mainnet")
        val signer = Signer.fromSecret(wallet.mnemonic, "mainnet")
        val sig = signer.signMessage("mainnet", "on device")
        assertTrue(verifyMessage(wallet.address, "on device", sig))
        assertTrue(!verifyMessage(wallet.address, "tampered", sig))
    }

    @Test
    fun errorsArriveAsKotlinExceptionsNotCrashes() {
        // The error mapping is generated code; if it is wrong this is a hard crash
        // rather than a catchable exception.
        try {
            Signer.fromSecret("not a phrase", "mainnet")
            throw AssertionError("expected a SignerException")
        } catch (e: SignerException) {
            assertNotNull(e.message)
        }
        assertTrue(!isValidMnemonic("not a phrase"))
    }

    @Test
    fun aMalformedPaymentIsRefusedAcrossTheBoundary() {
        val signer = Signer.fromSecret(generateWallet("mainnet").mnemonic, "mainnet")
        try {
            signer.verifyAndSignPayment(
                "testnet", "zkas:whatever", 1000uL, 10000uL, "00", "[]", "[]",
            )
            throw AssertionError("signed a payment it should have refused")
        } catch (e: SignerException) {
            assertNotNull(e.message)
        }
    }
}
