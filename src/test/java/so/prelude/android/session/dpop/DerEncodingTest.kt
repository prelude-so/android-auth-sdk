package so.prelude.android.session.dpop

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class DerEncodingTest {
    /**
     * Round-trip a real ECDSA P-256 signature through the DER → raw
     * converter. The output must be exactly 64 bytes (32 + 32) for a
     * P-256 signature regardless of where the DER form lands in its
     * possible size range (70–72 bytes, depending on `r`/`s` MSB).
     */
    @Test
    fun derToRaw_p256_signaturesAreFixedWidth() {
        val gen = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val keyPair = gen.generateKeyPair()
        val signer = Signature.getInstance("SHA256withECDSA")

        // Sign a few different payloads — `r` and `s` are random, so this
        // sweeps the leading-zero / 33-byte / sub-32-byte edges over the
        // course of the run rather than relying on a single signature.
        repeat(20) { i ->
            signer.initSign(keyPair.private)
            signer.update("sample-$i".toByteArray())
            val der = signer.sign()
            val raw = derToRawEcdsa(der, coordinateBytes = 32)
            assertEquals("raw signature must be exactly 64 bytes for P-256", 64, raw.size)
        }
    }

    @Test
    fun derToRaw_handlesShortIntegers_byLeftPadding() {
        // SEQUENCE { INTEGER 0x01, INTEGER 0x02 } — both components are 1 byte.
        // The converter must left-pad each to 32 bytes.
        val der = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)
        val raw = derToRawEcdsa(der, coordinateBytes = 32)
        val expected = ByteArray(64).also {
            it[31] = 0x01
            it[63] = 0x02
        }
        assertArrayEquals(expected, raw)
    }

    @Test
    fun derToRaw_stripsLeadingSignByte() {
        // INTEGERs are signed in DER. A 32-byte value with MSB set is encoded
        // with a leading 0x00 byte, making it 33 bytes on the wire. The
        // converter must drop that pad byte before left-padding to 32.
        val padded = ByteArray(33).also {
            it[0] = 0x00
            it[1] = 0x80.toByte()
            for (i in 2..32) it[i] = 0xAA.toByte()
        }
        val der = ByteArray(2 + 2 + 33 + 2 + 1).apply {
            this[0] = 0x30
            this[1] = (size - 2).toByte()
            this[2] = 0x02
            this[3] = 33
            padded.copyInto(this, destinationOffset = 4)
            this[37] = 0x02
            this[38] = 1
            this[39] = 0x05
        }
        val raw = derToRawEcdsa(der, coordinateBytes = 32)
        assertEquals(64, raw.size)
        assertEquals(0x80.toByte(), raw[0])
        assertEquals(0x05.toByte(), raw[63])
    }

    @Test
    fun derToRaw_rejectsNonSequenceTag() {
        val der = byteArrayOf(0x31, 0x02, 0x02, 0x00) // SET instead of SEQUENCE
        assertThrows(DPoPKeyStoreError.MalformedSignature::class.java) {
            derToRawEcdsa(der, coordinateBytes = 32)
        }
    }

    @Test
    fun derToRaw_rejectsTruncatedBlob() {
        // SEQUENCE header claiming 100 bytes, but only 1 follows.
        val der = byteArrayOf(0x30, 100, 0x02)
        assertThrows(DPoPKeyStoreError.MalformedSignature::class.java) {
            derToRawEcdsa(der, coordinateBytes = 32)
        }
    }

    @Test
    fun derToRaw_rejectsOversizedComponent() {
        // INTEGER claiming 64 bytes — too big for P-256.
        val r = ByteArray(64) { 0xAA.toByte() }
        val der = ByteArray(2 + 2 + 64 + 2 + 1).apply {
            this[0] = 0x30
            this[1] = (size - 2).toByte()
            this[2] = 0x02
            this[3] = 64
            r.copyInto(this, destinationOffset = 4)
            this[68] = 0x02
            this[69] = 1
            this[70] = 0x01
        }
        assertThrows(DPoPKeyStoreError.MalformedSignature::class.java) {
            derToRawEcdsa(der, coordinateBytes = 32)
        }
    }

    /**
     * Regression: `MalformedSignature` must be a class, not an `object`.
     * A shared singleton captures `fillInStackTrace` once at class-init,
     * so every throw site reports the same stack and accumulates
     * suppressed exceptions across unrelated callers (the same pattern
     * `PreludeSessionError.Timeout` was fixed for).
     */
    @Test
    fun malformedSignature_isFreshInstancePerThrow() {
        val firstBad = byteArrayOf(0x31, 0x02, 0x02, 0x00)
        val secondBad = byteArrayOf(0x30, 100, 0x02)

        val first = runCatching { derToRawEcdsa(firstBad, coordinateBytes = 32) }
            .exceptionOrNull()
        val second = runCatching { derToRawEcdsa(secondBad, coordinateBytes = 32) }
            .exceptionOrNull()

        org.junit.Assert.assertNotSame(
            "Two MalformedSignature throws returned the same instance — singleton regressed.",
            first,
            second,
        )
    }
}
