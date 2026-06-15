package so.prelude.android.auth.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PkceTest {
    @Test
    fun codeChallenge_matchesRfc7636TestVector() {
        // RFC 7636 Appendix B.
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            Pkce.codeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        )
    }

    @Test
    fun generateCodeVerifier_meetsRfcShape() {
        val verifier = Pkce.generateCodeVerifier()
        // 32 bytes base64url-encoded without padding → 43 chars, the
        // RFC minimum; alphabet is the unreserved base64url set.
        assertEquals(43, verifier.length)
        assertTrue(verifier.all { it.isLetterOrDigit() || it == '-' || it == '_' })
    }

    @Test
    fun generateCodeVerifier_isUniquePerCall() {
        assertNotEquals(Pkce.generateCodeVerifier(), Pkce.generateCodeVerifier())
    }
}
