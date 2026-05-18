package so.prelude.android.auth.dpop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

class JwtTest {
    /** Build a compact JWT with `payload` as the middle segment. Header
     *  and signature are placeholders — `decodeJwtJti` doesn't verify. */
    private fun token(payloadJson: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("{\"alg\":\"none\"}".toByteArray())
        val payload = enc.encodeToString(payloadJson.toByteArray())
        return "$header.$payload.signature"
    }

    @Test
    fun decodeJwtJti_extractsJti() {
        val jti = decodeJwtJti(token("""{"jti":"abc-123","sub":"user"}"""))
        assertEquals("abc-123", jti)
    }

    @Test
    fun decodeJwtJti_returnsNullWhenJtiMissing() {
        assertNull(decodeJwtJti(token("""{"sub":"user"}""")))
    }

    @Test
    fun decodeJwtJti_returnsNullForMalformedTokens() {
        assertNull(decodeJwtJti("only-one-part"))
        assertNull(decodeJwtJti("two.parts"))
        assertNull(decodeJwtJti("not.valid-base64!!!.signature"))
    }

    @Test
    fun decodeJwtJti_returnsNullForOversizedTokens() {
        // 8 KiB + 1 char.
        assertNull(decodeJwtJti("a".repeat(8 * 1024 + 1)))
    }

    @Test
    fun decodeJwtJti_returnsNullForNonObjectPayload() {
        assertNull(decodeJwtJti(token("\"just-a-string\"")))
        assertNull(decodeJwtJti(token("[1,2,3]")))
    }

    @Test
    fun decodeJwtJti_ignoresUnknownClaims() {
        val jti = decodeJwtJti(token("""{"jti":"x","weird":{"nested":true}}"""))
        assertEquals("x", jti)
    }
}
