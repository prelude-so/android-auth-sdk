package so.prelude.android.session.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import so.prelude.android.session.PreludeSessionError
import java.util.Base64

/**
 * Tests for [JwtDecoder]. The decoder is strict on structure but
 * lenient on claim *types* — anything that doesn't fit the typed
 * shape silently becomes `null`. The access-token cache and profile
 * readers depend on this contract.
 */
class JwtDecoderTest {
    private fun token(payloadJson: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString(payloadJson.toByteArray())
        return "$header.$payload.signature"
    }

    @Test
    fun decode_returnsTypedClaims() {
        val jwt = JwtDecoder.decode(
            token(
                """{"sub":"user_123","sid":"sess_abc","exp":1800000000,"iat":1700000000,"iss":"prelude","jti":"tok_xyz"}""",
            ),
        )
        assertEquals("user_123", jwt.claims.sub)
        assertEquals("sess_abc", jwt.claims.sid)
        assertEquals(1_800_000_000L, jwt.claims.exp)
        assertEquals(1_700_000_000L, jwt.claims.iat)
        assertEquals("prelude", jwt.claims.iss)
        assertEquals("tok_xyz", jwt.claims.jti)
    }

    @Test
    fun decode_keepsEncodedSegmentsVerbatim() {
        val raw = token("""{"sub":"user_123"}""")
        val jwt = JwtDecoder.decode(raw)
        val rebuilt = "${jwt.encoded.header}.${jwt.encoded.payload}.${jwt.encoded.signature}"
        assertEquals(raw, rebuilt)
    }

    @Test
    fun decode_returnsNullForMissingClaims() {
        // Empty payload — every typed claim absent.
        val jwt = JwtDecoder.decode(token("""{}"""))
        assertNull(jwt.claims.sub)
        assertNull(jwt.claims.sid)
        assertNull(jwt.claims.exp)
        assertNull(jwt.claims.jti)
    }

    @Test
    fun decode_returnsNullForMistypedNumericClaim() {
        // `sub` is a string claim, but a server bug sent it as a number.
        // The decoder should yield `null` rather than coercing.
        val jwt = JwtDecoder.decode(token("""{"sub":123}"""))
        assertNull(jwt.claims.sub)
    }

    @Test
    fun decode_returnsNullForMistypedStringClaim() {
        // Same idea the other way: `exp` should be a number; if the
        // server sent a string, ignore rather than parse.
        val jwt = JwtDecoder.decode(token("""{"exp":"1700000000"}"""))
        assertNull(jwt.claims.exp)
    }

    @Test
    fun decode_throwsForMissingThirdSegment() {
        val ex = assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            JwtDecoder.decode("only.two")
        }
        assertNotNull(ex.message)
    }

    @Test
    fun decode_throwsForEmptySegments() {
        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            JwtDecoder.decode("..")
        }
    }

    @Test
    fun decode_throwsForFourSegments() {
        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            JwtDecoder.decode("a.b.c.d")
        }
    }

    @Test
    fun decode_throwsForInvalidBase64Payload() {
        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            JwtDecoder.decode("aGVhZGVy.!!!not-base64!!!.c2ln")
        }
    }

    @Test
    fun decode_throwsForNonObjectPayload() {
        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            JwtDecoder.decode(token("\"a-string-not-an-object\""))
        }
        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            JwtDecoder.decode(token("[1,2,3]"))
        }
    }

    @Test
    fun decode_ignoresUnknownClaimsAtTopLevel() {
        // `weird` is application-specific and isn't on JwtClaims, but
        // it's still in the raw payload for the profile reader to pick
        // up via `extras`.
        val jwt = JwtDecoder.decode(token("""{"sub":"u","weird":{"nested":true}}"""))
        assertEquals("u", jwt.claims.sub)
        assertNotNull(jwt.payload["weird"])
    }
}
