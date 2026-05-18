package so.prelude.android.auth.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.PreludeJSONValue
import so.prelude.android.auth.PreludeProfile
import java.util.Base64

/**
 * Tests that [PreludeProfile.fromJwt] surfaces every claim from the JWT
 * payload — the typed [PreludeProfile.userId] / [PreludeProfile.sessionId]
 * fields plus everything else via [PreludeProfile.extras] — with JSON
 * types preserved.
 */
class ProfileExtrasTest {
    private fun makeJwt(payloadJson: String): Jwt {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString(payloadJson.toByteArray())
        return JwtDecoder.decode("$header.$payload.signature")
    }

    // MARK: - Typed fields

    @Test
    fun typedFields_areSurfacedFromClaims() {
        val profile = PreludeProfile.fromJwt(makeJwt("""{"sub":"user_123","sid":"sess_abc"}"""))
        assertEquals("user_123", profile.userId)
        assertEquals("sess_abc", profile.sessionId)
    }

    @Test
    fun subAndSid_areNotDuplicatedIntoExtras() {
        val profile =
            PreludeProfile.fromJwt(
                makeJwt("""{"sub":"user_123","sid":"sess_abc","email":"u@example.com"}"""),
            )
        assertNull(profile.extras["sub"])
        assertNull(profile.extras["sid"])
        assertEquals(PreludeJSONValue.Str("u@example.com"), profile.extras["email"])
    }

    // MARK: - Standard JWT claims fall through to extras

    @Test
    fun standardClaimsNotModelledAsTypedFields_appearInExtras() {
        val profile =
            PreludeProfile.fromJwt(
                makeJwt(
                    """{"sub":"u","sid":"s","iss":"https://api.prelude.so","exp":1800000000,"iat":1700000000,"nbf":1700000000,"jti":"tok_xyz","aud":"client_42"}""",
                ),
            )
        assertEquals(PreludeJSONValue.Str("https://api.prelude.so"), profile.extras["iss"])
        assertEquals(PreludeJSONValue.Int(1_800_000_000), profile.extras["exp"])
        assertEquals(PreludeJSONValue.Int(1_700_000_000), profile.extras["iat"])
        assertEquals(PreludeJSONValue.Int(1_700_000_000), profile.extras["nbf"])
        assertEquals(PreludeJSONValue.Str("tok_xyz"), profile.extras["jti"])
        assertEquals(PreludeJSONValue.Str("client_42"), profile.extras["aud"])
    }

    // MARK: - JSON type fidelity

    @Test
    fun customClaimTypes_arePreserved() {
        val profile =
            PreludeProfile.fromJwt(
                makeJwt(
                    // 9_007_199_254_740_993 is above Double's safe-int threshold of 2^53.
                    """
                    {
                      "sub":"user_123",
                      "email":"u@example.com",
                      "email_verified":true,
                      "account_balance":199.95,
                      "user_id":9007199254740993,
                      "roles":["admin","billing"],
                      "profile":{"first_name":"Ada","last_name":"Lovelace"},
                      "middle_name":null
                    }
                    """.trimIndent(),
                ),
            )

        assertEquals(PreludeJSONValue.Str("u@example.com"), profile.extras["email"])
        assertEquals(PreludeJSONValue.Bool(true), profile.extras["email_verified"])
        assertEquals(PreludeJSONValue.Double(199.95), profile.extras["account_balance"])
        // The whole point of carrying `Int` separately from `Double`:
        // 9_007_199_254_740_993 round-tripped through Double would
        // collapse to 9_007_199_254_740_992.
        assertEquals(PreludeJSONValue.Int(9_007_199_254_740_993L), profile.extras["user_id"])
        assertEquals(
            PreludeJSONValue.Array(
                listOf(
                    PreludeJSONValue.Str("admin"),
                    PreludeJSONValue.Str("billing"),
                ),
            ),
            profile.extras["roles"],
        )
        assertEquals(
            PreludeJSONValue.Object(
                mapOf(
                    "first_name" to PreludeJSONValue.Str("Ada"),
                    "last_name" to PreludeJSONValue.Str("Lovelace"),
                ),
            ),
            profile.extras["profile"],
        )
        assertEquals(PreludeJSONValue.Null, profile.extras["middle_name"])
    }

    @Test
    fun booleans_areNotCoercedIntoNumbers() {
        val profile = PreludeProfile.fromJwt(makeJwt("""{"flag_true":true,"flag_false":false}"""))
        assertEquals(PreludeJSONValue.Bool(true), profile.extras["flag_true"])
        assertEquals(PreludeJSONValue.Bool(false), profile.extras["flag_false"])
    }

    @Test
    fun unicodeStrings_areRoundTripped() {
        val profile = PreludeProfile.fromJwt(makeJwt("""{"display_name":"Æsop 文字 🎉"}"""))
        assertEquals(PreludeJSONValue.Str("Æsop 文字 🎉"), profile.extras["display_name"])
    }

    // MARK: - Degenerate payloads

    @Test
    fun emptyPayload_producesEmptyProfile() {
        val profile = PreludeProfile.fromJwt(makeJwt("""{}"""))
        assertNull(profile.userId)
        assertNull(profile.sessionId)
        assertTrue(profile.extras.isEmpty())
    }

    @Test
    fun missingSessionId_stillExposesUserId() {
        val profile = PreludeProfile.fromJwt(makeJwt("""{"sub":"user_123","email":"u@example.com"}"""))
        assertEquals("user_123", profile.userId)
        assertNull(profile.sessionId)
        assertEquals(PreludeJSONValue.Str("u@example.com"), profile.extras["email"])
    }
}
