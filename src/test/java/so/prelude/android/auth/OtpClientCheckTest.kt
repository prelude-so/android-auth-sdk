package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `/otp/check` request shape + error mapping. Finalize-side logic
 * lives in [OtpClientFinalizeTest].
 */
class OtpClientCheckTest {
    @Test
    fun checkOTP_sendsCodeVerbatim() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
                "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.checkOTP("123456")

            val checkBody =
                fixture.http
                    .requestsFor("/v1/session/otp/check")
                    .single()
                    .bodyAsJson()
            assertEquals("123456", checkBody["code"]!!.jsonPrimitive.content)
            Unit
        }

    @Test
    fun checkOTP_missingChallengeToken_throwsStructured() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/check",
            StubHttpSession.Canned.json("{}"),
        )

        assertThrows(PreludeAuthError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        // Finalize must not be called — there's nothing to exchange.
        assertTrue(fixture.http.requestsFor("/v1/session/login/finalize").isEmpty())
        // No tokens persisted on the failure path.
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun checkOTP_emptyChallengeToken_throwsStructured() {
        // Empty string is treated identically to a missing field so a
        // backend regression surfaces the same way regardless of shape.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/check",
            StubHttpSession.Canned.json("""{"challenge_token":""}"""),
        )

        assertThrows(PreludeAuthError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
    }

    @Test
    fun checkOTP_badCheckCode_mapsToInvalidOtpCode() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/check",
            OtpFixtures.apiError("bad_check_code", "wrong code", status = 400),
        )

        assertThrows(PreludeAuthError.InvalidOTPCode::class.java) {
            runBlocking { fixture.client.checkOTP("000000") }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
    }
}
