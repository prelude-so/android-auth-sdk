package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * `/login/finalize` happy path + response error mapping. Persistence
 * semantics (refresh/access write ordering, clock skew, store
 * failures) live in [OtpClientFinalizePersistenceTest].
 */
class OtpClientFinalizeTest {

    @Test
    fun checkOTP_happyPath_returnsUser_persistsRefresh_andCachesAccessToken() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(
                refreshToken = "refresh-v1",
                refreshExpiresAt = "2099-01-01T00:00:00Z",
            ),
        )

        val user = fixture.client.checkOTP("123456")

        assertEquals(OtpFixtures.JWT, user.accessToken)
        assertEquals("user-1", user.profile.userId)

        val record = fixture.refreshTokenStore.get(fixture.domain)
        assertNotNull(record)
        assertEquals("refresh-v1", record!!.refreshToken)
        assertEquals("2099-01-01T00:00:00Z", record.refreshTokenExpiresAt)

        val cached = fixture.accessTokenCache.get(fixture.domain)
        assertNotNull(cached)
        assertEquals(OtpFixtures.JWT, cached!!.accessToken)

        // Finalize body carries the challenge token from /otp/check verbatim.
        val finalizeBody = fixture.http.requestsFor("/v1/session/login/finalize")
            .single().bodyAsJson()
        assertEquals(
            "challenge-abc",
            finalizeBody["challenge_token"]!!.jsonPrimitive.content,
        )
        Unit
    }

    @Test
    fun checkOTP_finalizeReturnsEmptyAccessToken_throwsGeneric() {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to StubHttpSession.Canned.json(
                """{"access_token":"","expires_at":1700003600}""",
            ),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        assertEquals("missing_access_token", thrown.code)
    }

    @Test
    fun checkOTP_invalidChallengeToken_mapsToStructured_andDoesNotPersist() {
        // Race window: challenge token expires (or signing key rotates)
        // before /login/finalize sees it.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.apiError(
                "invalid_challenge_token",
                "expired",
                status = 400,
            ),
        )

        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun checkOTP_malformedAccessToken_throwsGeneric_notInvalidChallengeToken() {
        // The shared JWT decoder reuses `InvalidChallengeToken` for any
        // malformed JWT. The *challenge* token was accepted (we reached
        // makeUser), so re-map to a structured access-token error.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(
                accessToken = "not.a.jwt",
            ),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        assertEquals("invalid_access_token", thrown.code)
    }
}
