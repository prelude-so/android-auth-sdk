package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.store.FailingRefreshTokenStorage
import so.prelude.android.session.store.InMemoryRefreshTokenStorage

/**
 * Token persistence after `/login/finalize`: refresh-vs-access
 * write ordering, clock skew adjustment, and store failures.
 * Happy path + response decoding live in [OtpClientFinalizeTest].
 */
class OtpClientFinalizePersistenceTest {

    @Test
    fun checkOTP_finalizeWithoutRefreshHeader_doesNotPersistRefreshToken() = runBlocking {
        // Server omitting `X-Refresh-Token` is a backend regression we
        // shouldn't crash on; the access token still lands in the cache
        // so the user is functionally logged in until the next refresh.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(refreshToken = null),
        )

        val user = fixture.client.checkOTP("123456")
        assertEquals(OtpFixtures.JWT, user.accessToken)
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.get(fixture.domain))
        Unit
    }

    @Test
    fun checkOTP_persistsRefreshFromHeader_notFromSetCookie() = runBlocking {
        // The backend mints `__Host-refresh_<appId>` as a cookie for
        // browser flows. Mobile must use the X-Refresh-Token header —
        // the cookie jar is in-memory only; RefreshTokenStorage is
        // SharedPreferences-backed (Android's Keychain analogue) and
        // survives a cold start.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to StubHttpSession.Canned.json(
                """{"access_token":"${OtpFixtures.JWT}","expires_at":1700003600}""",
                headers = mapOf(
                    HttpHeader.REFRESH_TOKEN to "header-token",
                    HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
                    "Set-Cookie" to
                        "__Host-refresh_app-1=cookie-token; Path=/; HttpOnly; Secure",
                ),
            ),
        )

        fixture.client.checkOTP("123456")

        val record = fixture.refreshTokenStore.get(fixture.domain)
        assertNotNull(record)
        // Header is the source of truth; cookie value must be ignored.
        assertEquals("header-token", record!!.refreshToken)
        assertEquals("2099-01-01T00:00:00Z", record.refreshTokenExpiresAt)
        Unit
    }

    @Test
    fun checkOTP_finalizeAccessExpiry_isClockSkewAdjusted() = runBlocking {
        // Server `Date` 60s behind the fixture clock. `timeDiffSec`
        // picks up local - server = +60s and `storeAccessToken` adds
        // it to the server-supplied `expires_at` so the cache compares
        // correctly against the local clock.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to StubHttpSession.Canned.json(
                """{"access_token":"${OtpFixtures.JWT}","expires_at":1700003600}""",
                headers = mapOf(
                    HttpHeader.REFRESH_TOKEN to "refresh-v1",
                    "Date" to "Tue, 14 Nov 2023 22:12:20 GMT",
                ),
            ),
        )

        fixture.client.checkOTP("123456")

        // Server expiry: 1_700_003_600. Skew: +60. Cached: 1_700_003_660.
        val expiresAt = fixture.client.getAccessTokenExpiresAt()
        assertNotNull(expiresAt)
        assertEquals(1_700_003_660L, expiresAt!!.epochSecond)
        Unit
    }

    @Test
    fun checkOTP_refreshStoreWriteFails_doesNotPersistAccessToken() {
        // Refresh-before-access ordering invariant: a write failure on
        // the refresh-token store must abort *before* the access token
        // lands in the cache. Otherwise the next 401 has no refresh to
        // recover with.
        val failingStorage = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage()).apply {
            writeFailure = RuntimeException("simulated disk failure")
        }
        val fixture = Fixture.make(refreshTokenStorage = failingStorage)
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(
                refreshToken = "refresh-v1",
            ),
        )

        assertThrows(RuntimeException::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }
}
