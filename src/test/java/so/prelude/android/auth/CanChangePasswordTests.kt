package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.AccessTokenEntry
import so.prelude.android.auth.store.RefreshTokenRecord

/**
 * Unit tests for [canChangePassword].
 *
 * The helper invalidates the cache and forces a `/refresh` round-
 * trip so the scope decision is made against a freshly-minted
 * access token, not a possibly-stale cached one. Tests stub the
 * `/refresh` response with each variant of the `scope` claim and
 * assert on the resulting boolean (or thrown error).
 */
class CanChangePasswordTests {
    // payload: {"sub":"user-1","sid":"sess-1"} — used to seed the
    // pre-populated cache; the helper must NOT read it (cache is
    // invalidated before the refresh).
    private val cachedAccessToken =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    // payload: {"sub":"user-1","sid":"sess-1","scope":"prld:pwd:write"}
    private val tokenWithScope =
        "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6InBybGQ6cHdkOndyaXRlIn0.sig"

    // payload: {"sub":"user-1","sid":"sess-1","scope":"prld:foo:read prld:pwd:write prld:bar:write"}
    private val tokenWithScopeAmongMany =
        "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6InBybGQ6Zm9vOnJlYWQgcHJsZDpwd2Q6d3JpdGUgcHJsZDpiYXI6d3JpdGUifQ.sig"

    // payload: {"sub":"user-1","sid":"sess-1","scope":"prld:foo:read"}
    private val tokenWithOtherScope =
        "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6InBybGQ6Zm9vOnJlYWQifQ.sig"

    // payload: {"sub":"user-1","sid":"sess-1"} — no `scope` claim.
    private val tokenWithoutScope =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    // payload: {"sub":"user-1","sid":"sess-1","scope":42} — present
    // but not a string.
    private val tokenWithMalformedScope =
        "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6NDJ9.sig"

    private val baseEpoch: Long = 1_700_000_000L

    private fun Fixture.prePopulate(refreshToken: String = "refresh-v1") {
        keyStore.getOrCreate(domain)
        refreshTokenStore.set(
            domain = domain,
            record =
                RefreshTokenRecord(
                    refreshToken = refreshToken,
                    refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                ),
        )
        accessTokenCache.set(
            domain = domain,
            entry =
                AccessTokenEntry(
                    accessToken = cachedAccessToken,
                    expiresAt = clock.epochSecond + 3_600,
                ),
        )
    }

    private fun refreshOk(accessToken: String) =
        StubHttpSession.Canned.json(
            """{"access_token":"$accessToken","expires_at":${baseEpoch + 3_600}}""",
            headers =
                mapOf(
                    HttpHeader.REFRESH_TOKEN to "refresh-v2",
                    HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
                ),
        )

    // MARK: - Scope present

    @Test
    fun canChangePassword_scopePresent_returnsTrue() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/refresh", refreshOk(tokenWithScope))

            assertTrue(fixture.client.canChangePassword())
        }

    @Test
    fun canChangePassword_scopeAmongMany_returnsTrue() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/refresh", refreshOk(tokenWithScopeAmongMany))

            assertTrue(fixture.client.canChangePassword())
        }

    // MARK: - Scope absent / malformed

    @Test
    fun canChangePassword_otherScope_returnsFalse() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/refresh", refreshOk(tokenWithOtherScope))

            assertFalse(fixture.client.canChangePassword())
        }

    @Test
    fun canChangePassword_missingClaim_returnsFalse() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/refresh", refreshOk(tokenWithoutScope))

            assertFalse(fixture.client.canChangePassword())
        }

    @Test
    fun canChangePassword_malformedClaim_returnsFalse() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/refresh", refreshOk(tokenWithMalformedScope))

            assertFalse(fixture.client.canChangePassword())
        }

    // MARK: - Refresh failure propagates

    @Test
    fun canChangePassword_refreshFails_throws() {
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/refresh",
            StubHttpSession.Canned.json(
                """{"code":"internal_server_error","message":"boom"}""",
                statusCode = 500,
            ),
        )

        // Any thrown PreludeAuthError is acceptable — the contract is
        // "refresh failure surfaces" rather than a specific subtype.
        assertThrows(PreludeAuthError::class.java) {
            runBlocking { fixture.client.canChangePassword() }
        }
    }

    // MARK: - Invalidate-then-refresh is load-bearing

    @Test
    fun canChangePassword_alwaysHitsNetwork_evenWithFreshCache() =
        runBlocking {
            // Cache is freshly seeded by `prePopulate`; the helper must
            // still invalidate it and hit `/refresh`, because a cached
            // token can carry a scope the server has since consumed.
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/refresh", refreshOk(tokenWithScope))

            fixture.client.canChangePassword()

            assertEquals(
                "canChangePassword must invalidate + refresh even when the cache is warm",
                1,
                fixture.http.requestCount("/v1/session/refresh"),
            )
        }
}
