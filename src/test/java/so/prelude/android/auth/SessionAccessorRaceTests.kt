package so.prelude.android.auth

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.AccessTokenEntry
import so.prelude.android.auth.store.RefreshTokenRecord

/**
 * Race-coherence tests for [PreludeAuthClient]'s public session
 * accessors. `invalidateCache()` immediately followed by an accessor
 * must reflect a concurrent refresh's outcome, not the invalidated
 * gap. See [PreludeAuthClient.readCacheCoherent].
 */
class SessionAccessorRaceTests {
    // Distinct `sub` / `sid` so the post-refresh read is distinguishable
    // from the pre-refresh one.
    private val jwtV1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzaWQtMSJ9.sig"
    private val jwtV2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTIiLCJzaWQiOiJzaWQtMiJ9.sig"

    private fun refreshOk(accessToken: String) =
        StubHttpSession.Canned.json(
            """{"access_token":"$accessToken","expires_at":${1_700_000_000L + 3_600}}""",
            headers =
                mapOf(
                    HttpHeader.REFRESH_TOKEN to "refresh-v2",
                    HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
                ),
        )

    private fun seedSession(fixture: Fixture) {
        fixture.keyStore.getOrCreate(fixture.domain)
        fixture.refreshTokenStore.set(
            domain = fixture.domain,
            record =
                RefreshTokenRecord(
                    refreshToken = "refresh-v1",
                    refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                ),
        )
        fixture.accessTokenCache.set(
            domain = fixture.domain,
            entry =
                AccessTokenEntry(
                    accessToken = jwtV1,
                    expiresAt = fixture.clock.epochSecond + 3_600,
                ),
        )
    }

    @Test
    fun accessorsAfterInvalidate_waitForInflightRefresh() =
        runBlocking {
            // Invalidate, hold /refresh open at the gate, read each
            // accessor concurrently. Accessors must observe jwtV2.
            val fixture = Fixture.make()
            seedSession(fixture)
            fixture.http.install("/v1/session/refresh", refreshOk(jwtV2))
            fixture.http.installGate("/v1/session/refresh")

            coroutineScope {
                fixture.client.invalidateCache()
                val refresher = async { fixture.client.refresh() }
                waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }
                // Let `refresh()` publish its in-flight slot.
                delay(50)

                val token = async { fixture.client.getAccessToken() }
                val profile = async { fixture.client.getProfile() }
                val expiresAt = async { fixture.client.getAccessTokenExpiresAt() }
                val sessionId = async { fixture.client.getSessionId() }

                // Let the accessors reach `joinIfRunning` before releasing.
                repeat(5) { yield() }

                fixture.http.releaseGate("/v1/session/refresh")
                refresher.await()

                assertEquals(jwtV2, token.await())
                assertEquals("user-2", profile.await()?.userId)
                assertEquals("sid-2", sessionId.await())
                assertEquals(1_700_000_000L + 3_600, expiresAt.await()?.epochSecond)
            }

            assertEquals(
                "accessors must not start their own refresh",
                1,
                fixture.http.requestCount("/v1/session/refresh"),
            )
        }

    @Test
    fun accessorsWithValidCache_doNotTriggerNetwork() =
        runBlocking {
            // No `/refresh` canned response — a stray request fails the
            // stub. Asserts `joinIfRunning` stays a no-op on the happy path.
            val fixture = Fixture.make()
            seedSession(fixture)

            assertEquals(jwtV1, fixture.client.getAccessToken())
            assertEquals("user-1", fixture.client.getProfile()?.userId)
            assertEquals("sid-1", fixture.client.getSessionId())
            assertNotNull(fixture.client.getAccessTokenExpiresAt())
            assertEquals(0, fixture.http.requestCount("/v1/session/refresh"))
        }

    @Test
    fun accessorCancelledMidJoin_propagatesCancellationException() =
        runBlocking {
            // `Inflight.joinIfRunning` re-throws CancellationException;
            // accessors must surface it verbatim.
            val fixture = Fixture.make()
            seedSession(fixture)
            fixture.http.install("/v1/session/refresh", refreshOk(jwtV2))
            fixture.http.installGate("/v1/session/refresh")

            try {
                supervisorScope {
                    fixture.client.invalidateCache()
                    val refresher = async { fixture.client.refresh() }
                    waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }
                    delay(50)

                    val accessor = async { fixture.client.getAccessToken() }
                    repeat(5) { yield() }
                    accessor.cancel()
                    accessor.join()

                    assertTrue(
                        "accessor must surface CancellationException",
                        accessor.getCompletionExceptionOrNull() is CancellationException,
                    )

                    fixture.http.releaseGate("/v1/session/refresh")
                    refresher.await()
                }
            } finally {
                fixture.http.releaseGate("/v1/session/refresh")
            }
            // Pin the test's return type to `Unit` for JUnit 4.
            Unit
        }

    @Test
    fun accessorsWithEmptyCache_returnNullWhileNoRefreshIsRunning() =
        runBlocking {
            // `joinIfRunning` is a no-op on an empty slot — accessors
            // return null instead of waiting.
            val fixture = Fixture.make()

            assertNull(fixture.client.getAccessToken())
            assertNull(fixture.client.getProfile())
            assertNull(fixture.client.getSessionId())
            assertNull(fixture.client.getAccessTokenExpiresAt())
        }

    private suspend fun waitUntil(
        timeoutMs: Long = 2_000,
        predicate: () -> Boolean,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            delay(5)
        }
        throw AssertionError("timed out waiting for condition (after ${timeoutMs}ms)")
    }
}
