package so.prelude.android.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.RefreshTokenRecord
import java.util.Base64

/**
 * Tests for [PreludeAuthClient.refresh] (`POST /v1/session/refresh`).
 * Concurrency / dedup invariants live in [InflightTest]; the
 * 401-driven refresh path is covered by [http.AutoRefreshInterceptorTest].
 */
class RefreshClientTest {
    // Well-formed unsigned JWT, payload `{"sub":"user-1"}`.
    private val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private fun refreshOk(refreshToken: String = "refresh-v2") =
        StubHttpSession.Canned.json(
            """{"access_token":"$jwt","expires_at":${1_700_000_000L + 3_600}}""",
            headers =
                mapOf(
                    HttpHeader.REFRESH_TOKEN to refreshToken,
                    HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
                ),
        )

    private fun decodePayload(proof: String): String = String(Base64.getUrlDecoder().decode(proof.split('.')[1]))

    @Test
    fun refresh_reusesCachedDPoPNonce_andDoesNotTriggerChallenge() =
        runBlocking {
            // Seed: a refresh token + a DPoP nonce harvested from a prior
            // hop (e.g. /login/finalize). With both in place, `/refresh`
            // must include the cached nonce in its proof and skip the
            // server's `use_dpop_nonce` 401 round-trip.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.keyStore.setNonce(fixture.domain, "nonce-from-finalize")
            fixture.refreshTokenStore.set(
                domain = fixture.domain,
                record =
                    RefreshTokenRecord(
                        refreshToken = "refresh-v1",
                        refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )
            fixture.http.install("/v1/session/refresh", refreshOk())

            fixture.client.refresh()

            // Exactly one hop: no challenge round-trip.
            assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))

            val req = fixture.http.requestsFor("/v1/session/refresh").single()
            val proof = req.header(HttpHeader.DPOP)
            assertNotNull("refresh must carry a DPoP proof", proof)
            assertTrue(
                "proof must reuse the cached nonce, was: ${decodePayload(proof!!)}",
                "\"nonce\":\"nonce-from-finalize\"" in decodePayload(proof),
            )
        }

    @Test
    fun refresh_sendsRefreshTokenAsHeader_notCookie() =
        runBlocking {
            // Backend mints `__Host-refresh_<appId>` as a cookie for browser
            // flows (handled by OkHttp's CookieJar). Mobile uses the
            // X-Refresh-Token header so RefreshTokenStorage stays the
            // single source of truth — the in-memory cookie jar doesn't
            // survive cold start.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.refreshTokenStore.set(
                domain = fixture.domain,
                record =
                    RefreshTokenRecord(
                        refreshToken = "refresh-v1",
                        refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )
            fixture.http.install("/v1/session/refresh", refreshOk())

            fixture.client.refresh()

            val req = fixture.http.requestsFor("/v1/session/refresh").single()
            assertEquals("refresh-v1", req.header(HttpHeader.REFRESH_TOKEN))
            // The SDK never constructs a Cookie header itself; pin the
            // negative side anyway so a future regression that copies the
            // refresh token into one surfaces here.
            val cookie = req.header("Cookie").orEmpty()
            assertTrue("Cookie must not carry refresh-v1: $cookie", "refresh-v1" !in cookie)
        }

    @Test
    fun refresh_rotatesToken_persistsAndReusesOnNextCall() =
        runBlocking {
            // Single-use refresh tokens: each successful /refresh mints
            // v_n and revokes v_{n-1} server-side. The SDK must persist
            // the rotated value AND ship it on the next call — otherwise
            // the server 401s on the now-revoked v_{n-1}.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.refreshTokenStore.set(
                domain = fixture.domain,
                record =
                    RefreshTokenRecord(
                        refreshToken = "refresh-v1",
                        refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )
            fixture.http.install("/v1/session/refresh", refreshOk(refreshToken = "refresh-v2"))

            fixture.client.refresh()
            assertEquals(
                "refresh-v2",
                fixture.refreshTokenStore.get(fixture.domain)!!.refreshToken,
            )

            // Bypass the access-token fast path so the second refresh()
            // hits the wire instead of short-circuiting on the cached JWT.
            fixture.accessTokenCache.invalidate(fixture.domain)
            fixture.client.refresh()

            val recorded = fixture.http.requestsFor("/v1/session/refresh")
            assertEquals(2, recorded.size)
            assertEquals("refresh-v1", recorded[0].header(HttpHeader.REFRESH_TOKEN))
            assertEquals("refresh-v2", recorded[1].header(HttpHeader.REFRESH_TOKEN))
        }

    @Test
    fun refresh_revokedTokenReplay_surfacesUnauthorized_andLeavesStoreIntact() =
        runBlocking {
            // Server-side rotation contract: once v_n+1 is minted, v_n is
            // revoked. If the SDK ever ships a stale token (e.g. an
            // out-of-band rotation, or someone manually wedging a prior
            // value back in), the server returns 401/`unauthorized`.
            // Pin the failure shape end-to-end:
            //   * caller sees `PreludeAuthError.Unauthorized` — distinct
            //     from a transport error or a generic 4xx,
            //   * the store is NOT silently wiped — wipe-on-401 belongs
            //     to logout(), not to refresh(); a transient backend 401
            //     (MITM, deploy bug) shouldn't lose the user's credential.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.refreshTokenStore.set(
                domain = fixture.domain,
                record =
                    RefreshTokenRecord(
                        refreshToken = "refresh-v1-stale",
                        refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )
            fixture.http.install(
                "/v1/session/refresh",
                StubHttpSession.Canned.json(
                    """{"code":"unauthorized","message":"refresh token revoked"}""",
                    statusCode = 401,
                ),
            )

            assertThrows(PreludeAuthError.Unauthorized::class.java) {
                runBlocking { fixture.client.refresh() }
            }

            // Store unchanged — the caller can decide whether to logout()
            // or retry. SDK does not auto-wipe on a refresh 401.
            assertEquals(
                "refresh-v1-stale",
                fixture.refreshTokenStore.get(fixture.domain)?.refreshToken,
            )
            // Exactly one round-trip — no implicit retry that would burn
            // the (already revoked) token a second time.
            assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
        }

    @Test
    fun refresh_accessExpiry_isClockSkewAdjusted() =
        runBlocking {
            // Device clock 5 minutes ahead of the server. `timeDiffSec`
            // picks up local - server = +300s; doRefresh's
            // storeAccessToken adds the offset to the server-supplied
            // `expires_at` so the cache compares against the local
            // clock, not the server's. Mirrors the OTP / password
            // login path's skew tests for the refresh surface — a
            // regression in finalizeLogin's math could miss this one.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.refreshTokenStore.set(
                domain = fixture.domain,
                record =
                    RefreshTokenRecord(
                        refreshToken = "refresh-v1",
                        refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )
            fixture.http.install(
                "/v1/session/refresh",
                StubHttpSession.Canned.json(
                    """{"access_token":"$jwt","expires_at":1700003600}""",
                    headers =
                        mapOf(
                            HttpHeader.REFRESH_TOKEN to "refresh-v2",
                            HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
                            // Fixture clock is 1_700_000_000 (22:13:20 UTC); 300s before is 22:08:20.
                            "Date" to "Tue, 14 Nov 2023 22:08:20 GMT",
                        ),
                ),
            )

            fixture.client.refresh()

            // Server expiry: 1_700_003_600. Skew: +300. Cached: 1_700_003_900.
            val expiresAt = fixture.client.getAccessTokenExpiresAt()
            assertNotNull(expiresAt)
            assertEquals(1_700_003_900L, expiresAt!!.epochSecond)
        }

    @Test
    fun refresh_concurrentCallers_shareSingleRoundTrip() =
        runBlocking {
            // No thundering herd: several callers racing client.refresh()
            // must coalesce onto one network round-trip via inflightRefresh.
            // The single-use refresh token can't be spent N times.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.refreshTokenStore.set(
                domain = fixture.domain,
                record =
                    RefreshTokenRecord(
                        refreshToken = "refresh-v1",
                        refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )
            fixture.http.install("/v1/session/refresh", refreshOk())
            fixture.http.installGate("/v1/session/refresh")

            coroutineScope {
                val racers = (1..5).map { async { fixture.client.refresh() } }
                // Wait for the first racer to be in flight at the gate.
                waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }
                // Give the others a tick to enter `Inflight.runOrJoin`
                // and attach to the in-flight slot.
                delay(50)
                fixture.http.releaseGate("/v1/session/refresh")
                racers.awaitAll()
            }

            assertEquals(
                "5 callers, 1 round-trip",
                1,
                fixture.http.requestCount("/v1/session/refresh"),
            )
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
