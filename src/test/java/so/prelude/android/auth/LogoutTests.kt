package so.prelude.android.auth

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.dpop.DPoPKey
import so.prelude.android.auth.dpop.DPoPKeyStoreError
import so.prelude.android.auth.dpop.FakeDPoPKey
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.AccessTokenEntry
import so.prelude.android.auth.store.FailingAccessTokenStorage
import so.prelude.android.auth.store.FailingRefreshTokenStorage
import so.prelude.android.auth.store.InMemoryAccessTokenStorage
import so.prelude.android.auth.store.InMemoryRefreshTokenStorage
import so.prelude.android.auth.store.RefreshTokenRecord
import java.util.Base64

/**
 * Regression tests for the concurrency and robustness invariants of
 * [PreludeAuthClient.logout].
 *
 * Uses [runBlocking] (real dispatchers) for the same reason as the
 * other suites in this module — the inflight-coordinator and
 * interceptor chain hop through their own `Dispatchers.IO`-backed
 * scopes, and mixing virtual time with a real dispatcher makes
 * assertions about coroutine interleaving fragile.
 */
class LogoutTests {
    // Well-formed unsigned JWT — `JwtDecoder` only parses the payload,
    // so this is enough to round-trip a `userId = user-1` profile and
    // compute an expiry the cache will accept.
    // payload: {"sub":"user-1"} → eyJzdWIiOiJ1c2VyLTEifQ
    private val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    /** Pre-populate the fixture's stores so logout has something to wipe. */
    private fun Fixture.prePopulate(
        refreshToken: String = "refresh-v1",
        nonce: String? = "nonce-abc",
        accessTokenExpired: Boolean = false,
    ) {
        // Force key materialisation so [FakeDPoPKeyStore.get] returns
        // non-null — logout's snapshot only signs `/revoke` if it has
        // a key on file.
        keyStore.getOrCreate(domain)
        if (nonce != null) keyStore.setNonce(domain, nonce)

        refreshTokenStore.set(
            domain = domain,
            record =
                RefreshTokenRecord(
                    refreshToken = refreshToken,
                    refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
                ),
        )

        val expiresAt =
            if (accessTokenExpired) {
                clock.epochSecond - 60
            } else {
                clock.epochSecond + 3_600
            }
        accessTokenCache.set(
            domain = domain,
            entry = AccessTokenEntry(accessToken = jwt, expiresAt = expiresAt),
        )
    }

    /** Assert every domain-scoped store + the in-memory step-up handle is cleared. */
    private fun Fixture.assertWiped() {
        assertNull("DPoP key not wiped", keyStore.get(domain))
        assertNull("DPoP nonce not wiped", keyStore.getNonce(domain))
        assertNull("DPoP clock skew not wiped", keyStore.getClockSkewMs(domain))
        assertNull("Refresh token not wiped", refreshTokenStore.get(domain))
        assertNull(
            "Access token cache not wiped",
            accessTokenCache.getWithoutExpirationCheck(domain),
        )
        assertNull("activeStepUp not cleared", client.activeStepUp)
    }

    private fun refreshOk(
        refreshToken: String = "refresh-v2",
        expiresInSec: Long = 3_600,
    ) = StubHttpSession.Canned.json(
        """{"access_token":"$jwt","expires_at":${1_700_000_000L + expiresInSec}}""",
        headers =
            mapOf(
                HttpHeader.REFRESH_TOKEN to refreshToken,
                HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
            ),
    )

    private fun apiError(
        code: String,
        message: String = "",
        status: Int = 400,
    ) = StubHttpSession.Canned.json(
        """{"code":"$code","message":"$message"}""",
        statusCode = status,
    )

    // MARK: - Happy path

    @Test
    fun logout_revokesSession_andWipesAllStores() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.logout()

            assertEquals(1, fixture.http.requestCount("/v1/session/revoke"))
            fixture.assertWiped()
        }

    /**
     * Persisted clock skew must be wiped alongside the other
     * domain-scoped stores. Without this, a stale correction from
     * a previous session would leak into the next login's first
     * proof.
     */
    @Test
    fun logout_wipesPersistedClockSkew() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.keyStore.setClockSkewMs(fixture.domain, 30_000L)
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.logout()

            fixture.assertWiped()
        }

    @Test
    fun logout_wipesAllStoresBeforeRevokeReturns() =
        runBlocking {
            // Every store must already be empty while `/revoke` is in flight,
            // so a hanging or failing call can't leave a live credential behind.
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.client.setActiveStepUp(
                PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write"),
            )
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))
            fixture.http.installGate("/v1/session/revoke")

            coroutineScope {
                val caller = async { fixture.client.logout() }
                // Wait for /revoke to suspend at the gate.
                waitUntil { fixture.http.requestCount("/v1/session/revoke") >= 1 }
                // /revoke hasn't returned yet — but every store must
                // already be wiped.
                fixture.assertWiped()
                fixture.http.releaseGate("/v1/session/revoke")
                caller.await()
            }
        }

    @Test
    fun logout_revokeProof_carriesCurrentDPoPNonce() =
        runBlocking {
            // `/revoke` is signed inline from a pre-wipe snapshot, so the proof
            // must carry the last cached nonce: unlike every other hop, a nonce
            // challenge can't be retried once the keystore is wiped.
            val fixture = Fixture.make()
            fixture.prePopulate(nonce = "logout-nonce-abc")
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.logout()

            val proof =
                fixture.http
                    .requestsFor("/v1/session/revoke")
                    .single()
                    .header(HttpHeader.DPOP)
            assertNotNull(proof)
            val payload = String(Base64.getUrlDecoder().decode(proof!!.split('.')[1]))
            assertTrue(
                "revoke proof must carry the cached DPoP nonce; was: $payload",
                "\"nonce\":\"logout-nonce-abc\"" in payload,
            )
        }

    /**
     * `/revoke` is signed inline (bypassing the DPoP interceptor),
     * so it must read the persisted clock skew from the snapshot
     * just like the interceptor does. Without this the proof's
     * `iat` stays uncorrected and a clock-drifted device gets
     * rejected — the exact failure mode this PR fixes elsewhere.
     */
    @Test
    fun logout_revokeProof_carriesClockSkewCorrection() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulate(nonce = "logout-nonce-abc")
            val skewMs = 45_000L
            fixture.keyStore.setClockSkewMs(fixture.domain, skewMs)
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.logout()

            val proof =
                fixture.http
                    .requestsFor("/v1/session/revoke")
                    .single()
                    .header(HttpHeader.DPOP)
            assertNotNull(proof)
            val payload = String(Base64.getUrlDecoder().decode(proof!!.split('.')[1]))
            val iat = Regex("\"iat\":(\\d+)").find(payload)!!.groupValues[1].toLong()
            val expectedSec = (System.currentTimeMillis() + skewMs) / 1000
            assertTrue(
                "revoke iat $iat must carry the snapshotted skew (expected≈$expectedSec); payload=$payload",
                kotlin.math.abs(iat - expectedSec) <= 3,
            )
        }

    @Test
    fun logout_signsRevokeWithDpop_andCarriesRefreshToken() =
        runBlocking {
            // Signed from the pre-wipe snapshot: DPoPInterceptor would mint a
            // fresh keypair against the emptied store and mismatch the `jkt`.
            val fixture = Fixture.make()
            fixture.prePopulate(refreshToken = "refresh-v1")
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.logout()

            val req = fixture.http.requestsFor("/v1/session/revoke").single()
            assertNotNull("revoke must carry a DPoP proof", req.header(HttpHeader.DPOP))
            assertEquals("refresh-v1", req.header(HttpHeader.REFRESH_TOKEN))
            // DPoP-signed but not bearer-authenticated: `/revoke` revokes
            // the session keyed by the proof's jkt + the refresh token,
            // not by the access token (which is short-lived and may be
            // expired by the time logout runs).
            assertNull(
                "revoke must not carry a bearer token",
                req.header(HttpHeader.AUTHORIZATION),
            )
        }

    @Test
    fun logout_withoutAnyCredentials_skipsRevoke_andStillWipes() =
        runBlocking {
            // Nothing to revoke against: an unsigned proof with no
            // refresh-token header would be rejected as malformed.
            val fixture = Fixture.make()
            // Don't call prePopulate — stores are empty.
            fixture.client.logout()

            assertEquals(0, fixture.http.requestCount("/v1/session/revoke"))
            fixture.assertWiped()
        }

    @Test
    fun logout_withDpopKeyButNoRefreshToken_skipsRevoke() =
        runBlocking {
            // A DPoP key is necessary but not sufficient — without a
            // refresh token there's nothing to identify the session
            // server-side, so we skip the round-trip and just wipe.
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.keyStore.setNonce(fixture.domain, "nonce-abc")
            // No refresh token. Access token cache empty.

            fixture.client.logout()

            assertEquals(0, fixture.http.requestCount("/v1/session/revoke"))
            fixture.assertWiped()
        }

    // MARK: - Concurrency

    @Test
    fun logout_concurrentCallers_coalesceOntoOneRevoke() =
        runBlocking {
            // Without dedup the second caller would hit a 401 for "already
            // revoked" and surface a spurious Unauthorized. Dedup ensures
            // one round-trip per logical logout regardless of how many
            // callers race.
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))
            // Gate `/revoke` so all 16 callers are guaranteed to be in
            // flight before any of them completes — without the gate, the
            // first caller could finish before the rest enter and we'd
            // miss the dedup path.
            fixture.http.installGate("/v1/session/revoke")

            coroutineScope {
                val tasks = (0 until 16).map { async { fixture.client.logout() } }
                // Once one caller has filed `/revoke`, all 16 are guaranteed
                // to either be on the same in-flight task or queued behind
                // its mutex.
                waitUntil { fixture.http.requestCount("/v1/session/revoke") >= 1 }
                fixture.http.releaseGate("/v1/session/revoke")
                tasks.awaitAll()
            }

            assertEquals(
                "all 16 callers must coalesce onto one /revoke",
                1,
                fixture.http.requestCount("/v1/session/revoke"),
            )
            fixture.assertWiped()
        }

    @Test
    fun logout_drainsInflightRefresh_andSignsRevokeWithRotatedToken() =
        runBlocking {
            // `/revoke` must carry the refresh token produced by whichever
            // refresh was in flight at logout time, not the pre-rotation
            // one. The server treats spent (already-rotated) tokens as
            // invalid.
            val fixture = Fixture.make()
            fixture.prePopulate(refreshToken = "refresh-v1", accessTokenExpired = true)
            fixture.http.install("/v1/session/refresh", refreshOk(refreshToken = "refresh-v2"))
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))
            fixture.http.installGate("/v1/session/refresh")

            coroutineScope {
                val refresh = async { fixture.client.refresh() }
                // Wait for refresh to be in flight, blocked at the gate.
                waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }

                val logout = async { fixture.client.logout() }
                // Give logout a tick to enter `inflightRefresh.joinIfRunning`
                // and suspend on the in-flight refresh task.
                delay(50)
                fixture.http.releaseGate("/v1/session/refresh")

                refresh.await()
                logout.await()
            }

            val revoked = fixture.http.requestsFor("/v1/session/revoke").single()
            assertEquals(
                "logout must sign /revoke with the rotated refresh token, not the pre-rotation one",
                "refresh-v2",
                revoked.header(HttpHeader.REFRESH_TOKEN),
            )
        }

    @Test
    fun logout_concurrentRefreshDuringRevoke_cannotResurrectSession() =
        runBlocking {
            // A `refresh()` triggered during `/revoke`'s suspension can't
            // resurrect the session — the stores were wiped before
            // `/revoke` started, so there's no refresh token for the new
            // refresh to present and the server rejects it.
            val fixture = Fixture.make()
            fixture.prePopulate(accessTokenExpired = true)
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))
            fixture.http.installGate("/v1/session/revoke")
            fixture.http.install(
                "/v1/session/refresh",
                apiError("unauthorized", "no refresh token", status = 401),
            )

            // `supervisorScope` so the expected refresh failure doesn't abort
            // the scope before we can assert on the caught exception.
            supervisorScope {
                val logout = async { fixture.client.logout() }
                // Wait for logout to have wiped stores and started /revoke.
                waitUntil { fixture.http.requestCount("/v1/session/revoke") >= 1 }

                // The wipe already invalidated the cache, so the racing refresh
                // goes to the network with no refresh token and the server 401s.
                val refresh = async { fixture.client.refresh() }
                val caught = runCatching { refresh.await() }.exceptionOrNull()
                assertTrue(
                    "expected Unauthorized, got $caught",
                    caught is PreludeAuthError.Unauthorized,
                )

                fixture.http.releaseGate("/v1/session/revoke")
                logout.await()
            }

            // Stores stayed wiped despite the racing refresh.
            assertNull(fixture.refreshTokenStore.get(fixture.domain))
            assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        }

    // MARK: - Failure modes

    @Test
    fun logout_partialWipeFailure_stillFiresRevoke_thenSurfacesWipeError() =
        runBlocking {
            // A failing delete must not short-circuit the remaining wipes or
            // prevent `/revoke`; the captured error is re-thrown afterwards.
            val failing =
                FailingRefreshTokenStorage(InMemoryRefreshTokenStorage()).apply {
                    deleteFailure = RuntimeException("simulated delete failure")
                }
            val fixture = Fixture.make(refreshTokenStorage = failing)
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            val thrown =
                assertThrows(RuntimeException::class.java) {
                    runBlocking { fixture.client.logout() }
                }
            assertEquals("simulated delete failure", thrown.message)

            // /revoke still fires — the wipe error is about which error
            // wins, not about skipping the server round-trip.
            assertEquals(1, fixture.http.requestCount("/v1/session/revoke"))
            // The other three deletes ran successfully despite the
            // failing one.
            assertNull(fixture.keyStore.get(fixture.domain))
            assertNull(fixture.keyStore.getNonce(fixture.domain))
            assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        }

    @Test
    fun logout_partialWipe_andRevokeFailure_surfacesWipeError() =
        runBlocking {
            // The wipe error wins: a credential left on the device is worse
            // than a server session the server's TTL eventually clears.
            val failing =
                FailingRefreshTokenStorage(InMemoryRefreshTokenStorage()).apply {
                    deleteFailure = RuntimeException("simulated delete failure")
                }
            val fixture = Fixture.make(refreshTokenStorage = failing)
            fixture.prePopulate()
            fixture.http.install(
                "/v1/session/revoke",
                apiError("internal_server_error", "boom", status = 500),
            )

            val thrown =
                assertThrows(RuntimeException::class.java) {
                    runBlocking { fixture.client.logout() }
                }
            assertEquals(
                "wipe error must win over /revoke's server failure",
                "simulated delete failure",
                thrown.message,
            )

            // /revoke is still attempted before we re-throw — surfacing
            // the wipe error is about precedence, not about skipping work.
            assertEquals(1, fixture.http.requestCount("/v1/session/revoke"))
        }

    @Test
    fun logout_partialAccessTokenCacheFailure_surfacesWipeError() =
        runBlocking {
            // Symmetric to the refresh-token failure test, but for the
            // access-token cache.
            val failing =
                FailingAccessTokenStorage(InMemoryAccessTokenStorage()).apply {
                    deleteFailure = RuntimeException("simulated cache delete failure")
                }
            val fixture = Fixture.make(accessTokenStorage = failing)
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            val thrown =
                assertThrows(RuntimeException::class.java) {
                    runBlocking { fixture.client.logout() }
                }
            assertEquals("simulated cache delete failure", thrown.message)

            // The other three deletes ran successfully despite the
            // failing one — partial wipe, not skipped wipe.
            assertNull(fixture.keyStore.get(fixture.domain))
            assertNull(fixture.keyStore.getNonce(fixture.domain))
            assertNull(fixture.refreshTokenStore.get(fixture.domain))
            // /revoke still fires.
            assertEquals(1, fixture.http.requestCount("/v1/session/revoke"))
        }

    @Test
    fun logout_signingFailureDuringRevoke_silentlyDegrades_localWipeStillCompletes() =
        runBlocking {
            // A signing failure is unrecoverable: `/revoke` cannot be signed
            // without the original key. The local wipe landed and the server
            // session expires via TTL, so the error is silenced.
            val fixture = Fixture.make()
            fixture.prePopulate()
            // Replace the materialised key with one that throws on
            // sign — mimics the AVD-rollback / lock-screen-change
            // shape that surfaces in production logcat as
            // "ECDSA signing failed: Key permanently invalidated".
            fixture.keyStore.setKey(
                fixture.domain,
                object : DPoPKey {
                    override fun exportPublicJwk(): Map<String, String> = FakeDPoPKey().exportPublicJwk()

                    override fun signES256(data: ByteArray): ByteArray =
                        throw DPoPKeyStoreError.SigningFailed(
                            IllegalStateException("Key permanently invalidated"),
                        )
                },
            )
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            // Must not throw — the signing error is silenced.
            fixture.client.logout()

            // /revoke never fires (no proof to attach).
            assertEquals(0, fixture.http.requestCount("/v1/session/revoke"))
            // Local wipe still landed: stores are empty, activeStepUp clear.
            fixture.assertWiped()
        }

    // MARK: - Slot reuse

    @Test
    fun logout_secondCallAfterFirstCompletes_runsEndToEnd() =
        runBlocking {
            // After a logout settles the [Inflight] slot must clear, so a
            // second `logout()` files its own `/revoke` instead of no-oping.
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.logout()
            // Re-populate so the second logout has something to revoke.
            fixture.prePopulate(refreshToken = "refresh-v2")
            fixture.client.logout()

            assertEquals(
                "second logout must produce its own /revoke",
                2,
                fixture.http.requestCount("/v1/session/revoke"),
            )
            // Last /revoke must carry the second session's token, not
            // the first one — proves the second call snapshotted fresh
            // state rather than reusing the first call's captured value.
            assertEquals(
                "refresh-v2",
                fixture.http
                    .requestsFor("/v1/session/revoke")
                    .last()
                    .header(HttpHeader.REFRESH_TOKEN),
            )
            fixture.assertWiped()
        }

    // MARK: - Cancellation

    @Test
    fun logout_callerCancelledDuringRevoke_propagatesCancellation() =
        runBlocking {
            // Pins the cancellation invariant: a caller cancelled while
            // `/revoke` is in flight must observe [CancellationException]
            // rather than returning normally.
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))
            fixture.http.installGate("/v1/session/revoke")

            // `supervisorScope` so the cancelled child doesn't tear down
            // the test scope before we can read its completion cause.
            try {
                supervisorScope {
                    val caller = async { fixture.client.logout() }
                    waitUntil { fixture.http.requestCount("/v1/session/revoke") >= 1 }
                    // Give logout's `runCatching` block a tick to suspend
                    // inside `httpClient.sendExpectingNoBody` rather than
                    // racing the cancel against pre-suspend bookkeeping.
                    yield()
                    caller.cancel()
                    caller.join()

                    // Assert on the completion cause rather than `isCancelled`:
                    // the boolean can't say which exception the caller observed.
                    val cause = caller.getCompletionExceptionOrNull()
                    assertTrue(
                        "logout must surface CancellationException to the caller, was $cause",
                        cause is CancellationException,
                    )
                }
            } finally {
                // Release so the gated request unwinds cleanly even after
                // its parent coroutine was cancelled.
                fixture.http.releaseGate("/v1/session/revoke")
            }
        }

    // MARK: - Login / logout race (epoch guard)

    @Test
    fun loginWithPassword_racedByLogout_doesNotResurrectSession() =
        runBlocking {
            // Logout bumps the session epoch while `/login/finalize` is in
            // flight; finalize's epoch guard bails instead of persisting.
            val fixture = Fixture.make()
            fixture.prePopulate() // gives logout a session to revoke
            fixture.http.installAll(
                "/v1/session/login/email/password" to
                    StubHttpSession.Canned.json(
                        """{"challenge_token":"challenge-abc"}""",
                    ),
                "/v1/session/login/finalize" to refreshOk(refreshToken = "post-finalize"),
                "/v1/session/revoke" to StubHttpSession.Canned(statusCode = 204),
            )
            fixture.http.installGate("/v1/session/login/finalize")

            // `supervisorScope` so the expected `Unauthorized` from the
            // racing login doesn't cascade through the scope before we
            // can assert on it — same reasoning as in
            // `logout_concurrentRefreshDuringRevoke_cannotResurrectSession`.
            supervisorScope {
                val login =
                    async {
                        fixture.client.loginWithPassword(
                            LoginWithPasswordOptions(
                                identifier = "alice@example.com",
                                password = "hunter2",
                            ),
                        )
                    }
                // Wait for /login/finalize to be in flight, blocked at the
                // gate. By this point sessionEpoch was captured at the old
                // value.
                waitUntil { fixture.http.requestCount("/v1/session/login/finalize") >= 1 }

                // Logout bumps the epoch + wipes stores while finalize is
                // suspended.
                fixture.client.logout()

                // Release finalize. Its post-network epoch check sees the
                // bumped counter and bails before persisting.
                fixture.http.releaseGate("/v1/session/login/finalize")

                val caught = runCatching { login.await() }.exceptionOrNull()
                assertTrue(
                    "expected Unauthorized, got $caught",
                    caught is PreludeAuthError.Unauthorized,
                )
            }

            // Stores stay wiped — finalize did not persist its rotated
            // token despite the server returning a successful 200.
            assertNull(fixture.refreshTokenStore.get(fixture.domain))
            assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        }

    // MARK: - Helpers

    /**
     * Poll [predicate] every 5ms until it returns `true` or [timeoutMs]
     * elapses. Used to rendezvous on observable markers (recorded-
     * request counts) instead of fixed sleeps.
     */
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

    @Test
    fun logout_clearsActiveStepUp() =
        runBlocking {
            // A stale step-up handle that survives logout would let a
            // post-logout observer believe a flow is still in progress.
            val fixture = Fixture.make()
            fixture.prePopulate()
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))
            fixture.client.setActiveStepUp(
                PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write"),
            )

            fixture.client.logout()

            assertNull(
                "logout must clear activeStepUp",
                fixture.client.activeStepUp,
            )
        }
}
