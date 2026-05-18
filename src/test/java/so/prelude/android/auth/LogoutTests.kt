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

    @Test
    fun logout_wipesAllStoresBeforeRevokeReturns() =
        runBlocking {
            // Wipe-before-network: a successful `/revoke` is the easy
            // case. The dangerous case is a `/revoke` that hangs or fails
            // — the stores must already be empty by the time the network
            // call is in flight, so a stuck network can't leave a stale
            // credential live on the device.
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
            // /revoke is signed inline (not via DPoPInterceptor) because
            // the wipe runs first; the proof must still pull the
            // most-recently-cached nonce so the server can validate it
            // without forcing a fresh challenge round-trip on a hop that
            // can't retry — the keystore has been wiped by then.
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

    @Test
    fun logout_signsRevokeWithDpop_andCarriesRefreshToken() =
        runBlocking {
            // Verifies the inline-signed proof path: logout snapshots the
            // DPoP key + nonce + refresh token before wiping, then signs
            // `/revoke` manually rather than going through DPoPInterceptor
            // (which would mint a fresh keypair against the now-empty
            // store and produce a `jkt` mismatch on the server).
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
            // No DPoP key, no refresh token: there's nothing to revoke
            // against. We still run the local wipe (idempotent) but skip
            // the `/revoke` round-trip — calling it would attach an
            // unsigned proof and a missing refresh-token header, which
            // the server would reject as malformed.
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

            // `supervisorScope` so a failing `async` child doesn't cascade
            // and abort the scope before we've had a chance to assert on
            // the caught exception. We *expect* the racing refresh to
            // fail; under a plain `coroutineScope` the failure would
            // surface as the scope's terminal exception even after
            // `await()` consumed it.
            supervisorScope {
                val logout = async { fixture.client.logout() }
                // Wait for logout to have wiped stores and started /revoke.
                waitUntil { fixture.http.requestCount("/v1/session/revoke") >= 1 }

                // Now a racing refresh kicks off. The cache was already
                // invalidated by logout's wipe, so refresh enters its
                // network path and finds an empty refresh-token store —
                // server rejects with 401, which the SDK surfaces as
                // Unauthorized.
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
            // A failing store delete must not short-circuit the other
            // three deletes *or* prevent `/revoke` from firing. The
            // captured wipe error is re-thrown after the server attempt —
            // surfacing it lets the caller know to retry, which a silent
            // success would hide.
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
            // When the wipe AND `/revoke` both fail, surface the wipe
            // error: a stale credential left on a (potentially compromised)
            // device is more dangerous than a server session the server's
            // TTL eventually clears, and silencing the wipe error would
            // also hide the partial state from the caller.
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
            // Symmetric to the refresh-token failure test: a failing
            // access-token cache delete must surface as the thrown error,
            // and the other three deletes must still complete. Pins the
            // four-delete contract end-to-end against any single failing
            // store, not just the refresh-token one.
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
            // `KeyPermanentlyInvalidatedException` (and any other
            // signing failure surfaced via [DPoPKeyStoreError]) is
            // unrecoverable on this hardware: there is no path to
            // attempt `/revoke` without the original DPoP private key.
            // The local wipe still happened, so the device cannot use
            // this session, and the server session expires on its own
            // via TTL — surfacing the error to the caller would only
            // be noise. Pins the silent-degrade contract.
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
            // Regression for the [Inflight] slot-clearing contract on the
            // logout path: after a logout settles, the slot must clear so
            // a follow-up `logout()` produces a fresh `/revoke` round-trip
            // rather than re-awaiting the prior task. The slot-clearing
            // discipline is already covered by `InflightTest`, but this
            // pins the public surface — we never want a regression where
            // a second logout silently no-ops.
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
            // Pins the cancellation invariant for `logout()`: a caller
            // cancelled while `/revoke` is in flight observes
            // [CancellationException], not a normal return.
            //
            // `doLogout` keeps the invariant in two ways that we want to
            // notice if either ever drifts:
            //   1. The runCatching wrappers around the snapshot reads and
            //      the `/revoke` round-trip use `.rethrowingCancellation()`
            //      so cancellation isn't silently turned into a `null`
            //      result or a swallowed exception.
            //   2. The terminal `revokeError?.let { throw it }` re-raises
            //      whatever `/revoke` surfaced, including
            //      [CancellationException].
            //
            // A regression in either layer would make `logout()` return
            // normally under cancellation — exactly what this test fails
            // on.
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

                    // `getCompletionExceptionOrNull` reflects what the
                    // coroutine body actually surfaced — distinct from
                    // `isCancelled`, which only records that `cancel()`
                    // was called. Asserting on the body's exception is
                    // what proves the rethrow guards are doing their
                    // job: had `runCatching` swallowed the cancellation,
                    // `logout()` would have returned normally and the
                    // completion exception would be `null`.
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
            // A logout that lands while `/login/finalize` is in flight has
            // already wiped the stores we're about to write — the epoch
            // guard inside `finalizeLogin` catches the mismatch and
            // surfaces Unauthorized rather than persisting tokens that
            // refer to a session the caller just revoked.
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
