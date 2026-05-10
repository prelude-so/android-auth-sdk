package so.prelude.android.session

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.store.AccessTokenEntry
import so.prelude.android.session.store.FailingAccessTokenStorage
import so.prelude.android.session.store.InMemoryAccessTokenStorage
import so.prelude.android.session.store.RefreshTokenRecord

/**
 * Unit tests for the change-password surface (`changePassword`).
 *
 * Each test spins up a [Fixture], installs canned HTTP responses
 * keyed by path, exercises the public client API, and asserts on
 * side-effects (recorded request shape, the access-token cache,
 * the refresh-token store).
 *
 * Uses [runBlocking] (real dispatchers) for the same reason as the
 * OTP / password / step-up suites — the interceptor chain hops
 * through `withContext(Dispatchers.IO)`, and mixing virtual time
 * with a real dispatcher makes assertions about suspending state
 * mutations fragile.
 */
class ChangePasswordTests {

    // Well-formed unsigned JWT carrying `sub = user-1`. The decoder
    // only parses the payload, so this is enough to round-trip a
    // profile and compute a finite expiry.
    // payload: {"sub":"user-1","sid":"sess-1"}
    private val scopedAccessToken =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    // Distinct token used by the post-success refresh — different
    // from [scopedAccessToken] so the cache assertion proves the
    // refresh actually overwrote the cached value.
    // payload: {"sub":"user-1","sid":"sess-1","scope":""}
    private val unscopedAccessToken =
        "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6IiJ9.sig"

    // Used in the drain race test as the result of the *vanilla*
    // refresh that loses the race — distinct payload so the final
    // cache state can prove the post-drain bookkeeping refresh
    // overwrote it. payload:
    // {"sub":"user-1","sid":"sess-1","scope":"prld:pwd:write"}
    private val raceLostScopedAccessToken =
        "eyJhbGciOiJIUzI1NiJ9." +
            "eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEiLCJzY29wZSI6InBybGQ6cHdkOndyaXRlIn0.sig"

    private val baseEpoch: Long = 1_700_000_000L

    /**
     * Pre-populate the fixture so the protected
     * `/me/password/reset` call has a usable session — DPoP key
     * materialised, refresh token on file, and a still-valid cached
     * access token (otherwise the auto-refresh interceptor would
     * preemptively kick a refresh of its own and confuse the
     * post-success assertions).
     */
    private fun Fixture.prePopulate(refreshToken: String = "refresh-v1") {
        keyStore.getOrCreate(domain)
        refreshTokenStore.set(
            domain = domain,
            record = RefreshTokenRecord(
                refreshToken = refreshToken,
                refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
            ),
        )
        accessTokenCache.set(
            domain = domain,
            entry = AccessTokenEntry(
                accessToken = scopedAccessToken,
                expiresAt = clock.epochSecond + 3_600,
            ),
        )
    }

    private fun apiError(code: String, message: String = "", status: Int = 400) =
        StubHttpSession.Canned.json(
            """{"code":"$code","message":"$message"}""",
            statusCode = status,
        )

    private fun refreshOk(
        accessToken: String = unscopedAccessToken,
        refreshToken: String = "refresh-v2",
        expiresInSec: Long = 3_600,
    ) = StubHttpSession.Canned.json(
        """{"access_token":"$accessToken","expires_at":${baseEpoch + expiresInSec}}""",
        headers = mapOf(
            HttpHeader.REFRESH_TOKEN to refreshToken,
            HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
        ),
    )

    // MARK: - Happy path

    @Test
    fun changePassword_success_invalidatesCache_andRefreshes() = runBlocking {
        // Verifies the full happy-path sequence: POST the new
        // password, drain any in-flight refresh (no-op here), and
        // run the bookkeeping refresh that mints a fresh (unscoped)
        // access token. No thrown error.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )

        fixture.client.changePassword(RedactedString("new-secret-password"))

        assertEquals(
            "password reset must be POSTed exactly once",
            1,
            fixture.http.requestCount("/v1/session/me/password/reset"),
        )
        assertEquals(
            "post-success refresh must run exactly once",
            1,
            fixture.http.requestCount("/v1/session/refresh"),
        )

        // Cache holds the post-refresh (unscoped) token, not the
        // scoped one we pre-populated. Proves the bookkeeping refresh
        // overwrote it.
        val cached = fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)
        assertNotNull("access token must be re-cached after refresh", cached)
        assertEquals(unscopedAccessToken, cached!!.accessToken)
    }

    @Test
    fun changePassword_postsPasswordInBody_withRedactedToString() = runBlocking {
        // The JSON body carries the literal plaintext (the server
        // needs to verify it), but the [RedactedString] /
        // [ChangePasswordRequestBody] toString machinery should keep
        // the value out of any structured logs.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )

        val secret = RedactedString("hunter2!")
        fixture.client.changePassword(secret)

        val req = fixture.http.requestsFor("/v1/session/me/password/reset").single()
        val body = req.bodyAsJson()
        assertEquals("hunter2!", body["password"]!!.jsonPrimitive.content)

        // No `dispatch_id` on this surface — change-password is not
        // a login surface, so no signals envelope is dispatched.
        // Encoder skips the field entirely (encodeDefaults = false),
        // so it should be absent rather than present-with-null.
        assertTrue(
            "change-password body must not carry dispatch_id",
            "dispatch_id" !in body,
        )

        assertEquals(
            "RedactedString.toString must not leak the value",
            "<redacted>",
            secret.toString(),
        )
    }

    @Test
    fun changePassword_attachesBearer_butNotDPoPProof() = runBlocking {
        // /me/password/reset is bearer-only on the server: the
        // access token + `prld:pwd:write` scope is the entire
        // credential. Sending a DPoP proof would be ignored at best,
        // and on strict proxies short-circuits the request before the
        // server can return its real status.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )

        fixture.client.changePassword(RedactedString("new-secret-password"))

        val req = fixture.http.requestsFor("/v1/session/me/password/reset").single()
        assertEquals(
            "auto-refresh must attach the cached bearer",
            "Bearer $scopedAccessToken",
            req.header(HttpHeader.AUTHORIZATION),
        )
        assertNull(
            "/me/password/reset must NOT carry a DPoP proof",
            req.header(HttpHeader.DPOP),
        )
    }

    // MARK: - Error mapping

    @Test
    fun changePassword_insufficientScope_throwsStructured_andSkipsRefresh() = runBlocking {
        // 403 / `insufficient_scope` is the canonical "you forgot to
        // step up" error. Must surface as the structured type so UIs
        // can branch on it, and the post-success refresh MUST NOT
        // run — the change didn't land, the scoped bearer is still
        // server-valid for a retry.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/me/password/reset",
            apiError("insufficient_scope", "need prld:pwd:write", status = 403),
        )

        assertThrows(PreludeSessionError.InsufficientScope::class.java) {
            runBlocking {
                fixture.client.changePassword(RedactedString("new-secret-password"))
            }
        }

        assertEquals(
            "refresh must NOT run when the change failed",
            0,
            fixture.http.requestCount("/v1/session/refresh"),
        )

        // Cache untouched — the scoped bearer remains usable for a
        // retry once the caller obtains the missing scope.
        val cached = fixture.accessTokenCache.get(fixture.domain)
        assertNotNull("cache must NOT be invalidated on failure", cached)
        assertEquals(scopedAccessToken, cached!!.accessToken)
    }

    @Test
    fun changePassword_authBlocked_throwsForbidden_andSkipsRefresh() = runBlocking {
        // 403 / `auth_blocked` — server policy denial distinct from
        // `insufficient_scope` (need step-up). Should map to
        // `Forbidden` so UIs render "your account state forbids
        // this" rather than offering step-up as the recovery.
        // Pins the [PreludeSessionError.from] mapping for this code
        // end-to-end against the change-password surface.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/me/password/reset",
            apiError("auth_blocked", "policy denial", status = 403),
        )

        assertThrows(PreludeSessionError.Forbidden::class.java) {
            runBlocking {
                fixture.client.changePassword(RedactedString("new-secret-password"))
            }
        }

        assertEquals(0, fixture.http.requestCount("/v1/session/refresh"))
        assertNotNull(
            "cache must NOT be invalidated on failure",
            fixture.accessTokenCache.get(fixture.domain),
        )
    }

    @Test
    fun changePassword_invalidPassword_throwsStructured() = runBlocking {
        // 400 / `invalid_password` — the new password failed the
        // server's policy. Distinct from `unauthorized` (wrong old
        // credentials) so callers can branch on the recovery path
        // ("pick a stronger password" vs "re-authenticate").
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/me/password/reset",
            apiError("invalid_password", "too weak", status = 400),
        )

        assertThrows(PreludeSessionError.InvalidPassword::class.java) {
            runBlocking {
                fixture.client.changePassword(RedactedString("weak"))
            }
        }

        assertEquals(
            "refresh must NOT run when the change failed",
            0,
            fixture.http.requestCount("/v1/session/refresh"),
        )
    }

    @Test
    fun changePassword_serverError_propagates_andSkipsRefresh() = runBlocking {
        // 5xx on the change itself must propagate verbatim and skip
        // the post-success bookkeeping. A subsequent retry should
        // see the same scoped bearer in the cache.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/me/password/reset",
            apiError("internal_server_error", "boom", status = 500),
        )

        assertThrows(PreludeSessionError.InternalServerError::class.java) {
            runBlocking {
                fixture.client.changePassword(RedactedString("new-secret-password"))
            }
        }

        assertEquals(0, fixture.http.requestCount("/v1/session/refresh"))
        assertNotNull(
            "cache must NOT be invalidated on failure",
            fixture.accessTokenCache.get(fixture.domain),
        )
    }

    // MARK: - Non-fatal post-success bookkeeping

    @Test
    fun changePassword_refreshFails_stillReturnsSuccess_andCacheIsInvalidated() = runBlocking {
        // The change itself succeeded — a follow-up refresh failure
        // must NOT leak as a thrown error. The cache invalidate ran
        // first (inside the replace block, before doRefresh), so the
        // next protected call's auto-refresh interceptor will drive
        // the same refresh.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to apiError(
                "internal_server_error",
                "boom",
                status = 500,
            ),
        )

        // Does NOT throw — bookkeeping failures are non-fatal.
        fixture.client.changePassword(RedactedString("new-secret-password"))

        // Refresh was attempted (so we know we got that far) but its
        // failure didn't surface to the caller.
        assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))

        // Cache was invalidated BEFORE the failed refresh, so the
        // expiration-checking accessor returns null. The raw entry
        // is still observable via getWithoutExpirationCheck so the
        // app can render the profile while the next refresh runs.
        assertNull(
            "cache must read as expired after invalidate",
            fixture.accessTokenCache.get(fixture.domain),
        )
        assertNotNull(
            "raw entry must still be observable for profile reads",
            fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain),
        )
    }

    @Test
    fun changePassword_invalidateInsideReplaceBlockRunsBeforeRefresh() = runBlocking {
        // Sequencing matters inside the replace block: invalidate
        // must run BEFORE doRefresh. If it ran AFTER, doRefresh would
        // mint and cache the unscoped token, and invalidate would
        // immediately mark it as `expiresAt = now - 1` — leaving the
        // cache fast-path missing on the very next call. We pin the
        // post-state: cache holds the unscoped token at a future
        // expiry, proving doRefresh's write was NOT clobbered by a
        // post-refresh invalidate.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )

        fixture.client.changePassword(RedactedString("new-secret-password"))

        assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
        val cached = fixture.accessTokenCache.get(fixture.domain)
        assertNotNull(
            "cache must hold the post-refresh entry (proves invalidate ran before doRefresh)",
            cached,
        )
        assertEquals(unscopedAccessToken, cached!!.accessToken)
        assertTrue(
            "post-refresh expiresAt must be in the future",
            cached.expiresAt > fixture.clock.epochSecond,
        )
    }

    @Test
    fun changePassword_invalidateStorageFails_isNonFatal() = runBlocking {
        // The bookkeeping invalidate writes to persistent storage
        // before mutating in-memory state (storage-before-memory
        // invariant in [AccessTokenCache]). When the storage write
        // throws, the in-memory entry stays at its scoped value.
        // Per the surface contract, this must NOT propagate to the
        // caller — the password change already succeeded, and the
        // auto-refresh interceptor will drive the drop on the next
        // protected call. Pins that the caller doesn't see a thrown
        // error from a follow-up cleanup hop.
        val failing = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        val fixture = Fixture.make(accessTokenStorage = failing)
        fixture.prePopulate()
        // Arm the storage failure AFTER prePopulate's cache.set has
        // landed, so it strikes only the bookkeeping invalidate.
        failing.writeFailure = RuntimeException("simulated cache write failure")
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )

        // Does NOT throw — bookkeeping failures are non-fatal.
        fixture.client.changePassword(RedactedString("new-secret-password"))

        // Storage failure rolled back the invalidate (storage-before-
        // memory ordering), so the in-memory cache still holds the
        // scoped entry at its original expiry. doRefresh did not
        // run because the failure inside the replace block
        // short-circuited it; the contract is that the next
        // protected call's auto-refresh interceptor self-heals from
        // here, which the higher-level interceptor tests already
        // cover.
        val cached = fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)
        assertNotNull(cached)
        assertEquals(scopedAccessToken, cached!!.accessToken)
    }

    @Test
    fun changePassword_cancelledMidBookkeeping_propagatesCancellation() = runBlocking {
        // The bookkeeping helper distinguishes [CancellationException]
        // from other [Exception] so structured concurrency stays
        // correct — without that distinction, cancelling a coroutine
        // running changePassword would silently complete, leaving the
        // parent hung on an "uncancelled" child.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )
        // Gate /refresh so the bookkeeping replace task suspends,
        // giving us a deterministic window to cancel.
        fixture.http.installGate("/v1/session/refresh")

        val job = launch {
            fixture.client.changePassword(RedactedString("new-secret-password"))
        }

        try {
            // Wait until the bookkeeping refresh has fired and is
            // suspended on the gate. /me/password/reset has already
            // returned by this point.
            waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }

            job.cancel()
            job.join()

            assertTrue(
                "changePassword must surface cancellation, not silently complete",
                job.isCancelled,
            )
        } finally {
            // Release so the inflight task (running on its own
            // Dispatchers.IO scope, not the test scope) can drain.
            fixture.http.releaseGate("/v1/session/refresh")
        }
    }

    // MARK: - Concurrency

    @Test
    fun changePassword_drainsInflightRefresh_thenInstallsScopeDroppingRefresh() = runBlocking {
        // A vanilla `refresh()` racing in [Inflight] may have been
        // processed server-side BEFORE /me/password/reset consumed
        // the scope, and would mint a still-scoped access token.
        // Joining its result via runOrJoin would land that scoped
        // token in the cache — exactly the leak the bookkeeping is
        // supposed to prevent. End-to-end check that the
        // [Inflight.replace] shape `refreshAfterStepUp` already uses
        // is wired through here too: drain the racing refresh, then
        // install our own that overwrites the cache with the
        // unscoped token.
        val fixture = Fixture.make()
        fixture.prePopulate(refreshToken = "refresh-v1")
        // Force the cache expired so refresh() actually hits the
        // network rather than short-circuiting on the cache.
        fixture.accessTokenCache.set(
            domain = fixture.domain,
            entry = AccessTokenEntry(
                accessToken = scopedAccessToken,
                expiresAt = fixture.clock.epochSecond - 60,
            ),
        )
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            // Vanilla refresh response carries a still-scoped token
            // (modelling the "processed before the server consumed
            // the scope" race). We swap this for the unscoped
            // response below before releasing the gate.
            "/v1/session/refresh" to refreshOk(
                accessToken = raceLostScopedAccessToken,
                refreshToken = "refresh-v2",
            ),
        )
        // Gate /refresh so the vanilla refresh suspends in the slot
        // while changePassword races to drain it.
        fixture.http.installGate("/v1/session/refresh")

        coroutineScope {
            val vanilla = async { fixture.client.refresh() }
            // Wait until the vanilla refresh is in flight, blocked
            // at the gate. Any later changePassword bookkeeping
            // observes a non-null inflight slot and has to drain.
            waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }

            val changing = async {
                fixture.client.changePassword(RedactedString("new-secret-password"))
            }

            // Release; the vanilla refresh completes (mints the
            // still-scoped token), the drain returns, and the
            // bookkeeping refresh runs (mints the unscoped token).
            // Install a second canned response so the second
            // /refresh returns the unscoped token.
            fixture.http.install(
                "/v1/session/refresh",
                refreshOk(
                    accessToken = unscopedAccessToken,
                    refreshToken = "refresh-v3",
                ),
            )
            fixture.http.releaseGate("/v1/session/refresh")
            vanilla.await()
            changing.await()
        }

        // Two `/refresh` round-trips: the racing vanilla refresh and
        // the post-drain bookkeeping refresh.
        assertEquals(2, fixture.http.requestCount("/v1/session/refresh"))

        // Final cached token is the unscoped one: the bookkeeping's
        // post-drain refresh overwrote whatever the vanilla refresh
        // had landed. If we'd run runOrJoin instead of replace, the
        // bookkeeping would have piggybacked on the racing result
        // and the cache would hold the still-scoped token here.
        val cached = fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)
        assertNotNull(cached)
        assertEquals(unscopedAccessToken, cached!!.accessToken)
        // Final stored refresh token reflects the LAST rotation —
        // the bookkeeping one.
        assertEquals(
            "refresh-v3",
            fixture.refreshTokenStore.get(fixture.domain)?.refreshToken,
        )
    }

    // MARK: - Helpers

    private fun okhttp3.Request.bodyAsString(): String {
        val buffer = Buffer()
        body?.writeTo(buffer)
        return buffer.readUtf8()
    }

    private fun okhttp3.Request.bodyAsJson(): JsonObject =
        Json.parseToJsonElement(bodyAsString()).jsonObject

    /**
     * See [LogoutTests.waitUntil] / [StepUpTests.waitUntil] — same
     * shape, copied here to keep each suite self-contained.
     */
    private suspend fun waitUntil(timeoutMs: Long = 2_000, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            delay(5)
        }
        throw AssertionError("timed out waiting for condition (after ${timeoutMs}ms)")
    }

    @Test
    fun changePassword_success_clearsActiveStepUp() = runBlocking {
        // The reset consumes any in-flight step-up; the handle must
        // not survive a successful reset, otherwise an observer would
        // see a stale challenge after the scope's been spent.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/me/password/reset" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/refresh" to refreshOk(),
        )
        // Seed an active handle directly — the lifecycle through
        // requestStepUp/submitStepUpOTP is covered by the step-up suite;
        // here we only care about the post-reset clear.
        fixture.client.setActiveStepUp(
            PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write"),
        )

        fixture.client.changePassword(RedactedString("new-secret-password"))

        assertNull(
            "successful reset must clear activeStepUp",
            fixture.client.activeStepUp,
        )
    }

    @Test
    fun changePassword_failure_clearsActiveStepUp() = runBlocking {
        // Symmetric to the success case: the handle clears on every
        // outcome via `finally`. A stale challenge surviving a failed
        // reset would let an observer believe a flow is still open
        // when it's already been consumed by the request — and the
        // recovery path is the same as success (re-request step-up).
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/me/password/reset",
            apiError("invalid_password", "too weak", status = 400),
        )
        fixture.client.setActiveStepUp(
            PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write"),
        )

        assertThrows(PreludeSessionError.InvalidPassword::class.java) {
            runBlocking {
                fixture.client.changePassword(RedactedString("weak"))
            }
        }
        assertNull(
            "failed reset must still clear activeStepUp",
            fixture.client.activeStepUp,
        )
    }
}
