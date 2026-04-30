package so.prelude.android.session

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.store.AccessTokenEntry
import so.prelude.android.session.store.RefreshTokenRecord
import java.util.Base64

/**
 * Unit tests for the step-up surface (`requestStepUp`,
 * `submitStepUpOTP`).
 *
 * Each test spins up a [Fixture], installs canned HTTP responses
 * keyed by path, exercises the public client API, and asserts on
 * side-effects (recorded request shapes, the returned
 * [PreludeStepUpChallenge] handle, the access token cache, and the
 * refresh-token store after a post-completion refresh).
 *
 * Uses [runBlocking] for the same reason as the OTP / password /
 * logout suites — the interceptor chain hops through
 * `withContext(Dispatchers.IO)` and mixing virtual time with a real
 * dispatcher makes assertions about suspending state-mutations
 * fragile.
 */
class StepUpTests {

    // A well-formed unsigned JWT carrying a scoped access token.
    // payload: {"sub":"user-1","sid":"sess-1"}
    private val scopedAccessToken =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    /** Fixed clock baseline used across the suite. */
    private val baseEpoch: Long = 1_700_000_000L

    private val verifyEmailToken: String by lazy {
        makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_email",
                "jti" to "jti-otp",
                "exp" to baseEpoch + 600,
            ),
        )
    }

    private val verifySmsToken: String by lazy {
        makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_sms",
                "jti" to "jti-sms",
                "exp" to baseEpoch + 600,
            ),
        )
    }

    private val completedToken: String by lazy {
        makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "completed",
                "jti" to "jti-completed",
                "exp" to baseEpoch + 600,
            ),
        )
    }

    /**
     * Pre-populate the fixture so the protected `/stepup/request`
     * call has a usable session. Keep the access token unexpired so
     * the auto-refresh interceptor doesn't kick a refresh of its own
     * — every test that needs the auto-refresh path opts in
     * explicitly.
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

    private fun stepUpResponse(status: String, challengeToken: String? = null): StubHttpSession.Canned {
        // Build the JSON body explicitly rather than via TQS interpolation:
        // a triple-quoted string containing `"$x"""` lexes ambiguously
        // around the trailing closing-quote vs. the value's closing `"`,
        // and getting it wrong here would silently produce malformed JSON
        // the tests wouldn't catch until decode time.
        val tokenField = if (challengeToken != null) {
            ",\"challenge_token\":\"$challengeToken\""
        } else {
            ""
        }
        return StubHttpSession.Canned.json("""{"status":"$status"$tokenField}""")
    }

    private fun apiError(code: String, message: String = "", status: Int = 400) =
        StubHttpSession.Canned.json(
            """{"code":"$code","message":"$message"}""",
            statusCode = status,
        )

    private fun refreshOk(refreshToken: String = "refresh-v2", expiresInSec: Long = 3_600) =
        StubHttpSession.Canned.json(
            """{"access_token":"$scopedAccessToken","expires_at":${baseEpoch + expiresInSec}}""",
            headers = mapOf(
                HttpHeader.REFRESH_TOKEN to refreshToken,
                HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
            ),
        )

    // MARK: - requestStepUp

    @Test
    fun requestStepUp_otpStep_returnsChallenge_andAutoFiresOTPDelivery() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertEquals(PreludeStepUpStatus.CONTINUE, challenge.status)
        assertEquals("chal-1", challenge.challengeId)
        assertEquals("verify_email", challenge.currentStep)
        assertEquals("prld:pwd:write", challenge.requestedScope)

        // Auto-kick: /otp fires inline so the caller's next action is
        // just "submit the code".
        assertEquals(1, fixture.http.requestCount("/v1/session/otp"))
        // The /otp body is identified by the challenge token, NOT by
        // a bearer or DPoP — same shape as the unauthenticated start
        // of an OTP login.
        val otpBody = fixture.http.requestsFor("/v1/session/otp").single().bodyAsJson()
        assertEquals(verifyEmailToken, otpBody["challenge_token"]!!.jsonPrimitive.content)
        Unit
    }

    @Test
    fun requestStepUp_blocked_returnsBlockedHandle_andSkipsOTPDelivery() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/stepup/request",
            stepUpResponse("block"),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertEquals(PreludeStepUpStatus.BLOCKED, challenge.status)
        assertEquals("prld:pwd:write", challenge.requestedScope)
        assertEquals("blocked challenge must not carry a challenge id", "", challenge.challengeId)
        assertEquals(0, fixture.http.requestCount("/v1/session/otp"))
        Unit
    }

    @Test
    fun requestStepUp_underReview_returnsReviewHandle_andSkipsOTPDeliveryWhenStepIsNotOTP() = runBlocking {
        // A `review` status with a non-OTP `current_step` (e.g. an
        // out-of-band `wait_for_review` step) must NOT auto-kick the
        // OTP route — there's no code to send and the server would
        // reject the request.
        val fixture = Fixture.make()
        fixture.prePopulate()
        val reviewToken = makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-2",
                "current_step" to "wait_for_review",
                "jti" to "jti-review",
                "exp" to baseEpoch + 600,
            ),
        )
        fixture.http.install(
            "/v1/session/stepup/request",
            stepUpResponse("review", reviewToken),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertEquals(PreludeStepUpStatus.UNDER_REVIEW, challenge.status)
        assertEquals("wait_for_review", challenge.currentStep)
        assertEquals(0, fixture.http.requestCount("/v1/session/otp"))
        Unit
    }

    @Test
    fun requestStepUp_continueWithoutChallengeToken_throwsMissingChallengeToken() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulate()
        // Server contract violation: `continue` MUST carry a token.
        fixture.http.install(
            "/v1/session/stepup/request",
            stepUpResponse("continue"),
        )

        val thrown = assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
        }
        assertTrue(
            thrown.message!!.contains("Missing challenge token"),
        )
    }

    @Test
    fun requestStepUp_unknownStatus_surfacesGenericError() = runBlocking {
        // A server emitting a status the SDK doesn't model (e.g. a
        // future `pending` value rolled out before the SDK ships) is
        // surfaced as `Generic` rather than silently coerced to one
        // of the known enum values.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/stepup/request",
            StubHttpSession.Canned.json("""{"status":"pending"}"""),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
        }
        assertEquals("unknown_stepup_status", thrown.code)
    }

    @Test
    fun requestStepUp_scopeNotAllowed_surfacesForbidden() = runBlocking {
        // `scope_not_allowed` is step-up's specific refusal — the
        // session may not request this scope at all. Mapped to
        // Forbidden by the central error mapper.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/stepup/request",
            apiError("scope_not_allowed", "no", status = 403),
        )

        assertThrows(PreludeSessionError.Forbidden::class.java) {
            runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
        }
        Unit
    }

    @Test
    fun requestStepUp_postsScope_andOmitsDispatchIdWhenUnconfigured() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
        )

        fixture.client.requestStepUp(scope = "prld:pwd:write")

        val body = fixture.http.requestsFor("/v1/session/stepup/request")
            .single().bodyAsJson()
        assertEquals("prld:pwd:write", body["scope"]!!.jsonPrimitive.content)
        // No dispatcher configured → `dispatch_id` is omitted (encoder
        // skips defaults), not sent as null.
        assertFalse("dispatch_id should be omitted", body.containsKey("dispatch_id"))
        Unit
    }

    @Test
    fun requestStepUp_attachesDispatchId_whenSignalsDispatcherConfigured() = runBlocking {
        var dispatched = 0
        val fixture = Fixture.make(
            signalsDispatcher = {
                dispatched += 1
                "dispatch-stepup"
            },
        )
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
        )

        fixture.client.requestStepUp(scope = "prld:pwd:write")

        // Two dispatches: one for /stepup/request, one for the
        // auto-fired /otp delivery.
        assertEquals(2, dispatched)
        val stepUpBody = fixture.http.requestsFor("/v1/session/stepup/request")
            .single().bodyAsJson()
        assertEquals("dispatch-stepup", stepUpBody["dispatch_id"]!!.jsonPrimitive.content)
    }

    // MARK: - submitStepUpOTP

    @Test
    fun submitStepUpOTP_blockedChallenge_throwsInvalidChallengeToken_withoutNetwork() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulate()

        val blocked = PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write")

        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(blocked, code = "123456") }
        }
        // The SDK must not fire `/otp/check` on a blocked handle —
        // there's no token to bind the proof to.
        assertEquals(0, fixture.http.requestCount("/v1/session/otp/check"))
        Unit
    }

    @Test
    fun submitStepUpOTP_expiredChallenge_throwsInvalidChallengeToken_withoutNetwork() = runBlocking {
        // Server-side an expired challenge surfaces as
        // `bad_check_code` — indistinguishable from a wrong code by
        // design. Catching expiry locally lets the UI tell the user
        // "your verification expired, request a fresh one" rather
        // than just "wrong code".
        //
        // Use a JWT whose `exp` is already in the past relative to
        // the fixture's pinned clock, with the stub's `Date:` header
        // matching the same clock. That keeps the [HttpClient]
        // clock-skew adjustment at zero, so the local expiry guard
        // compares the JWT `exp` directly against `now` — nothing
        // shifts the boundary either way.
        val fixture = Fixture.make()
        fixture.prePopulate()
        val alreadyExpiredToken = makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_email",
                "jti" to "jti-expired",
                // 100 seconds in the past from the fixture clock.
                "exp" to baseEpoch - 100,
            ),
        )
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", alreadyExpiredToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            // /otp/check intentionally NOT installed — the local
            // expiry guard must short-circuit before any /otp/check
            // round-trip. If it doesn't, the stub will fail loudly
            // with "no canned response installed", and that's the
            // failure mode we want to catch in CI.
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(challenge, code = "123456") }
        }

        assertEquals(
            "expired challenge must short-circuit before /otp/check",
            0,
            fixture.http.requestCount("/v1/session/otp/check"),
        )
    }

    @Test
    fun submitStepUpOTP_completed_refreshesWithStepUpToken_andReturnsNull() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulate(refreshToken = "refresh-v1")
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to StubHttpSession.Canned.json(
                """{"challenge_token":"$completedToken"}""",
            ),
            "/v1/session/refresh" to refreshOk(refreshToken = "refresh-v2"),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        val next = fixture.client.submitStepUpOTP(challenge, code = "123456")

        assertNull("completed challenge must yield a null follow-up", next)

        // Post-completion refresh sent `step_up_token` so the server
        // mints a scoped access token. Verifies the integration
        // between submitStepUpOTP -> refreshAfterStepUp -> doRefresh.
        val refreshRequests = fixture.http.requestsFor("/v1/session/refresh")
        assertEquals(1, refreshRequests.size)
        val refreshBody = refreshRequests.single().bodyAsJson()
        assertEquals(completedToken, refreshBody["step_up_token"]!!.jsonPrimitive.content)
        assertEquals(
            "refresh-v1",
            refreshRequests.single().header(HttpHeader.REFRESH_TOKEN),
        )

        // Rotated token persisted; scoped access token cached.
        assertEquals(
            "refresh-v2",
            fixture.refreshTokenStore.get(fixture.domain)?.refreshToken,
        )
        val cached = fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)
        assertNotNull(cached)
        assertEquals(scopedAccessToken, cached!!.accessToken)
    }

    @Test
    fun submitStepUpOTP_advancesToOTPStep_autoFiresNextDelivery() = runBlocking {
        // Multi-step OTP: `verify_email` → `verify_sms`. The second
        // delivery MUST fire automatically — without symmetry with
        // `requestStepUp`'s auto-kick the chain would silently stall
        // waiting for an SMS the server never sent.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to StubHttpSession.Canned.json(
                """{"challenge_token":"$verifySmsToken"}""",
            ),
        )

        val first = fixture.client.requestStepUp(scope = "prld:pwd:write")
        assertEquals(
            "first OTP delivery should have fired during requestStepUp",
            1,
            fixture.http.requestCount("/v1/session/otp"),
        )

        val next = fixture.client.submitStepUpOTP(first, code = "123456")

        assertNotNull("multi-step flow returns the next challenge", next)
        assertEquals("verify_sms", next!!.currentStep)
        assertEquals("chal-1", next.challengeId)
        // Same scope and status — those persist across the chain.
        assertEquals("prld:pwd:write", next.requestedScope)
        assertEquals(PreludeStepUpStatus.CONTINUE, next.status)

        assertEquals(
            "second OTP delivery should have fired during submitStepUpOTP",
            2,
            fixture.http.requestCount("/v1/session/otp"),
        )
    }

    @Test
    fun submitStepUpOTP_badCheckCode_throwsInvalidOTPCode_andLeavesChallengeReusable() = runBlocking {
        // `bad_check_code` means "retry the code" — distinct from a
        // dead challenge. The original handle stays usable up to the
        // server's bucket limit; only after that does the server
        // start rejecting the challenge as expired.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to apiError("bad_check_code", "wrong", status = 401),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertThrows(PreludeSessionError.InvalidOTPCode::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(challenge, code = "000000") }
        }

        // The handle is still good — same id, same step.
        assertEquals("chal-1", challenge.challengeId)
        assertEquals("verify_email", challenge.currentStep)
    }

    @Test
    fun submitStepUpOTP_otpCheckMissingChallengeToken_surfacesStructuredError() = runBlocking {
        // A `/otp/check` 200 without a `challenge_token` is a server
        // contract violation; surface as MissingChallengeToken so a
        // backend regression is actionable.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to StubHttpSession.Canned.json("""{}"""),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(challenge, code = "123456") }
        }
        Unit
    }

    @Test
    fun submitStepUpOTP_attachesChallengeDPoPProof_andOmitsBearer() = runBlocking {
        // `/otp/check` is authenticated via the challenge token in
        // the body + a DPoP proof bound to the challenge's `jti`.
        // No bearer — there's nothing to refresh on this hop, and
        // attaching one would route auth via the wrong layer.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to StubHttpSession.Canned.json(
                """{"challenge_token":"$verifySmsToken"}""",
            ),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        fixture.client.submitStepUpOTP(challenge, code = "123456")

        val req = fixture.http.requestsFor("/v1/session/otp/check").single()
        assertNotNull(
            "/otp/check must carry a challenge-bound DPoP proof",
            req.header(HttpHeader.DPOP),
        )
        assertNull(
            "/otp/check must not carry a bearer token",
            req.header(HttpHeader.AUTHORIZATION),
        )
        // The body carries the challenge token verbatim — that's
        // what the server matches against the DPoP `jti`.
        val body = req.bodyAsJson()
        assertEquals(verifyEmailToken, body["challenge_token"]!!.jsonPrimitive.content)
        assertEquals("123456", body["code"]!!.jsonPrimitive.content)
    }

    // MARK: - Concurrency

    @Test
    fun submitStepUpOTP_completion_drainsInflightRefresh_thenInstallsScopedRefresh() = runBlocking {
        // A vanilla `refresh()` racing in the inflight slot would
        // mint an UNSCOPED access token; the post-completion refresh
        // must drain it first, then install a scoped refresh that
        // any concurrent caller piggybacks on. End-to-end check that
        // [Inflight.replace] is wired through correctly.
        val fixture = Fixture.make()
        fixture.prePopulate(refreshToken = "refresh-v1")
        // Force an expired access token so refresh() actually hits
        // the network rather than short-circuiting on the cache.
        fixture.accessTokenCache.set(
            domain = fixture.domain,
            entry = AccessTokenEntry(
                accessToken = scopedAccessToken,
                expiresAt = fixture.clock.epochSecond - 60,
            ),
        )
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to StubHttpSession.Canned.json(
                """{"challenge_token":"$completedToken"}""",
            ),
            "/v1/session/refresh" to refreshOk(refreshToken = "refresh-v2"),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        // Gate /refresh so the vanilla refresh suspends in the slot
        // while submitStepUpOTP races to drain it.
        fixture.http.installGate("/v1/session/refresh")

        coroutineScope {
            val vanilla = async { fixture.client.refresh() }
            // Wait until the vanilla refresh is in flight, blocked
            // at the gate. Any later submitStepUpOTP completion will
            // observe a non-null inflight slot and have to drain.
            waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }

            val submit = async {
                fixture.client.submitStepUpOTP(challenge, code = "123456")
            }

            // Release; the vanilla refresh completes (refresh-v1 →
            // refresh-v2), the drain returns, and the post-completion
            // refresh runs (refresh-v2 → refresh-v3). We install a
            // second canned response so the second /refresh succeeds.
            fixture.http.install(
                "/v1/session/refresh",
                refreshOk(refreshToken = "refresh-v3"),
            )
            fixture.http.releaseGate("/v1/session/refresh")
            vanilla.await()
            submit.await()
        }

        // Two `/refresh` round-trips: one vanilla, one scoped.
        assertEquals(2, fixture.http.requestCount("/v1/session/refresh"))
        // The scoped refresh shipped the step-up token; the vanilla
        // one did not.
        val refreshBodies = fixture.http.requestsFor("/v1/session/refresh")
            .map { it.bodyAsJson() }
        assertEquals(
            "exactly one /refresh must carry step_up_token",
            1,
            refreshBodies.count { it.containsKey("step_up_token") },
        )
        // Final stored refresh token reflects the LAST rotation —
        // the scoped one.
        assertEquals(
            "refresh-v3",
            fixture.refreshTokenStore.get(fixture.domain)?.refreshToken,
        )
    }

    @Test
    fun logoutDuringSubmitCompletion_surfacesUnauthorizedFromRefresh() = runBlocking {
        // A logout that lands while `/otp/check` is in flight has
        // already revoked the session by the time the post-completion
        // refresh runs. The refresh's epoch guard catches the bumped
        // counter (or the empty refresh-token store maps to a 401)
        // and surfaces Unauthorized — not a successful resurrection.
        val fixture = Fixture.make()
        fixture.prePopulate(refreshToken = "refresh-v1")
        fixture.http.installAll(
            "/v1/session/stepup/request" to stepUpResponse("continue", verifyEmailToken),
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to StubHttpSession.Canned.json(
                """{"challenge_token":"$completedToken"}""",
            ),
            // Stub /refresh to fail with 401 — the post-logout state
            // has no refresh token to ship, and the server responds
            // with an unauthorized payload.
            "/v1/session/refresh" to apiError(
                "unauthorized",
                "no refresh token",
                status = 401,
            ),
            "/v1/session/revoke" to StubHttpSession.Canned(statusCode = 204),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        // Gate /otp/check so logout can race the post-completion
        // refresh that submitStepUpOTP triggers.
        fixture.http.installGate("/v1/session/otp/check")

        // `supervisorScope` so the expected throw from the racing
        // submit doesn't cascade through the scope before we can
        // assert on it. Same reasoning as the logout suite.
        supervisorScope {
            val submit = async {
                fixture.client.submitStepUpOTP(challenge, code = "123456")
            }
            // Wait for /otp/check to be in flight, blocked at the gate.
            waitUntil { fixture.http.requestCount("/v1/session/otp/check") >= 1 }

            // Logout wipes stores and bumps the epoch while
            // /otp/check is suspended.
            fixture.client.logout()

            // Release /otp/check; the submit advances to its
            // post-completion refresh, which sees no refresh token
            // and surfaces Unauthorized.
            fixture.http.releaseGate("/v1/session/otp/check")

            val caught = runCatching { submit.await() }.exceptionOrNull()
            assertTrue(
                "expected Unauthorized, got $caught",
                caught is PreludeSessionError.Unauthorized,
            )
        }

        // Stores stay wiped — the scoped refresh did not persist
        // into stores logout just emptied.
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun multipleSequentialStepUpFlows_useIndependentChallengeHandles() = runBlocking {
        // The challenge handle is value-typed, so distinct step-ups
        // on the same client don't share state — neither response
        // overwrites the prior handle. The stub serves the
        // most-recently-installed canned response, which is why this
        // is structured as two sequential calls rather than a true
        // race; the value-typed contract is what we're pinning here.
        val fixture = Fixture.make()
        fixture.prePopulate()

        val tokenA = makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-A",
                "current_step" to "verify_email",
                "jti" to "jti-A",
                "exp" to baseEpoch + 600,
            ),
        )
        val tokenB = makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-B",
                "current_step" to "verify_sms",
                "jti" to "jti-B",
                "exp" to baseEpoch + 600,
            ),
        )

        // Two distinct stepup/request responses delivered round-robin
        // — first call gets A, second gets B. The stub serves the
        // most-recently installed canned response, so we can't simply
        // install both; instead we do them sequentially.
        fixture.http.install("/v1/session/stepup/request", stepUpResponse("continue", tokenA))
        fixture.http.install("/v1/session/otp", StubHttpSession.Canned(statusCode = 204))

        val challengeA = fixture.client.requestStepUp(scope = "prld:scope:a")

        fixture.http.install("/v1/session/stepup/request", stepUpResponse("continue", tokenB))
        val challengeB = fixture.client.requestStepUp(scope = "prld:scope:b")

        assertEquals("chal-A", challengeA.challengeId)
        assertEquals("chal-B", challengeB.challengeId)
        // Distinct tokens preserved on the handles — neither was
        // overwritten by the second request's response.
        assertEquals("prld:scope:a", challengeA.requestedScope)
        assertEquals("prld:scope:b", challengeB.requestedScope)
    }

    @Test
    fun requestStepUp_underReview_skipsOTPDelivery_evenWhenStepIsOTP() = runBlocking {
        // A `review` flow is server-side asynchronous — the caller
        // shouldn't be auto-firing `/otp` regardless of what
        // `current_step` reads. The previous gate keyed only on the
        // step name, so a `review` response that happened to carry
        // `verify_email` would have triggered an unsolicited OTP
        // delivery. This pins the wider gate (status == CONTINUE).
        val fixture = Fixture.make()
        fixture.prePopulate()
        val reviewOtpToken = makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-r",
                "current_step" to "verify_email",
                "jti" to "jti-review-otp",
                "exp" to baseEpoch + 600,
            ),
        )
        fixture.http.install(
            "/v1/session/stepup/request",
            stepUpResponse("review", reviewOtpToken),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertEquals(PreludeStepUpStatus.UNDER_REVIEW, challenge.status)
        assertEquals("verify_email", challenge.currentStep)
        assertEquals(
            "review status must skip OTP delivery regardless of current_step",
            0,
            fixture.http.requestCount("/v1/session/otp"),
        )
    }

    @Test
    fun requestStepUp_directlyCompletedChallenge_throwsInvalidChallengeToken() = runBlocking {
        // Defensive: `/stepup/request` is contracted to emit flows
        // that need at least one verification step. A response that
        // arrives already at `completed` is a server contract
        // violation; surface as InvalidChallengeToken so a backend
        // regression is loud rather than handing the caller a handle
        // that submitStepUpOTP would reject as expired.
        val fixture = Fixture.make()
        fixture.prePopulate()
        fixture.http.install(
            "/v1/session/stepup/request",
            stepUpResponse("continue", completedToken),
        )

        val thrown = assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
        }
        assertTrue(
            "error message should call out the directly-completed shape",
            thrown.message!!.contains("already-completed"),
        )
        // The defensive throw fires BEFORE any post-completion
        // refresh — a refused handle must not silently consume the
        // refresh-token rotation.
        assertEquals(0, fixture.http.requestCount("/v1/session/refresh"))
    }

    // MARK: - Helpers

    /**
     * Build a well-formed but unsigned JWT. The SDK's [JwtDecoder]
     * reads only the header + payload, so a placeholder signature
     * is enough to round-trip the test claims.
     */
    private fun makeChallengeToken(claims: Map<String, Any>): String {
        val header = base64Url("""{"alg":"HS256","typ":"JWT"}""".toByteArray())
        // Hand-roll the payload JSON in a deterministic order — the
        // SDK doesn't care about key order, but stable output makes
        // golden-token snapshots predictable across JVM versions.
        val payloadJson = buildString {
            append('{')
            claims.entries.forEachIndexed { i, (k, v) ->
                if (i > 0) append(',')
                append('"').append(k).append('"').append(':')
                when (v) {
                    is Number, is Boolean -> append(v.toString())
                    else -> append('"').append(v.toString().replace("\"", "\\\"")).append('"')
                }
            }
            append('}')
        }
        val payload = base64Url(payloadJson.toByteArray())
        return "$header.$payload.sig"
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** See [LogoutTests.waitUntil] — same shape, copied here to keep
     *  each suite self-contained. */
    private suspend fun waitUntil(timeoutMs: Long = 2_000, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            delay(5)
        }
        throw AssertionError("timed out waiting for condition (after ${timeoutMs}ms)")
    }

    private fun okhttp3.Request.bodyAsString(): String {
        val buffer = Buffer()
        body?.writeTo(buffer)
        return buffer.readUtf8()
    }

    private fun okhttp3.Request.bodyAsJson(): JsonObject =
        Json.parseToJsonElement(bodyAsString()).jsonObject
}
