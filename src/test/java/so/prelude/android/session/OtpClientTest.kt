package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
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
import so.prelude.android.session.store.FailingRefreshTokenStorage
import so.prelude.android.session.store.InMemoryRefreshTokenStorage

/**
 * Unit tests for the OTP login surface (`startOTPLogin`, `retryOTP`,
 * `checkOTP`) and the shared `finalizeLogin` helper they delegate to.
 *
 * Each test spins up a [Fixture], installs canned HTTP responses keyed
 * by path, exercises the public client API, and asserts on
 * side-effects (cache, refresh-token store, recorded request shapes).
 *
 * We use [runBlocking] (not [kotlinx.coroutines.test.runTest]) because
 * the production code path goes through `withContext(Dispatchers.IO)`
 * inside [so.prelude.android.session.http.DPoPInterceptor]; mixing
 * virtual time with a real dispatcher makes assertions about
 * suspending state-mutations fragile. Same reasoning as
 * [InflightTest].
 */
class OtpClientTest {

    // A well-formed unsigned JWT. The decoder reads only the payload,
    // so this is enough to round-trip a `userId = user-1` profile.
    // payload: {"sub":"user-1"} → eyJzdWIiOiJ1c2VyLTEifQ
    private val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private val emailIdentifier = PreludeIdentifier(
        type = PreludeIdentifierType.EMAIL_ADDRESS,
        value = "alice@example.com",
    )

    private fun checkOkResponse(challenge: String = "challenge-abc") =
        StubHttpSession.Canned.json("""{"challenge_token":"$challenge"}""")

    private fun finalizeOkResponse(
        accessToken: String = jwt,
        expiresInSec: Long = 3600,
        refreshToken: String? = "refresh-v1",
        refreshExpiresAt: String? = null,
    ): StubHttpSession.Canned {
        val expiresAt = 1_700_000_000L + expiresInSec
        val headers = mutableMapOf<String, String>()
        if (refreshToken != null) headers[HttpHeader.REFRESH_TOKEN] = refreshToken
        if (refreshExpiresAt != null) {
            headers[HttpHeader.REFRESH_TOKEN_EXPIRES_AT] = refreshExpiresAt
        }
        return StubHttpSession.Canned.json(
            """{"access_token":"$accessToken","expires_at":$expiresAt}""",
            headers = headers,
        )
    }

    private fun apiError(code: String, message: String = "", status: Int = 400) =
        StubHttpSession.Canned.json(
            """{"code":"$code","message":"$message"}""",
            statusCode = status,
        )

    // MARK: - startOTPLogin

    @Test
    fun startOTPLogin_postsIdentifier_andOmitsDispatchIdWhenUnconfigured() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.startOTPLogin(StartOTPLoginOptions(identifier = emailIdentifier))

        val req = fixture.http.requestsFor("/v1/session/otp").single()
        val body = req.bodyAsJson()
        assertEquals(
            "email_address",
            body["identifier"]!!.jsonObject["type"]!!.jsonPrimitive.content,
        )
        assertEquals(
            "alice@example.com",
            body["identifier"]!!.jsonObject["value"]!!.jsonPrimitive.content,
        )
        // No dispatcher configured → `dispatch_id` is omitted entirely
        // (encoder skips defaults) rather than sent as null.
        assertFalse("dispatch_id should be omitted", body.containsKey("dispatch_id"))
        // No login_config_id supplied → also omitted.
        assertFalse(
            "login_config_id should be omitted",
            body.containsKey("login_config_id"),
        )
        Unit
    }

    @Test
    fun startOTPLogin_attachesDispatchId_whenSignalsDispatcherIsConfigured() = runBlocking {
        var dispatched = 0
        val fixture = Fixture.make(
            signalsDispatcher = {
                dispatched += 1
                "dispatch-xyz"
            },
        )
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier = emailIdentifier,
                loginConfigId = "cfg-1",
            ),
        )

        assertEquals(1, dispatched)
        val body = fixture.http.requestsFor("/v1/session/otp").single().bodyAsJson()
        assertEquals("dispatch-xyz", body["dispatch_id"]!!.jsonPrimitive.content)
        assertEquals("cfg-1", body["login_config_id"]!!.jsonPrimitive.content)
        Unit
    }

    @Test
    fun startOTPLogin_dispatcherFailure_wrapsAsSignalsDispatchFailed_andSkipsHttp() {
        val fixture = Fixture.make(
            signalsDispatcher = { error("boom") },
        )
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        val thrown = assertThrows(PreludeSessionError.SignalsDispatchFailed::class.java) {
            runBlocking {
                fixture.client.startOTPLogin(
                    StartOTPLoginOptions(identifier = emailIdentifier),
                )
            }
        }
        // Underlying dispatcher exception is preserved as the cause so
        // diagnostic UIs can drill into the real failure rather than
        // just seeing the wrapper.
        assertTrue(
            "expected IllegalStateException cause, got ${thrown.cause}",
            thrown.cause is IllegalStateException,
        )
        // The HTTP call must not have been issued — silently shipping a
        // login without anti-fraud coverage would be the worst possible
        // failure mode.
        assertTrue(fixture.http.requestsFor("/v1/session/otp").isEmpty())
    }

    @Test
    fun startOTPLogin_rateLimited_mapsToStructuredError() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp",
            apiError("rate_limited", "slow down", status = 429),
        )

        assertThrows(PreludeSessionError.RateLimited::class.java) {
            runBlocking {
                fixture.client.startOTPLogin(
                    StartOTPLoginOptions(identifier = emailIdentifier),
                )
            }
        }
    }

    // MARK: - retryOTP

    @Test
    fun retryOTP_postsToRetryPath_withEmptyBody() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/retry",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.retryOTP()

        val req = fixture.http.requestsFor("/v1/session/otp/retry").single()
        assertEquals("POST", req.method)
        // Default empty `{}` body is fine; servers that ignore it stay
        // untouched, servers that decode it parse a no-op object.
        assertEquals("{}", req.bodyAsString())
        Unit
    }

    // MARK: - checkOTP → finalizeLogin

    @Test
    fun checkOTP_happyPath_returnsUser_persistsRefresh_andCachesAccessToken() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(
                refreshToken = "refresh-v1",
                refreshExpiresAt = "2099-01-01T00:00:00Z",
            ),
        )

        val user = fixture.client.checkOTP("123456")

        assertEquals(jwt, user.accessToken)
        assertEquals("user-1", user.profile.userId)

        val record = fixture.refreshTokenStore.get(fixture.domain)
        assertNotNull(record)
        assertEquals("refresh-v1", record!!.refreshToken)
        assertEquals("2099-01-01T00:00:00Z", record.refreshTokenExpiresAt)

        // Access token cache reflects the finalize response.
        val cached = fixture.accessTokenCache.get(fixture.domain)
        assertNotNull(cached)
        assertEquals(jwt, cached!!.accessToken)

        // The check request body carries the OTP code verbatim.
        val checkBody = fixture.http.requestsFor("/v1/session/otp/check")
            .single().bodyAsJson()
        assertEquals("123456", checkBody["code"]!!.jsonPrimitive.content)

        // The finalize request body carries the challenge token from
        // /otp/check verbatim.
        val finalizeBody = fixture.http.requestsFor("/v1/session/login/finalize")
            .single().bodyAsJson()
        assertEquals(
            "challenge-abc",
            finalizeBody["challenge_token"]!!.jsonPrimitive.content,
        )
        Unit
    }

    @Test
    fun checkOTP_missingChallengeToken_throwsStructured() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/check",
            StubHttpSession.Canned.json("{}"),
        )

        assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
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
        // The server contract says the field is non-empty when present;
        // empty string is treated identically to a missing field so a
        // backend regression surfaces the same way regardless of which
        // shape it took.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/check",
            StubHttpSession.Canned.json("""{"challenge_token":""}"""),
        )

        assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
    }

    @Test
    fun checkOTP_badCheckCode_mapsToInvalidOtpCode() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/check",
            apiError("bad_check_code", "wrong code", status = 400),
        )

        assertThrows(PreludeSessionError.InvalidOTPCode::class.java) {
            runBlocking { fixture.client.checkOTP("000000") }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
    }

    @Test
    fun checkOTP_finalizeReturnsEmptyAccessToken_throwsGeneric() {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
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
    fun checkOTP_finalizeWithoutRefreshHeader_doesNotPersistRefreshToken() = runBlocking {
        // Server omitting `X-Refresh-Token` is a backend regression we
        // shouldn't crash on; the access token still lands in the cache
        // so the user is functionally logged in until the next refresh.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(refreshToken = null),
        )

        val user = fixture.client.checkOTP("123456")
        assertEquals(jwt, user.accessToken)
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.get(fixture.domain))
        Unit
    }

    @Test
    fun checkOTP_invalidChallengeToken_mapsToStructured_andDoesNotPersist() {
        // Race window: the challenge token /otp/check just minted
        // expires (or the server rotates its signing key) before
        // /login/finalize sees it. The request body is well-formed —
        // the failure surfaces as `invalid_challenge_token`.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to apiError(
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
        // malformed JWT. On the login path the *challenge* token was
        // accepted (otherwise we wouldn't have reached makeUser), so the
        // OTP path re-maps to a structured access-token error.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(
                accessToken = "not.a.jwt",
            ),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        assertEquals("invalid_access_token", thrown.code)
    }

    @Test
    fun checkOTP_finalizeAccessExpiry_isClockSkewAdjusted() = runBlocking {
        // Drift the server's `Date` 60s behind the fixture's local
        // clock. The HttpClient's `timeDiffSec` should pick up
        // local - server = +60s, and `storeAccessToken` should add it
        // to the server-supplied `expires_at` so the cache compares
        // correctly against the local clock.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to StubHttpSession.Canned.json(
                """{"access_token":"$jwt","expires_at":1700003600}""",
                headers = mapOf(
                    HttpHeader.REFRESH_TOKEN to "refresh-v1",
                    // 1_700_000_000 - 60 = 1_699_999_940 → 1969...
                    // We just need any `Date` 60s before the fixture clock.
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
        // The refresh-before-access ordering invariant: a write failure
        // on the refresh-token store must abort *before* the access
        // token lands in the cache. Otherwise we'd hand the auto-refresh
        // interceptor a fresh access token paired with a stale-or-missing
        // refresh token on disk, and the next 401 would have nothing to
        // recover with.
        val failingStorage = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage()).apply {
            writeFailure = RuntimeException("simulated disk failure")
        }
        val fixture = Fixture.make(refreshTokenStorage = failingStorage)
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(
                refreshToken = "refresh-v1",
            ),
        )

        assertThrows(RuntimeException::class.java) {
            runBlocking { fixture.client.checkOTP("123456") }
        }
        // Refresh token wasn't persisted (write threw).
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        // Critically, neither was the access token — the throw aborted
        // before storeAccessToken ran.
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    // MARK: - Interceptor wiring

    @Test
    fun startOTPLogin_isUnauthenticated_attachesNeitherDPoPNorBearer() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.startOTPLogin(StartOTPLoginOptions(identifier = emailIdentifier))

        val req = fixture.http.requestsFor("/v1/session/otp").single()
        // No DPoP proof — the device has no key bound to a session yet.
        assertNull(req.header(HttpHeader.DPOP))
        // No bearer — the user isn't logged in.
        assertNull(req.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    @Test
    fun retryOTP_isUnauthenticated_attachesNeitherDPoPNorBearer() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/retry",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.retryOTP()

        val req = fixture.http.requestsFor("/v1/session/otp/retry").single()
        assertNull(req.header(HttpHeader.DPOP))
        assertNull(req.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    @Test
    fun checkOTP_signsBothHopsWithDPoP_andAttachesNoBearer() = runBlocking {
        // Both `/otp/check` (proves the device's keypair to the
        // challenge issuer) and `/login/finalize` (proves it to the
        // token mint) must be DPoP-signed, but the auto-refresh
        // interceptor must not be on either chain — there's no bearer
        // to refresh until /login/finalize returns one.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to checkOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(),
        )

        fixture.client.checkOTP("123456")

        val checkReq = fixture.http.requestsFor("/v1/session/otp/check").single()
        assertNotNull(checkReq.header(HttpHeader.DPOP))
        assertNull(checkReq.header(HttpHeader.AUTHORIZATION))

        val finalizeReq = fixture.http.requestsFor("/v1/session/login/finalize").single()
        assertNotNull(finalizeReq.header(HttpHeader.DPOP))
        assertNull(finalizeReq.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    // MARK: - Helpers

    private fun okhttp3.Request.bodyAsString(): String {
        val buffer = Buffer()
        body?.writeTo(buffer)
        return buffer.readUtf8()
    }

    private fun okhttp3.Request.bodyAsJson() =
        Json.parseToJsonElement(bodyAsString()).jsonObject
}
