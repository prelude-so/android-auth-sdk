package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okio.Buffer
import so.prelude.android.session.http.LoginWithPasswordRequestBody
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
 * Unit tests for the password login surface (`loginWithPassword`)
 * and the shared `finalizeLogin` helper it delegates to.
 *
 * Each test spins up a [Fixture],
 * installs canned HTTP responses keyed by path, exercises the public
 * client API, and asserts on side-effects (cache, refresh-token
 * store, recorded request shapes).
 *
 * Uses [runBlocking] (not [kotlinx.coroutines.test.runTest]) for the
 * same reason as the OTP suite — the interceptor chain hops through
 * `withContext(Dispatchers.IO)` and mixing virtual time with a real
 * dispatcher makes assertions about suspending state-mutations
 * fragile. Same reasoning as [InflightTest].
 */
class PasswordClientTest {

    // A well-formed unsigned JWT. The decoder reads only the payload,
    // so this is enough to round-trip a `userId = user-1` profile.
    // payload: {"sub":"user-1"} → eyJzdWIiOiJ1c2VyLTEifQ
    private val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private val email = "alice@example.com"
    private val password = "correct horse battery staple"

    private fun loginOkResponse(challenge: String = "challenge-abc") =
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

    // MARK: - Happy path

    @Test
    fun loginWithPassword_happyPath_returnsUser_persistsRefresh_andCachesAccessToken() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(
                refreshToken = "refresh-v1",
                refreshExpiresAt = "2099-01-01T00:00:00Z",
            ),
        )

        val user = fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )

        assertEquals(jwt, user.accessToken)
        assertEquals("user-1", user.profile.userId)

        val record = fixture.refreshTokenStore.get(fixture.domain)
        assertNotNull(record)
        assertEquals("refresh-v1", record!!.refreshToken)
        assertEquals("2099-01-01T00:00:00Z", record.refreshTokenExpiresAt)

        val cached = fixture.accessTokenCache.get(fixture.domain)
        assertNotNull(cached)
        assertEquals(jwt, cached!!.accessToken)
        Unit
    }

    @Test
    fun loginWithPassword_postsCredentials_andOmitsDispatchIdWhenUnconfigured() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(),
        )

        fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )

        val req = fixture.http.requestsFor("/v1/session/login/email/password").single()
        val body = req.bodyAsJson()
        assertEquals(email, body["identifier"]!!.jsonPrimitive.content)
        assertEquals(password, body["password"]!!.jsonPrimitive.content)
        // No dispatcher configured → `dispatch_id` is omitted entirely
        // (encoder skips defaults), not sent as null.
        assertFalse("dispatch_id should be omitted", body.containsKey("dispatch_id"))
        Unit
    }

    @Test
    fun loginWithPassword_attachesDispatchId_whenSignalsDispatcherIsConfigured() = runBlocking {
        var dispatched = 0
        val fixture = Fixture.make(
            signalsDispatcher = {
                dispatched += 1
                "dispatch-xyz"
            },
        )
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(),
        )

        fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )

        assertEquals(1, dispatched)
        val body = fixture.http.requestsFor("/v1/session/login/email/password")
            .single().bodyAsJson()
        assertEquals("dispatch-xyz", body["dispatch_id"]!!.jsonPrimitive.content)
        Unit
    }

    @Test
    fun loginWithPassword_dispatcherReturningNull_omitsDispatchId() = runBlocking {
        // A configured dispatcher returning `null` (a documented
        // "skip this pass" no-op) must produce the same wire payload
        // as no dispatcher at all — `dispatch_id` omitted, not sent
        // as JSON null. Distinct from `_omitsDispatchIdWhenUnconfigured`
        // because the dispatcher is invoked here.
        var dispatched = 0
        val fixture = Fixture.make(
            signalsDispatcher = {
                dispatched += 1
                null
            },
        )
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(),
        )

        fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )

        assertEquals(1, dispatched)
        val body = fixture.http.requestsFor("/v1/session/login/email/password")
            .single().bodyAsJson()
        assertFalse(
            "dispatch_id should be omitted when the dispatcher returns null",
            body.containsKey("dispatch_id"),
        )
        Unit
    }

    @Test
    fun loginWithPassword_dispatcherFailure_wrapsAsSignalsDispatchFailed_andSkipsHttp() {
        val fixture = Fixture.make(
            signalsDispatcher = { error("boom") },
        )
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(),
        )

        val thrown = assertThrows(PreludeSessionError.SignalsDispatchFailed::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
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
        // Both endpoints must remain unhit — silently shipping a login
        // without anti-fraud coverage is the worst possible failure.
        assertTrue(
            fixture.http.requestsFor("/v1/session/login/email/password").isEmpty(),
        )
        assertTrue(
            fixture.http.requestsFor("/v1/session/login/finalize").isEmpty(),
        )
    }

    // MARK: - Error mapping

    @Test
    fun loginWithPassword_invalidEmailShape_mapsBadRequest() {
        // The KDoc on `loginWithPassword` enumerates `BadRequest` for
        // an invalid email shape — the server emits `bad_request`,
        // which `PreludeSessionError.from` maps to `BadRequest`. Pin it
        // so the doc claim doesn't drift from the mapping table.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/login/email/password",
            apiError("bad_request", "invalid email", status = 400),
        )

        assertThrows(PreludeSessionError.BadRequest::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = "not-an-email", password = password),
                )
            }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun loginWithPassword_invalidPassword_mapsStructured() {
        // Password didn't meet the policy (too short, no symbols, etc.).
        // Distinct from `unauthorized` — fix is to retry with a stronger
        // password, not a different one.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/login/email/password",
            apiError("invalid_password", "policy", status = 400),
        )

        assertThrows(PreludeSessionError.InvalidPassword::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = "x"),
                )
            }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun loginWithPassword_badCredentials_mapsUnauthorized() {
        // Wrong password for an existing identifier. Retry with the
        // correct one (or fall back to OTP / reset).
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/login/email/password",
            apiError("unauthorized", "bad credentials", status = 401),
        )

        assertThrows(PreludeSessionError.Unauthorized::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = "wrong"),
                )
            }
        }
    }

    @Test
    fun loginWithPassword_rateLimited_mapsToStructuredError() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/login/email/password",
            apiError("rate_limited", "slow down", status = 429),
        )

        assertThrows(PreludeSessionError.RateLimited::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
                )
            }
        }
    }

    @Test
    fun loginWithPassword_missingChallengeToken_throwsStructured() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/login/email/password",
            StubHttpSession.Canned.json("{}"),
        )

        assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
                )
            }
        }
        // Finalize must not be called — there's nothing to exchange.
        assertTrue(fixture.http.requestsFor("/v1/session/login/finalize").isEmpty())
        // No tokens persisted on the failure path.
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun loginWithPassword_emptyChallengeToken_throwsStructured() {
        // Server contract says the field is non-empty when present;
        // empty string is treated identically to a missing field so a
        // backend regression surfaces the same way regardless of which
        // shape it took. Same behaviour as the OTP path.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/login/email/password",
            StubHttpSession.Canned.json("""{"challenge_token":""}"""),
        )

        assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
                )
            }
        }
    }

    @Test
    fun loginWithPassword_finalizeReturnsEmptyAccessToken_throwsGeneric() {
        // A 200 from /login/finalize with an empty access token is a
        // backend regression; surface as `Generic("missing_access_token")`
        // so the auto-refresh interceptor (which isn't on this chain)
        // can't paper over the failure.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to StubHttpSession.Canned.json(
                """{"access_token":"","expires_at":1700003600}""",
            ),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
                )
            }
        }
        assertEquals("missing_access_token", thrown.code)
    }

    @Test
    fun loginWithPassword_invalidChallengeToken_doesNotPersist() {
        // Race window: the challenge token /login/email/password just
        // minted expires (or the server rotates its signing key) before
        // /login/finalize sees it. The request body is well-formed —
        // failure surfaces as `invalid_challenge_token`.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to apiError(
                "invalid_challenge_token",
                "expired",
                status = 400,
            ),
        )

        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
                )
            }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    @Test
    fun loginWithPassword_finalizeWithoutRefreshHeader_doesNotPersistRefreshToken() = runBlocking {
        // Server omitting `X-Refresh-Token` is a backend regression we
        // shouldn't crash on; the access token still lands in the cache
        // so the user is functionally logged in until the next refresh.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(refreshToken = null),
        )

        val user = fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )
        assertEquals(jwt, user.accessToken)
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.get(fixture.domain))
        Unit
    }

    // MARK: - Persistence ordering invariant

    @Test
    fun loginWithPassword_refreshStoreWriteFails_doesNotPersistAccessToken() {
        // The refresh-before-access ordering invariant: a write failure
        // on the refresh-token store must abort *before* the access
        // token lands in the cache. Otherwise the next 401 would have
        // a fresh access token paired with a stale (or missing) refresh
        // token, with nothing to recover. Same invariant as the OTP and
        // refresh paths.
        val failingStorage = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage()).apply {
            writeFailure = RuntimeException("simulated disk failure")
        }
        val fixture = Fixture.make(refreshTokenStorage = failingStorage)
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(refreshToken = "refresh-v1"),
        )

        assertThrows(RuntimeException::class.java) {
            runBlocking {
                fixture.client.loginWithPassword(
                    LoginWithPasswordOptions(identifier = email, password = password),
                )
            }
        }
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    // MARK: - Interceptor wiring

    @Test
    fun loginWithPassword_firstHopIsUnauthenticated_finalizeIsDPoPSigned() = runBlocking {
        // `/login/email/password` is the chicken-and-egg endpoint: the
        // device has no keypair bound to a session yet, so it must run
        // unauthenticated (no DPoP, no bearer). `/login/finalize` then
        // mints the access + refresh token DPoP-bound to this device's
        // keypair. The auto-refresh interceptor isn't on either chain
        // — there's no bearer to refresh until /login/finalize returns
        // one.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to finalizeOkResponse(),
        )

        fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )

        val loginReq = fixture.http
            .requestsFor("/v1/session/login/email/password").single()
        assertNull("password endpoint must not carry DPoP", loginReq.header(HttpHeader.DPOP))
        assertNull(
            "password endpoint must not carry a bearer",
            loginReq.header(HttpHeader.AUTHORIZATION),
        )

        val finalizeReq = fixture.http.requestsFor("/v1/session/login/finalize").single()
        assertNotNull(
            "finalize must be DPoP-signed",
            finalizeReq.header(HttpHeader.DPOP),
        )
        assertNull(finalizeReq.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    @Test
    fun loginWithPassword_finalizeAccessExpiry_isClockSkewAdjusted() = runBlocking {
        // Drift the server's `Date` 60s behind the fixture's local
        // clock. The HttpClient's `timeDiffSec` should pick up
        // local - server = +60s, and `storeAccessToken` should add it
        // to the server-supplied `expires_at` so the cache compares
        // correctly against the local clock. Same reasoning as the OTP path's
        // skew test so a regression in `finalizeLogin` shows up on
        // both surfaces.
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/login/email/password" to loginOkResponse(),
            "/v1/session/login/finalize" to StubHttpSession.Canned.json(
                """{"access_token":"$jwt","expires_at":1700003600}""",
                headers = mapOf(
                    HttpHeader.REFRESH_TOKEN to "refresh-v1",
                    // Any `Date` 60s before the fixture clock.
                    "Date" to "Tue, 14 Nov 2023 22:12:20 GMT",
                ),
            ),
        )

        fixture.client.loginWithPassword(
            LoginWithPasswordOptions(identifier = email, password = password),
        )

        // Server expiry: 1_700_003_600. Skew: +60. Cached: 1_700_003_660.
        val expiresAt = fixture.client.getAccessTokenExpiresAt()
        assertNotNull(expiresAt)
        assertEquals(1_700_003_660L, expiresAt!!.epochSecond)
        Unit
    }

    // MARK: - Redaction surface

    @Test
    fun loginWithPasswordOptions_toString_redactsThePassword() {
        // Belt-and-braces: a stray `Log.d` / coroutine error path must
        // not leak the plaintext via the options' `toString`. The
        // `RedactedString` wrapper renders `<redacted>`, and the
        // `LoginWithPasswordOptions` `toString` matches that. Caller
        // can still get the value back through `password.value`.
        val opts = LoginWithPasswordOptions(
            identifier = email,
            password = "super-secret",
        )
        val rendered = opts.toString()
        assertFalse("toString must not contain plaintext", rendered.contains("super-secret"))
        assertTrue("toString must mark the redacted slot", rendered.contains("<redacted>"))
        // The unwrap is still available to the call site.
        assertEquals("super-secret", opts.password.value)
    }

    @Test
    fun redactedString_toString_rendersRedacted() {
        val s = RedactedString("hunter2")
        assertEquals("<redacted>", s.toString())
        assertEquals("hunter2", s.value)
    }

    @Test
    fun loginWithPasswordRequestBody_toString_redactsThePassword() {
        // The wire DTO carries the plaintext (the server has to verify
        // it) but its `toString` must not leak — a stray `Log.d` of
        // the request struct or a coroutine error path that dumps it
        // would otherwise surface the plaintext in any logging
        // pipeline tailing the SDK.
        val body = LoginWithPasswordRequestBody(
            identifier = email,
            password = "super-secret",
        )
        val rendered = body.toString()
        assertFalse("toString must not leak plaintext", rendered.contains("super-secret"))
        assertTrue("toString must mark the redacted slot", rendered.contains("<redacted>"))
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
