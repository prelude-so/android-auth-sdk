package so.prelude.android.session

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.store.AccessTokenEntry
import so.prelude.android.session.store.FailingRefreshTokenStorage
import so.prelude.android.session.store.InMemoryRefreshTokenStorage
import so.prelude.android.session.store.RefreshTokenRecord
import java.time.Instant

/**
 * Unit tests for the list/revoke sessions surface.
 *
 * Uses [runBlocking] (real dispatchers) for the same reason as the
 * other suites — the interceptor chain hops through
 * `Dispatchers.IO`-backed scopes and mixing virtual time with a real
 * dispatcher makes assertions about coroutine interleaving fragile.
 */
class SessionsTest {

    // Well-formed unsigned JWT carrying `sub = user-1`, `sid = sess-current`.
    // payload: {"sub":"user-1","sid":"sess-current"}
    private val jwtCurrent =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLWN1cnJlbnQifQ.sig"

    // No `sid` claim — used by the "revoke a specific id with no
    // cached sid" test to assert we DON'T wipe on a maybe-match.
    // payload: {"sub":"user-1"}
    private val jwtNoSid = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private val listResponseSingle = """
        {
          "sessions": [
            {
              "id": "sess-1",
              "device_model": "Pixel 8",
              "device_type": "mobile",
              "os_version": "Android 14",
              "country_code": "FR",
              "created_at": "2026-04-01T10:00:00Z",
              "last_seen_at": "2026-04-29T12:34:56Z",
              "expires_at": "2099-01-01T00:00:00Z"
            }
          ],
          "total": 1,
          "limit": 10,
          "offset": 0
        }
    """.trimIndent()

    /** Pre-populate the fixture's stores so authenticated requests have credentials. */
    private fun Fixture.preLogin(jwt: String = jwtCurrent, refreshToken: String = "refresh-v1") {
        keyStore.getOrCreate(domain) // ensures DPoP can sign
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
                accessToken = jwt,
                expiresAt = clock.epochSecond + 3_600,
            ),
        )
    }

    private fun Fixture.assertWiped(preEpoch: Long) {
        assertNull("DPoP key not wiped", keyStore.get(domain))
        assertNull("Refresh token not wiped", refreshTokenStore.get(domain))
        assertNull(
            "Access token cache not wiped",
            accessTokenCache.getWithoutExpirationCheck(domain),
        )
        // Pin the epoch bump directly (rather than relying on the
        // post-wipe refresh-401 test to catch a missing
        // `getAndIncrement()`): a refactor that drops the bump would
        // pass the store-wipe assertions but silently break the
        // snapshot guard in `doRefresh` / `finalizeLogin`.
        assertTrue(
            "sessionEpoch must be bumped after a calling-session-touching revoke",
            client.sessionEpoch.get() > preEpoch,
        )
    }

    private fun apiError(code: String, message: String = "", status: Int = 400) =
        StubHttpSession.Canned.json(
            """{"code":"$code","message":"$message"}""",
            statusCode = status,
        )

    // MARK: - listSessions

    @Test
    fun listSessions_happyPath_decodesEntries_andEchoesPagination() = runBlocking {
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(listResponseSingle),
        )

        val page = fixture.client.listSessions()

        assertEquals(1, page.total)
        assertEquals(10, page.limit)
        assertEquals(0, page.offset)
        val entry = page.sessions.single()
        assertEquals("sess-1", entry.id)
        assertEquals("Pixel 8", entry.deviceModel)
        assertEquals(PreludeSessionDeviceType.MOBILE, entry.deviceType)
        assertEquals("Android 14", entry.osVersion)
        assertEquals("FR", entry.countryCode)
        assertEquals(Instant.parse("2026-04-01T10:00:00Z"), entry.createdAt)
        assertEquals(Instant.parse("2026-04-29T12:34:56Z"), entry.lastSeenAt)
        assertEquals(Instant.parse("2099-01-01T00:00:00Z"), entry.expiresAt)
    }

    @Test
    fun listSessions_signedAuthenticated_GET_withDpop() = runBlocking {
        // Pins the protected-route shape: GET, DPoP-signed, no body.
        // Regression catches a future refactor that switches the
        // method or drops one of the interceptors.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(listResponseSingle),
        )

        fixture.client.listSessions()

        val req = fixture.http.requestsFor("/v1/session/me/list").single()
        assertEquals("GET", req.method)
        assertNotNull("list must carry a DPoP proof", req.header(HttpHeader.DPOP))
        // GET with no query params: builder emits a bodyless request.
        assertNull("GET must not carry a body", req.body)
        // Bearer is wired via `autoRefreshInterceptor`.
        assertEquals(
            "Bearer $jwtCurrent",
            req.header(HttpHeader.AUTHORIZATION),
        )
    }

    @Test
    fun listSessions_attachesPaginationQueryParams_whenProvided() = runBlocking {
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(listResponseSingle),
        )

        fixture.client.listSessions(PreludeListSessionsOptions(limit = 25, offset = 50))

        val req = fixture.http.requestsFor("/v1/session/me/list").single()
        assertEquals("25", req.url.queryParameter("limit"))
        assertEquals("50", req.url.queryParameter("offset"))
    }

    @Test
    fun listSessions_omitsQueryParams_whenNotProvided() = runBlocking {
        // Defaulting on the server (currently limit=10, offset=0)
        // means a server-side default change lands without a client
        // release. Pin that the SDK doesn't second-guess by sending
        // explicit zeros / tens.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(listResponseSingle),
        )

        fixture.client.listSessions()

        val req = fixture.http.requestsFor("/v1/session/me/list").single()
        assertNull(req.url.queryParameter("limit"))
        assertNull(req.url.queryParameter("offset"))
    }

    @Test
    fun preludeListSessionsOptions_rejectsNegativeLimitAndOffset() {
        // Fail-fast at the call site: a negative paging value is a
        // programmer error, so we throw before the request goes out.
        // Pin both fields independently so a future refactor that
        // forgets one is visible.
        assertThrows(IllegalArgumentException::class.java) {
            PreludeListSessionsOptions(limit = -1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PreludeListSessionsOptions(offset = -1)
        }
        // Zero is allowed (server treats it as "first page").
        PreludeListSessionsOptions(limit = 0, offset = 0)
        // Null defers to the server's defaults — also allowed.
        PreludeListSessionsOptions()
    }

    @Test
    fun listSessions_unknownDeviceType_foldsIntoUnknown() = runBlocking {
        // Server-side additions (a new device class) must not break
        // older SDKs — same forward-compat shape as
        // `PreludeStepUpStatus.fromWire` / wire enum decoders.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(
                """
                {
                  "sessions": [{
                    "id":"sess-1","device_model":"Foo","device_type":"smart-fridge",
                    "os_version":"v1","country_code":"FR",
                    "created_at":"2026-04-01T10:00:00Z",
                    "last_seen_at":"2026-04-01T10:00:00Z",
                    "expires_at":"2099-01-01T00:00:00Z"
                  }],
                  "total":1,"limit":10,"offset":0
                }
                """.trimIndent(),
            ),
        )

        val page = fixture.client.listSessions()

        assertEquals(PreludeSessionDeviceType.UNKNOWN, page.sessions.single().deviceType)
    }

    @Test
    fun listSessions_malformedTimestamp_surfacesAsDecodingFailed() {
        // A bad timestamp is more likely contract drift than one-off
        // corruption — fail the page so the regression is visible
        // rather than masked behind a partial render.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(
                """
                {
                  "sessions":[{
                    "id":"sess-1","device_model":"x","device_type":"mobile",
                    "os_version":"v","country_code":"FR",
                    "created_at":"not-a-date",
                    "last_seen_at":"2026-04-01T10:00:00Z",
                    "expires_at":"2099-01-01T00:00:00Z"
                  }],"total":1,"limit":10,"offset":0
                }
                """.trimIndent(),
            ),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { fixture.client.listSessions() }
        }
        assertEquals("decoding_failed", thrown.code)
        assertTrue(
            "should mention the offending field",
            thrown.displayMessage.contains("created_at"),
        )
    }

    @Test
    fun listSessions_missingOptionalFields_decodeAsEmptyStrings() = runBlocking {
        // Wire DTO defaults the soft fields so a server response
        // missing `device_model` etc. doesn't throw a structural
        // decode error — the page just renders with empty labels.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(
                """
                {
                  "sessions":[{
                    "id":"sess-1",
                    "created_at":"2026-04-01T10:00:00Z",
                    "last_seen_at":"2026-04-01T10:00:00Z",
                    "expires_at":"2099-01-01T00:00:00Z"
                  }],"total":1,"limit":10,"offset":0
                }
                """.trimIndent(),
            ),
        )

        val entry = fixture.client.listSessions().sessions.single()
        assertEquals("", entry.deviceModel)
        assertEquals("", entry.osVersion)
        assertEquals("", entry.countryCode)
        assertEquals(PreludeSessionDeviceType.UNKNOWN, entry.deviceType)
    }

    @Test
    fun listSessions_missingRequiredFields_surfaceAsDecodingFailed_notMissingFieldException() {
        // Loic's nit (PR #5754): every wire field defaults so a
        // server response missing `id` or any timestamp doesn't trip
        // a kotlinx.serialization.MissingFieldException. Empty
        // timestamps still fail `parseInstant` and surface as the
        // SDK's structured `decoding_failed` — same outcome as a
        // malformed timestamp, just routed through the public error
        // type instead of leaking a kotlinx exception. Pin so a
        // future refactor that drops the defaults is visible.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            StubHttpSession.Canned.json(
                """
                {
                  "sessions":[{}],
                  "total":1,"limit":10,"offset":0
                }
                """.trimIndent(),
            ),
        )

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { fixture.client.listSessions() }
        }
        assertEquals("decoding_failed", thrown.code)
        // The first parseInstant call (created_at) is the one that
        // trips on the empty default — message should name it so a
        // future regression is actionable.
        assertTrue(
            "should mention the offending field, got: ${thrown.displayMessage}",
            thrown.displayMessage.contains("created_at"),
        )
    }

    @Test
    fun listSessions_serverError_propagatesStructured() {
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/list",
            apiError("internal_server_error", "boom", status = 500),
        )

        val thrown = assertThrows(PreludeSessionError.InternalServerError::class.java) {
            runBlocking { fixture.client.listSessions() }
        }
        assertTrue(thrown.message!!.contains("boom"))
    }

    // MARK: - revokeSessions

    @Test
    fun revokeSessions_all_sendsTargetParam_andWipesLocalState() = runBlocking {
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        val preEpoch = fixture.client.sessionEpoch.get()
        fixture.client.revokeSessions(PreludeRevokeTarget.All)

        val req = fixture.http.requestsFor("/v1/session/me/revoke").single()
        assertEquals("POST", req.method)
        assertEquals("all", req.url.queryParameter("target"))
        assertNull(req.url.queryParameter("session_id"))
        assertNotNull("revoke must carry a DPoP proof", req.header(HttpHeader.DPOP))
        fixture.assertWiped(preEpoch)
    }

    @Test
    fun revokeSessions_mine_wipesLocalState() = runBlocking {
        // `mine` is logout-equivalent in effect: server kills the
        // calling session, so the local stores must follow.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        val preEpoch = fixture.client.sessionEpoch.get()
        fixture.client.revokeSessions(PreludeRevokeTarget.Mine)

        assertEquals(
            "mine",
            fixture.http.requestsFor("/v1/session/me/revoke").single().url
                .queryParameter("target"),
        )
        fixture.assertWiped(preEpoch)
    }

    @Test
    fun revokeSessions_others_doesNotWipeLocalState() = runBlocking {
        // `others` revokes every session except this one, so the
        // calling client must remain logged in. Asymmetric vs the
        // wipe in `all` / `mine`.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        fixture.client.revokeSessions(PreludeRevokeTarget.Others)

        // Stores intact.
        assertNotNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        assertNotNull(fixture.keyStore.get(fixture.domain))
    }

    @Test
    fun revokeSessions_session_matchingCurrentSid_wipesLocalState() = runBlocking {
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        val preEpoch = fixture.client.sessionEpoch.get()
        fixture.client.revokeSessions(PreludeRevokeTarget.Session("sess-current"))

        val req = fixture.http.requestsFor("/v1/session/me/revoke").single()
        assertEquals("session", req.url.queryParameter("target"))
        assertEquals("sess-current", req.url.queryParameter("session_id"))
        fixture.assertWiped(preEpoch)
    }

    @Test
    fun revokeSessions_session_otherId_doesNotWipeLocalState() = runBlocking {
        // Revoking a sibling device's session leaves THIS client
        // untouched.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        fixture.client.revokeSessions(PreludeRevokeTarget.Session("sess-sibling"))

        assertEquals(
            "sess-sibling",
            fixture.http.requestsFor("/v1/session/me/revoke").single().url
                .queryParameter("session_id"),
        )
        // Stores intact.
        assertNotNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        assertNotNull(fixture.keyStore.get(fixture.domain))
    }

    @Test
    fun revokeSessions_session_noCachedSid_doesNotWipe() = runBlocking {
        // Without a cached `sid` we don't know if the revoked id is
        // ours — defaulting to "not us" is safer than wiping on a
        // maybe-match.
        val fixture = Fixture.make()
        fixture.preLogin(jwt = jwtNoSid)
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        fixture.client.revokeSessions(PreludeRevokeTarget.Session("sess-anything"))

        assertNotNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        assertNotNull(fixture.keyStore.get(fixture.domain))
    }

    @Test
    fun revokeSessions_serverFailure_doesNotWipeLocalState() = runBlocking {
        // Wipe runs only on success — a transport failure must leave
        // the client able to retry without re-logging in. Distinct
        // from `logout` (wipe-first), see the file header.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            apiError("internal_server_error", "boom", status = 500),
        )

        assertThrows(PreludeSessionError.InternalServerError::class.java) {
            runBlocking { fixture.client.revokeSessions(PreludeRevokeTarget.All) }
        }

        // Stores intact — the user can retry.
        assertNotNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNotNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        assertNotNull(fixture.keyStore.get(fixture.domain))
    }

    @Test
    fun revokeSessions_postWipe_refreshSurfacesUnauthorized() = runBlocking {
        // After a wipe-causing revoke the user is effectively logged
        // out: a follow-up refresh finds empty stores, sends `/refresh`
        // without a refresh-token header, and the server rejects with
        // 401. Pins that the wipe is durable across the inflight slot
        // (would-be resurrection point) and the cache fast path.
        val fixture = Fixture.make()
        fixture.preLogin()
        // Expired cache token so refresh enters its network path
        // instead of fast-pathing on the cache.
        fixture.accessTokenCache.set(
            domain = fixture.domain,
            entry = AccessTokenEntry(
                accessToken = jwtCurrent,
                expiresAt = fixture.clock.epochSecond - 60,
            ),
        )
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )
        fixture.http.install(
            "/v1/session/refresh",
            apiError("unauthorized", "no refresh token", status = 401),
        )

        val preEpoch = fixture.client.sessionEpoch.get()
        fixture.client.revokeSessions(PreludeRevokeTarget.All)
        // Snapshot the wiped state BEFORE calling refresh — the DPoP
        // interceptor lazily mints a fresh keypair on the next signed
        // request, so a post-refresh assertion would see the new key
        // and miss the regression we care about (the revoke wipe
        // itself).
        fixture.assertWiped(preEpoch)

        val caught = runCatching { fixture.client.refresh() }.exceptionOrNull()
        assertTrue(
            "expected Unauthorized, got $caught",
            caught is PreludeSessionError.Unauthorized,
        )
    }

    @Test
    fun revokeSessions_sessionId_isProperlyEncoded_inQueryString() = runBlocking {
        // OkHttp's `addQueryParameter` percent-encodes per RFC 3986.
        // Pin the contract so a future refactor that hand-builds the
        // query string can't regress to manual concatenation that
        // would mis-encode reserved characters.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        fixture.client.revokeSessions(PreludeRevokeTarget.Session("a b&c=d"))

        val req = fixture.http.requestsFor("/v1/session/me/revoke").single()
        // OkHttp decodes back to the original string for the
        // `queryParameter` accessor — this proves the encode/decode
        // round-trip preserved the literal value.
        assertEquals("a b&c=d", req.url.queryParameter("session_id"))
    }

    // MARK: - Concurrency

    @Test
    fun revokeSessions_drainsInflightRefresh_beforeWiping() = runBlocking {
        // Pin the drain in `revokeSessions` for a calling-session-
        // touching target: a `/refresh` mid-rotation must complete (or
        // fail) before we wipe, otherwise rotated tokens land back in
        // stores we just emptied. The same invariant the
        // `refreshSurfacesUnauthorized` test covers transitively — pin
        // it directly so a refactor that elides `joinIfRunning` is
        // visible without relying on the post-wipe refresh path.
        val fixture = Fixture.make()
        fixture.preLogin()
        // Expired access token → `client.refresh()` enters the network
        // path instead of fast-pathing on the cache.
        fixture.accessTokenCache.set(
            domain = fixture.domain,
            entry = AccessTokenEntry(
                accessToken = jwtCurrent,
                expiresAt = fixture.clock.epochSecond - 60,
            ),
        )
        val refreshExpiresAt = fixture.clock.epochSecond + 3_600
        fixture.http.install(
            "/v1/session/refresh",
            StubHttpSession.Canned.json(
                "{\"access_token\":\"" + jwtCurrent + "\",\"expires_at\":" + refreshExpiresAt + "}",
                headers = mapOf(
                    HttpHeader.REFRESH_TOKEN to "refresh-v2",
                    HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
                ),
            ),
        )
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )
        // Gate `/refresh` so we can guarantee it's in flight when
        // revoke enters its drain.
        fixture.http.installGate("/v1/session/refresh")

        coroutineScope {
            val refresh = async { fixture.client.refresh() }
            // Wait for refresh to file the request and suspend at the
            // gate — at this point `inflightRefresh` is populated.
            waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }

            // Revoke runs concurrently. The mutex around `revokeSessions`
            // serialises against other revokes, not against refresh,
            // so this enters its drain path regardless.
            val revoke = async { fixture.client.revokeSessions(PreludeRevokeTarget.All) }
            // Give revoke a tick to complete `/me/revoke` and reach
            // `inflightRefresh.joinIfRunning()`.
            delay(50)
            // Stores must still be populated — the drain is holding
            // back the wipe.
            assertNotNull(
                "wipe must not run before the in-flight refresh drains",
                fixture.refreshTokenStore.get(fixture.domain),
            )

            fixture.http.releaseGate("/v1/session/refresh")
            refresh.await()
            revoke.await()
        }

        // After both settle, the wipe ran exactly once.
        assertNull(fixture.refreshTokenStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        assertNull(fixture.keyStore.get(fixture.domain))
    }

    @Test
    fun revokeSessions_concurrentCallers_serialise_onRevokeMutex() = runBlocking {
        // Concurrent callers must serialise on `revokeMutex` — without
        // it, both fire `/me/revoke` concurrently and race
        // `clearAllStores()` / double-bump the epoch. The mid-flight
        // assertion below is what distinguishes serialisation from
        // racing: at gate-time we should see exactly ONE request, not
        // two.
        val fixture = Fixture.make()
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )
        // Gate `/me/revoke`. With the mutex, only the first caller
        // reaches the stub; the second is blocked on `withLock` and
        // never builds a request.
        fixture.http.installGate("/v1/session/me/revoke")

        val outcomes = coroutineScope {
            val tasks = (0 until 2).map {
                async { runCatching { fixture.client.revokeSessions(PreludeRevokeTarget.All) } }
            }
            // Wait for the first caller's request to reach the stub.
            waitUntil { fixture.http.requestCount("/v1/session/me/revoke") >= 1 }
            // Give a racy second caller a chance to also reach the
            // stub if no mutex were in place. With the mutex, this
            // delay is wasted — the second is queued on `withLock`.
            delay(50)
            assertEquals(
                "with the mutex the second caller must wait — only one request " +
                    "reaches the stub while the first is in flight",
                1,
                fixture.http.requestCount("/v1/session/me/revoke"),
            )
            fixture.http.releaseGate("/v1/session/me/revoke")
            tasks.awaitAll()
        }

        // After release, the second caller acquires the mutex and
        // fires its own request — total count is 2, proving
        // serialisation (not coalescing).
        assertEquals(
            "second caller must fire its own request once it acquires the mutex",
            2,
            fixture.http.requestCount("/v1/session/me/revoke"),
        )
        // Both callers succeed: the stub is path-keyed and idempotent,
        // and the second caller's wipe-and-bump is a no-op against the
        // already-empty stores. The point of the mutex isn't to fail
        // the second caller; it's to prevent the racy double-wipe.
        val (first, second) = outcomes
        assertTrue("first caller should succeed", first.isSuccess)
        assertTrue(
            "second caller should succeed, got " + second.exceptionOrNull(),
            second.isSuccess,
        )
    }

    @Test
    fun revokeSessions_partialWipeFailure_stillBumpsEpoch_thenSurfacesError() {
        // The bump must run even when `clearAllStores` throws —
        // otherwise a concurrent `doRefresh` whose snapshot matches
        // the unbumped epoch passes its post-network guard and writes
        // rotated tokens back into the (partially) emptied stores.
        // Same precedence shape as `logout`: capture wipe error,
        // bump, re-throw.
        val failing = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage()).apply {
            deleteFailure = RuntimeException("simulated delete failure")
        }
        val fixture = Fixture.make(refreshTokenStorage = failing)
        fixture.preLogin()
        fixture.http.install(
            "/v1/session/me/revoke",
            StubHttpSession.Canned(statusCode = 204),
        )

        val preEpoch = fixture.client.sessionEpoch.get()

        val thrown = assertThrows(RuntimeException::class.java) {
            runBlocking { fixture.client.revokeSessions(PreludeRevokeTarget.All) }
        }
        assertEquals("simulated delete failure", thrown.message)

        // Epoch was bumped despite the wipe error — pins the
        // invariant a refactor could silently break.
        assertTrue(
            "sessionEpoch must be bumped even when clearAllStores throws",
            fixture.client.sessionEpoch.get() > preEpoch,
        )
        // The other deletes still ran (`clearAllStores` is best-
        // effort); only the refresh-token delete faulted.
        assertNull(fixture.keyStore.get(fixture.domain))
        assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
    }

    /**
     * Spin until [predicate] returns true or [timeoutMs] elapses. Same
     * shape as `LogoutTests.waitUntil` — used to rendezvous on
     * observable markers (recorded-request counts) instead of fixed
     * sleeps.
     */
    private suspend fun waitUntil(timeoutMs: Long = 2_000, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            delay(5)
        }
        throw AssertionError("timed out waiting for condition (after " + timeoutMs + "ms)")
    }

}
