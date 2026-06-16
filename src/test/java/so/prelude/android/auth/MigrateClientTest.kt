package so.prelude.android.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.crypto.Pkce
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.AccessTokenEntry

/**
 * Unit tests for the migration surface (`migrate`): cache
 * short-circuit, PKCE binding between `/migration` and
 * `/login/finalize`, single-flight coalescing of concurrent callers,
 * and structured errors.
 *
 * Uses [runBlocking] (not `runTest`): the client runs on real
 * dispatchers, and mixing virtual time with them makes assertions
 * about suspension state fragile.
 */
class MigrateClientTest {
    // Well-formed unsigned JWT: payload `{"sub":"user-1"}`. The
    // decoder reads only the payload.
    private val jwt = OtpFixtures.JWT

    private val migrationPath = "/v1/session/migration"
    private val finalizePath = "/v1/session/login/finalize"

    private fun migrationOkResponse(challenge: String = "challenge-abc") =
        StubHttpSession.Canned.json("""{"challenge_token":"$challenge"}""")

    // MARK: - Happy path

    @Test
    fun migrate_happyPath_returnsUser_persistsRefresh_andCachesAccessToken() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to
                    OtpFixtures.finalizeOkResponse(
                        refreshToken = "refresh-v1",
                        refreshExpiresAt = "2099-01-01T00:00:00Z",
                    ),
            )

            val user = fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

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

    // MARK: - PKCE binding

    @Test
    fun migrate_sendsPkceChallenge_andMatchingVerifierOnFinalize() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            val migrationBody =
                fixture.http
                    .requestsFor(migrationPath)
                    .single()
                    .bodyAsJson()
            val finalizeBody =
                fixture.http
                    .requestsFor(finalizePath)
                    .single()
                    .bodyAsJson()

            assertEquals("legacy-bearer", migrationBody["token"]!!.jsonPrimitive.content)
            assertEquals("challenge-abc", finalizeBody["challenge_token"]!!.jsonPrimitive.content)

            val challenge = migrationBody["code_challenge"]!!.jsonPrimitive.content
            val verifier = finalizeBody["code_verifier"]!!.jsonPrimitive.content
            assertEquals(
                "code_challenge must be the S256 transform of code_verifier",
                challenge,
                Pkce.codeChallenge(verifier),
            )
        }

    @Test
    fun migrate_generatesFreshVerifierPerMigration() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))
            // Wipe the session so the second migrate round-trips.
            fixture.accessTokenCache.clear(fixture.domain)
            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            val challenges =
                fixture.http
                    .requestsFor(migrationPath)
                    .map { it.bodyAsJson()["code_challenge"]!!.jsonPrimitive.content }
            assertEquals(2, challenges.size)
            assertNotEquals(
                "each migration must bind a fresh PKCE challenge",
                challenges[0],
                challenges[1],
            )
        }

    // MARK: - Cache short-circuit

    @Test
    fun migrate_shortCircuits_whenSessionAlreadyCached() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.accessTokenCache.set(
                domain = fixture.domain,
                entry = AccessTokenEntry(accessToken = jwt, expiresAt = 1_700_000_000L + 3600),
            )

            val user = fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            assertEquals("user-1", user.profile.userId)
            assertEquals(0, fixture.http.requestCount(migrationPath))
        }

    @Test
    fun migrate_secondCallAfterSuccess_shortCircuits() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))
            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            assertEquals(1, fixture.http.requestCount(migrationPath))
            assertEquals(1, fixture.http.requestCount(finalizePath))
        }

    @Test
    fun migrate_expiredCachedToken_runsMigration() =
        runBlocking {
            val fixture = Fixture.make()
            // Expired entry: the fast path must not treat it as a session.
            fixture.accessTokenCache.set(
                domain = fixture.domain,
                entry = AccessTokenEntry(accessToken = jwt, expiresAt = 1_700_000_000L - 10),
            )
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            assertEquals(1, fixture.http.requestCount(migrationPath))
        }

    // MARK: - Error mapping

    @Test
    fun migrate_missingChallengeToken_throwsStructured() {
        val fixture = Fixture.make()
        fixture.http.install(migrationPath, StubHttpSession.Canned.json("{}"))

        assertThrows(PreludeAuthError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) }
        }
    }

    @Test
    fun migrate_serverRejectsLegacyToken_mapsToBadRequest() {
        val fixture = Fixture.make()
        // The server returns 400 `bad_request` when the legacy token
        // is rejected or migration isn't configured.
        fixture.http.install(migrationPath, OtpFixtures.apiError(code = "bad_request"))

        assertThrows(PreludeAuthError.BadRequest::class.java) {
            runBlocking { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) }
        }
    }

    @Test
    fun migrate_failure_doesNotLatch_nextCallRetries() {
        val fixture = Fixture.make()
        fixture.http.install(migrationPath, OtpFixtures.apiError(code = "internal", status = 500))

        assertThrows(PreludeAuthError.InternalServerError::class.java) {
            runBlocking { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) }
        }

        // The slot must not latch the failure: a retry round-trips.
        fixture.http.installAll(
            migrationPath to migrationOkResponse(),
            finalizePath to OtpFixtures.finalizeOkResponse(),
        )
        val user = runBlocking { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) }
        assertEquals("user-1", user.profile.userId)
        assertEquals(2, fixture.http.requestCount(migrationPath))
    }

    // MARK: - Auth headers

    @Test
    fun migrate_migrationHopIsUnauthenticated_finalizeIsDPoPSigned() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            val migrationReq = fixture.http.requestsFor(migrationPath).single()
            assertNull(migrationReq.header(HttpHeader.DPOP))
            assertNull(migrationReq.header(HttpHeader.AUTHORIZATION))

            val finalizeReq = fixture.http.requestsFor(finalizePath).single()
            assertNotNull(
                "finalize binds the issued tokens to the device key",
                finalizeReq.header(HttpHeader.DPOP),
            )
            assertNull(finalizeReq.header(HttpHeader.AUTHORIZATION))
            Unit
        }

    // MARK: - Signals

    @Test
    fun migrate_attachesDispatchId_whenDispatcherConfigured() =
        runBlocking {
            val fixture = Fixture.make(signalsDispatcher = { "dispatch-123" })
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            val body =
                fixture.http
                    .requestsFor(migrationPath)
                    .single()
                    .bodyAsJson()
            assertEquals("dispatch-123", body["dispatch_id"]!!.jsonPrimitive.content)
        }

    @Test
    fun migrate_dispatcherThrows_proceedsWithoutDispatchId() =
        runBlocking {
            val fixture = Fixture.make(signalsDispatcher = { error("boom") })
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            // Must not throw — signals failures degrade gracefully.
            fixture.client.migrate(MigrateOptions(token = "legacy-bearer"))

            val body =
                fixture.http
                    .requestsFor(migrationPath)
                    .single()
                    .bodyAsJson()
            assertFalse(
                "dispatch_id must be omitted when the dispatcher fails",
                body.containsKey("dispatch_id"),
            )
        }

    // MARK: - Concurrency

    @Test
    fun migrate_concurrentCallers_shareSingleMigration() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )
            fixture.http.installGate(migrationPath)

            val first = async { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) }
            val second = async { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) }

            StepUpFixtures.waitUntil { fixture.http.requestCount(migrationPath) >= 1 }
            fixture.http.releaseGate(migrationPath)

            val users = listOf(first.await(), second.await())
            assertEquals(users[0].accessToken, users[1].accessToken)
            // One exchange total: the legacy token is spent once and the
            // single-use challenge is redeemed once.
            assertEquals(1, fixture.http.requestCount(migrationPath))
            assertEquals(1, fixture.http.requestCount(finalizePath))
        }

    // MARK: - Logout race

    @Test
    fun migrate_logoutDuringExchange_abortsAndDoesNotResurrectSession() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                migrationPath to migrationOkResponse(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )
            fixture.http.installGate(migrationPath)

            // `runCatching` inside the child: a bare failing `async`
            // would cancel the enclosing runBlocking scope before the
            // assertions run.
            val migration =
                async { runCatching { fixture.client.migrate(MigrateOptions(token = "legacy-bearer")) } }
            StepUpFixtures.waitUntil { fixture.http.requestCount(migrationPath) >= 1 }

            // Logout runs to completion while the exchange is parked
            // between its two hops — after the epoch capture, before
            // finalize. The threaded epoch must abort persistence.
            fixture.client.logout()
            fixture.http.releaseGate(migrationPath)

            val result = migration.await()
            assertTrue(
                "expected Unauthorized, got $result",
                result.exceptionOrNull() is PreludeAuthError.Unauthorized,
            )
            assertNull(fixture.refreshTokenStore.get(fixture.domain))
            assertNull(fixture.accessTokenCache.get(fixture.domain))
        }

    // MARK: - Logging hygiene

    @Test
    fun migrateOptions_toString_redactsTheToken() {
        val rendered = MigrateOptions(token = "legacy-secret").toString()
        assertFalse("toString must not contain the legacy token", rendered.contains("legacy-secret"))
        assertTrue(rendered.contains("redacted"))
    }
}
