package so.prelude.android.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.store.AccessTokenEntry

/**
 * Step-up concurrency: drains a vanilla `refresh()` racing the
 * post-completion scoped refresh, and the logout-during-`/otp/check`
 * race that must surface Unauthorized rather than resurrect.
 */
class StepUpConcurrencyTest {
    @Test
    fun submitStepUpOTP_completion_drainsInflightRefresh_thenInstallsScopedRefresh() =
        runBlocking {
            // A vanilla `refresh()` racing in the inflight slot would
            // mint an UNSCOPED access token; the post-completion refresh
            // must drain it first, then install a scoped refresh that
            // any concurrent caller piggybacks on. End-to-end check that
            // [Inflight.replace] is wired through correctly.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp(refreshToken = "refresh-v1")
            // Force an expired access token so refresh() actually hits the
            // network rather than short-circuiting on the cache.
            fixture.accessTokenCache.set(
                domain = fixture.domain,
                entry =
                    AccessTokenEntry(
                        accessToken = StepUpFixtures.SCOPED_ACCESS_TOKEN,
                        expiresAt = fixture.clock.epochSecond - 60,
                    ),
            )
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp/check" to
                    StubHttpSession.Canned.json(
                        """{"challenge_token":"${StepUpFixtures.completedToken}"}""",
                    ),
                "/v1/session/refresh" to StepUpFixtures.refreshOk(refreshToken = "refresh-v2"),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
            // Gate /refresh so the vanilla refresh suspends in the slot
            // while submitStepUpOTP races to drain it.
            fixture.http.installGate("/v1/session/refresh")

            coroutineScope {
                val vanilla = async { fixture.client.refresh() }
                // Wait until the vanilla refresh is in flight at the gate.
                // Any later submitStepUpOTP completion will observe a
                // non-null inflight slot and have to drain.
                StepUpFixtures.waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }

                val submit =
                    async {
                        fixture.client.submitStepUpOTP(challenge, code = "123456")
                    }

                // Release; vanilla refresh completes (refresh-v1 →
                // refresh-v2), drain returns, post-completion refresh
                // runs (refresh-v2 → refresh-v3). Install a second canned
                // response so the second /refresh succeeds.
                fixture.http.install(
                    "/v1/session/refresh",
                    StepUpFixtures.refreshOk(refreshToken = "refresh-v3"),
                )
                fixture.http.releaseGate("/v1/session/refresh")
                vanilla.await()
                submit.await()
            }

            // Two `/refresh` round-trips: one vanilla, one scoped.
            assertEquals(2, fixture.http.requestCount("/v1/session/refresh"))
            // Scoped refresh shipped step_up_token; vanilla didn't.
            val refreshBodies =
                fixture.http
                    .requestsFor("/v1/session/refresh")
                    .map { it.bodyAsJson() }
            assertEquals(
                "exactly one /refresh must carry step_up_token",
                1,
                refreshBodies.count { it.containsKey("step_up_token") },
            )
            // Final stored refresh token reflects the LAST rotation — scoped.
            assertEquals(
                "refresh-v3",
                fixture.refreshTokenStore.get(fixture.domain)?.refreshToken,
            )
        }

    @Test
    fun logoutDuringSubmitCompletion_surfacesUnauthorizedFromRefresh() =
        runBlocking {
            // A logout that lands while `/otp/check` is in flight has
            // already revoked the session by the time the post-completion
            // refresh runs. The refresh's epoch guard catches the bumped
            // counter (or the empty refresh-token store maps to 401) and
            // surfaces Unauthorized — not a successful resurrection.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp(refreshToken = "refresh-v1")
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp/check" to
                    StubHttpSession.Canned.json(
                        """{"challenge_token":"${StepUpFixtures.completedToken}"}""",
                    ),
                // /refresh fails with 401 — post-logout the store is empty
                // and the server responds with unauthorized.
                "/v1/session/refresh" to
                    StepUpFixtures.apiError(
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
            // submit doesn't cascade through the scope before we assert.
            supervisorScope {
                val submit =
                    async {
                        fixture.client.submitStepUpOTP(challenge, code = "123456")
                    }
                StepUpFixtures.waitUntil { fixture.http.requestCount("/v1/session/otp/check") >= 1 }

                // Logout wipes stores and bumps the epoch while
                // /otp/check is suspended.
                fixture.client.logout()

                // Release /otp/check; submit advances to its post-completion
                // refresh, which sees no refresh token and surfaces Unauthorized.
                fixture.http.releaseGate("/v1/session/otp/check")

                val caught = runCatching { submit.await() }.exceptionOrNull()
                assertTrue(
                    "expected Unauthorized, got $caught",
                    caught is PreludeAuthError.Unauthorized,
                )
            }

            // Stores stay wiped — the scoped refresh did not persist into
            // stores logout just emptied.
            assertNull(fixture.refreshTokenStore.get(fixture.domain))
            assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
        }
}
