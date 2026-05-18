package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.AccessTokenEntry

/**
 * `submitStepUpOTP` completion: post-OTP refresh shape, cache
 * replacement, and multi-step advancement (e.g. verify_email →
 * verify_sms). Non-completion paths live in [SubmitStepUpOTPTest];
 * concurrency in [StepUpConcurrencyTest].
 */
class SubmitStepUpOTPCompletionTest {
    @Test
    fun submitStepUpOTP_completed_refreshesWithStepUpToken_andReturnsNull() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp(refreshToken = "refresh-v1")
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
            val next = fixture.client.submitStepUpOTP(challenge, code = "123456")

            assertNull("completed challenge must yield a null follow-up", next)

            // Post-completion refresh sent `step_up_token` so the server
            // mints a scoped access token. Pins the integration:
            // submitStepUpOTP -> refreshAfterStepUp -> doRefresh.
            val refreshRequests = fixture.http.requestsFor("/v1/session/refresh")
            assertEquals(1, refreshRequests.size)
            val refreshBody = refreshRequests.single().bodyAsJson()
            assertEquals(
                StepUpFixtures.completedToken,
                refreshBody["step_up_token"]!!.jsonPrimitive.content,
            )
            assertEquals(
                "refresh-v1",
                refreshRequests.single().header(HttpHeader.REFRESH_TOKEN),
            )

            // Rotated refresh persisted; scoped access token cached.
            assertEquals(
                "refresh-v2",
                fixture.refreshTokenStore.get(fixture.domain)?.refreshToken,
            )
            val cached = fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)
            assertNotNull(cached)
            assertEquals(StepUpFixtures.SCOPED_ACCESS_TOKEN, cached!!.accessToken)
        }

    @Test
    fun submitStepUpOTP_completed_replacesCachedAccessToken_withRefreshedToken() =
        runBlocking {
            // The happy path uses the same `SCOPED_ACCESS_TOKEN` on both
            // sides of the refresh, so it can't distinguish "replaced
            // with the same value" from "didn't replace at all". Pin the
            // cache-replacement contract with two distinct JWTs.
            val preStepUpAccessToken =
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTAifQ.sig"

            val fixture = Fixture.make()
            fixture.prePopulateStepUp(refreshToken = "refresh-v1")
            // Override prePopulate's default access token with a distinct
            // pre-step-up value.
            fixture.accessTokenCache.set(
                domain = fixture.domain,
                entry =
                    AccessTokenEntry(
                        accessToken = preStepUpAccessToken,
                        expiresAt = StepUpFixtures.BASE_EPOCH + 3_600,
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
            fixture.client.submitStepUpOTP(challenge, code = "123456")

            // Pre-step-up token is gone; the scoped one minted by /refresh
            // sits in the cache.
            val cached = fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)
            assertNotNull(cached)
            assertEquals(StepUpFixtures.SCOPED_ACCESS_TOKEN, cached!!.accessToken)
        }

    @Test
    fun submitStepUpOTP_advancesToOTPStep_returnsNextChallenge_withoutAutoFiringDelivery() =
        runBlocking {
            // Multi-step OTP: `verify_email` → `verify_sms`. The SDK no
            // longer auto-fires `/otp` for the next step — the caller
            // drives delivery via `sendStepUpOTP`. /otp intentionally
            // NOT installed so a regression to auto-firing fails loudly.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp/check" to
                    StubHttpSession.Canned.json(
                        """{"challenge_token":"${StepUpFixtures.verifySmsToken}"}""",
                    ),
            )

            val first = fixture.client.requestStepUp(scope = "prld:pwd:write")
            assertEquals(
                "requestStepUp must not auto-fire /otp",
                0,
                fixture.http.requestCount("/v1/session/otp"),
            )

            val next = fixture.client.submitStepUpOTP(first, code = "123456")

            assertNotNull("multi-step flow returns the next challenge", next)
            assertEquals("verify_sms", next!!.currentStep)
            assertEquals("chal-1", next.challengeId)
            assertEquals("prld:pwd:write", next.requestedScope)
            assertEquals(PreludeStepUpStatus.CONTINUE, next.status)

            assertEquals(
                "submitStepUpOTP must not auto-fire /otp for the next OTP step",
                0,
                fixture.http.requestCount("/v1/session/otp"),
            )
        }

    @Test
    fun activeStepUp_lifecycle_setOnRequest_advancedOnSubmit_clearedOnCompletion() =
        runBlocking {
            // Pins the three transitions in one go: requestStepUp installs
            // the handle, submitStepUpOTP advances it, completion clears.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp(refreshToken = "refresh-v1")
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/refresh" to StepUpFixtures.refreshOk(refreshToken = "refresh-v2"),
            )

            assertNull("no flow yet", fixture.client.activeStepUp)

            // First advance: verify_email step.
            val first = fixture.client.requestStepUp(scope = "prld:pwd:write")
            assertEquals(first.challengeId, fixture.client.activeStepUp?.challengeId)
            assertEquals("verify_email", fixture.client.activeStepUp?.currentStep)

            // Second advance: server hands us verify_sms.
            fixture.http.install(
                "/v1/session/otp/check",
                StubHttpSession.Canned.json(
                    """{"challenge_token":"${StepUpFixtures.verifySmsToken}"}""",
                ),
            )
            fixture.client.submitStepUpOTP(first, code = "123456")
            assertEquals("verify_sms", fixture.client.activeStepUp?.currentStep)

            // Completion: handle clears.
            fixture.http.install(
                "/v1/session/otp/check",
                StubHttpSession.Canned.json(
                    """{"challenge_token":"${StepUpFixtures.completedToken}"}""",
                ),
            )
            val current = fixture.client.activeStepUp!!
            fixture.client.submitStepUpOTP(current, code = "123456")
            assertNull("completion must clear activeStepUp", fixture.client.activeStepUp)
        }

    @Test
    fun submitStepUpOTP_completed_clearsActiveStepUp_evenWhenRefreshFails() =
        runBlocking {
            // Pin the `finally` cleanup in the completion branch: if
            // the post-completion refresh throws, `activeStepUp` must
            // still be `null` afterwards — otherwise observers would
            // see a stale challenge for a flow the server has already
            // consumed.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp(refreshToken = "refresh-v1")
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp/check" to
                    StubHttpSession.Canned.json(
                        """{"challenge_token":"${StepUpFixtures.completedToken}"}""",
                    ),
                // Refresh fails — exception must propagate, handle
                // must still clear.
                "/v1/session/refresh" to StepUpFixtures.apiError("internal_error", status = 500),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
            val thrown =
                runCatching { fixture.client.submitStepUpOTP(challenge, code = "123456") }
                    .exceptionOrNull()

            assertNotNull("refresh failure must surface", thrown)
            assertNull(
                "activeStepUp must clear even when refreshAfterStepUp throws",
                fixture.client.activeStepUp,
            )
        }
}
