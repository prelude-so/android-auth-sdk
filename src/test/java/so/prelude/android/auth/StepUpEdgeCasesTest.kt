package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Edge cases the main step-up suites would otherwise overweight:
 * independent handles across sequential flows, the no-auto-OTP
 * contract on `requestStepUp`, and defensive throws against
 * directly-completed challenges.
 */
class StepUpEdgeCasesTest {
    @Test
    fun multipleSequentialStepUpFlows_useIndependentChallengeHandles() =
        runBlocking {
            // Challenge handles are value-typed: distinct step-ups on the
            // same client don't share state — neither response overwrites
            // the prior handle. Sequential calls because StubHttpSession
            // serves the most-recently-installed canned response per path.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()

            val tokenA =
                StepUpFixtures.makeChallengeToken(
                    mapOf(
                        "challenge_id" to "chal-A",
                        "current_step" to "verify_email",
                        "jti" to "jti-A",
                        "exp" to StepUpFixtures.BASE_EPOCH + 600,
                    ),
                )

            val tokenB =
                StepUpFixtures.makeChallengeToken(
                    mapOf(
                        "challenge_id" to "chal-B",
                        "current_step" to "verify_sms",
                        "jti" to "jti-B",
                        "exp" to StepUpFixtures.BASE_EPOCH + 600,
                    ),
                )

            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", tokenA),
            )

            val challengeA = fixture.client.requestStepUp(scope = "prld:scope:a")

            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", tokenB),
            )

            val challengeB = fixture.client.requestStepUp(scope = "prld:scope:b")

            assertEquals("chal-A", challengeA.challengeId)
            assertEquals("chal-B", challengeB.challengeId)
            // Distinct tokens preserved on the handles — neither was
            // overwritten by the second request's response.
            assertEquals("prld:scope:a", challengeA.requestedScope)
            assertEquals("prld:scope:b", challengeB.requestedScope)
        }

    @Test
    fun requestStepUp_neverAutoFires_OTP_regardlessOfStatusOrStep() =
        runBlocking {
            // The no-auto-fire contract is pinned on the awkward shape (status
            // `review` + step `verify_email`): /otp is intentionally NOT
            // installed, so a regression fails with "no canned response".
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            val reviewOtpToken =
                StepUpFixtures.makeChallengeToken(
                    mapOf(
                        "challenge_id" to "chal-r",
                        "current_step" to "verify_email",
                        "jti" to "jti-review-otp",
                        "exp" to StepUpFixtures.BASE_EPOCH + 600,
                    ),
                )
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("review", reviewOtpToken),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

            assertEquals(PreludeStepUpStatus.UNDER_REVIEW, challenge.status)
            assertEquals("verify_email", challenge.currentStep)
            assertEquals(
                "requestStepUp must never auto-fire /otp; sendStepUpOTP is caller-driven",
                0,
                fixture.http.requestCount("/v1/session/otp"),
            )
        }

    @Test
    fun requestStepUp_directlyCompletedChallenge_throwsInvalidChallengeToken() =
        runBlocking {
            // `/stepup/request` must emit a flow with at least one
            // verification step; an already-`completed` response is a server
            // contract violation, so the SDK refuses the handle.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.completedToken),
            )

            val thrown =
                assertThrows(PreludeAuthError.InvalidChallengeToken::class.java) {
                    runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
                }
            assertTrue(
                "error message should call out the directly-completed shape",
                thrown.message!!.contains("already-completed"),
            )
            // The defensive throw fires BEFORE any post-completion refresh
            // — a refused handle must not silently consume the rotation.
            assertEquals(0, fixture.http.requestCount("/v1/session/refresh"))
        }

    @Test
    fun expiredChallenge_recoveredCleanly_byFreshRequestStepUp() =
        runBlocking {
            // Real-world shape: user backgrounds the app past the
            // challenge TTL, returns, and tries again. The expired
            // submit must not poison the next flow — a fresh
            // requestStepUp should succeed and yield a usable challenge.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            val expiredToken =
                StepUpFixtures.makeChallengeToken(
                    mapOf(
                        "challenge_id" to "chal-expired",
                        "current_step" to "verify_email",
                        "jti" to "jti-expired",
                        "exp" to StepUpFixtures.BASE_EPOCH - 100,
                    ),
                )
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", expiredToken),
            )

            val expired = fixture.client.requestStepUp(scope = "prld:pwd:write")
            assertThrows(PreludeAuthError.InvalidChallengeToken::class.java) {
                runBlocking { fixture.client.submitStepUpOTP(expired, code = "123456") }
            }

            // /otp/check is installed only here, on the recovery path: any
            // leftover state from the expired flow would have failed earlier.
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            )
            fixture.http.install(
                "/v1/session/otp/check",
                StubHttpSession.Canned.json(
                    """{"challenge_token":"${StepUpFixtures.verifySmsToken}"}""",
                ),
            )

            val fresh = fixture.client.requestStepUp(scope = "prld:pwd:write")
            assertEquals("chal-1", fresh.challengeId)
            // activeStepUp tracks the fresh challenge — the expired one
            // was overwritten, not lingering.
            assertEquals("chal-1", fixture.client.activeStepUp?.challengeId)

            val next = fixture.client.submitStepUpOTP(fresh, code = "123456")
            assertEquals("verify_sms", next?.currentStep)
        }
}
