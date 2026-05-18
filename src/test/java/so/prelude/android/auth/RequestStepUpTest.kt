package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Status branches + error mapping for `requestStepUp`. Request-shape
 * + 401-recovery cases live in [RequestStepUpAuthTest]; the
 * `submitStepUpOTP` surface in [SubmitStepUpOTPTest].
 */
class RequestStepUpTest {
    @Test
    fun requestStepUp_otpStep_returnsChallenge_andDoesNotFireOTPDelivery() =
        runBlocking {
            // `requestStepUp` returns the challenge handle, and the
            // caller decides when to fire `POST /otp` via `sendStepUpOTP`.
            // /otp intentionally NOT
            // installed — if the SDK regressed to auto-firing, the stub
            // would fail loudly with "no canned response".
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

            assertEquals(PreludeStepUpStatus.CONTINUE, challenge.status)
            assertEquals("chal-1", challenge.challengeId)
            assertEquals("verify_email", challenge.currentStep)
            assertEquals("prld:pwd:write", challenge.requestedScope)

            assertEquals(
                "requestStepUp must not auto-fire /otp; caller drives delivery",
                0,
                fixture.http.requestCount("/v1/session/otp"),
            )
            Unit
        }

    @Test
    fun requestStepUp_blocked_returnsBlockedHandle_andSkipsOTPDelivery() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("block"),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

            assertEquals(PreludeStepUpStatus.BLOCKED, challenge.status)
            assertEquals("prld:pwd:write", challenge.requestedScope)
            assertEquals("blocked challenge must not carry a challenge id", "", challenge.challengeId)
            assertEquals(0, fixture.http.requestCount("/v1/session/otp"))
            Unit
        }

    @Test
    fun requestStepUp_underReview_returnsReviewHandle_andDoesNotFireOTPDelivery() =
        runBlocking {
            // `review` flows are server-side asynchronous — but
            // regardless of status, `requestStepUp` never auto-fires
            // `/otp`. The caller decides whether to call
            // `sendStepUpOTP` based on `currentStep`.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            val reviewToken =
                StepUpFixtures.makeChallengeToken(
                    mapOf(
                        "challenge_id" to "chal-2",
                        "current_step" to "wait_for_review",
                        "jti" to "jti-review",
                        "exp" to StepUpFixtures.BASE_EPOCH + 600,
                    ),
                )
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("review", reviewToken),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

            assertEquals(PreludeStepUpStatus.UNDER_REVIEW, challenge.status)
            assertEquals("wait_for_review", challenge.currentStep)
            assertEquals(0, fixture.http.requestCount("/v1/session/otp"))
            Unit
        }

    @Test
    fun requestStepUp_continueWithoutChallengeToken_throwsMissingChallengeToken() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            // Server contract violation: `continue` MUST carry a token.
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue"),
            )

            val thrown =
                assertThrows(PreludeAuthError.MissingChallengeToken::class.java) {
                    runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
                }
            assertTrue(thrown.message!!.contains("Missing challenge token"))
        }

    @Test
    fun requestStepUp_unknownStatus_surfacesGenericError() =
        runBlocking {
            // A status the SDK doesn't model (e.g. a future `pending` value
            // rolled out before the SDK ships) is `Generic` rather than
            // silently coerced to a known enum.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(
                "/v1/session/stepup/request",
                StubHttpSession.Canned.json("""{"status":"pending"}"""),
            )

            val thrown =
                assertThrows(PreludeAuthError.Generic::class.java) {
                    runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
                }
            assertEquals("unknown_stepup_status", thrown.code)
        }

    @Test
    fun requestStepUp_scopeNotAllowed_surfacesForbidden() =
        runBlocking {
            // `scope_not_allowed` = the session may not request this scope.
            // Mapped to Forbidden by the central error mapper.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.apiError("scope_not_allowed", "no", status = 403),
            )

            assertThrows(PreludeAuthError.Forbidden::class.java) {
                runBlocking { fixture.client.requestStepUp(scope = "prld:pwd:write") }
            }
            Unit
        }
}
