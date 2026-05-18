package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader

/**
 * Caller-driven OTP delivery: [sendStepUpOTP] fires `POST /otp`
 * for an in-flight step-up challenge. The SDK no longer auto-
 * delivers from `requestStepUp` / `submitStepUpOTP`.
 */
class SendStepUpOTPTest {
    @Test
    fun sendStepUpOTP_firesOTP_withChallengeToken() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
            // requestStepUp must NOT have fired /otp — this is the whole
            // point of the new contract.
            assertEquals(0, fixture.http.requestCount("/v1/session/otp"))

            fixture.client.sendStepUpOTP(challenge)

            assertEquals(1, fixture.http.requestCount("/v1/session/otp"))
            val body =
                fixture.http
                    .requestsFor("/v1/session/otp")
                    .single()
                    .bodyAsJson()
            assertEquals(
                StepUpFixtures.verifyEmailToken,
                body["challenge_token"]!!.jsonPrimitive.content,
            )
            // No dispatcher configured → `dispatch_id` is omitted, not
            // sent as null.
            assertFalse("dispatch_id should be omitted", body.containsKey("dispatch_id"))
        }

    @Test
    fun sendStepUpOTP_attachesDispatchId_whenSignalsDispatcherConfigured() =
        runBlocking {
            var dispatched = 0
            val fixture =
                Fixture.make(
                    signalsDispatcher = {
                        dispatched += 1
                        "dispatch-otp"
                    },
                )
            fixture.prePopulateStepUp()
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
            // Snapshot the dispatch count after requestStepUp so we
            // measure only what sendStepUpOTP itself fires.
            val baseline = dispatched
            fixture.client.sendStepUpOTP(challenge)

            assertEquals("one dispatch fires for /otp", baseline + 1, dispatched)
            val body =
                fixture.http
                    .requestsFor("/v1/session/otp")
                    .single()
                    .bodyAsJson()
            assertEquals("dispatch-otp", body["dispatch_id"]!!.jsonPrimitive.content)
        }

    @Test
    fun sendStepUpOTP_blockedChallenge_throwsInvalidChallengeToken_withoutNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()

            val blocked = PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write")

            assertThrows(PreludeAuthError.InvalidChallengeToken::class.java) {
                runBlocking { fixture.client.sendStepUpOTP(blocked) }
            }
            // No /otp fired — there's no token to identify the caller.
            assertEquals(0, fixture.http.requestCount("/v1/session/otp"))
            Unit
        }

    @Test
    fun sendStepUpOTP_doesNotAttachBearer_orDPoP() =
        runBlocking {
            // /otp is unauthenticated on the wire — the challenge token
            // in the body identifies the caller. No bearer (could leak a
            // perfectly valid access token to a server route that doesn't
            // need it) and no DPoP proof.
            val fixture = Fixture.make()
            fixture.prePopulateStepUp() // populates a valid access token
            fixture.http.installAll(
                "/v1/session/stepup/request" to
                    StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
                "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            )

            val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
            fixture.client.sendStepUpOTP(challenge)

            val req = fixture.http.requestsFor("/v1/session/otp").single()
            assertNull(
                "/otp must not carry Authorization",
                req.header(HttpHeader.AUTHORIZATION),
            )
            assertNull(
                "/otp must not carry a DPoP proof",
                req.header(HttpHeader.DPOP),
            )
        }
}
