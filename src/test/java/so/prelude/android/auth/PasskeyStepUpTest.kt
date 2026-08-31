package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** `continueStepUpWithPasskey`: assertion-options plumbing + advancement. */
class PasskeyStepUpTest {
    private val verifyPasskeyToken: String =
        StepUpFixtures.makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_passkey",
                "jti" to "jti-passkey",
                "exp" to StepUpFixtures.BASE_EPOCH + 600,
            ),
        )

    private fun requestPasskeyStepUp(fixture: Fixture): PreludeStepUpChallenge {
        fixture.http.install(
            "/v1/session/stepup/request",
            PasskeyFixtures.stepUpVerifyPasskey(verifyPasskeyToken),
        )
        return runBlocking { fixture.client.requestStepUp(scope = "prld:sensitive") }
    }

    @Test
    fun requestStepUp_verifyPasskey_carriesAssertionOptions() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()

            val challenge = requestPasskeyStepUp(fixture)

            assertEquals("verify_passkey", challenge.currentStep)
            assertEquals(
                "example.com",
                challenge.passkeyAssertionOptions!!["rpId"]!!.jsonPrimitive.content,
            )
        }

    @Test
    fun continueStepUpWithPasskey_postsAssertion_andCompletes() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            val challenge = requestPasskeyStepUp(fixture)
            fixture.http.installAll(
                "/v1/session/stepup/continue" to
                    PasskeyFixtures.challengeTokenResponse(StepUpFixtures.completedToken),
                "/v1/session/refresh" to StepUpFixtures.refreshOk(),
            )
            val fake = FakePasskeyCeremony()

            val next = fixture.client.continueStepUpWithPasskey(challenge, fake)

            assertNull("completed flow returns null", next)
            assertNotNull("ceremony was driven with the assertion options", fake.assertedOptions)

            val body =
                fixture.http
                    .requestsFor("/v1/session/stepup/continue")
                    .single()
                    .bodyAsJson()
            assertNotNull(body["passkey_assertion"])
            assertEquals(challenge.token, body["challenge_token"]!!.jsonPrimitive.content)
            assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
        }

    @Test
    fun continueStepUpWithPasskey_withoutOptions_throwsStepUnavailable() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            // A non-passkey step carries no assertion options.
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifySmsToken),
            )
            val challenge = fixture.client.requestStepUp(scope = "prld:sensitive")

            assertThrows(PreludeAuthError.PasskeyStepUnavailable::class.java) {
                runBlocking { fixture.client.continueStepUpWithPasskey(challenge, FakePasskeyCeremony()) }
            }
            assertEquals(0, fixture.http.requestCount("/v1/session/stepup/continue"))
        }

    @Test
    fun continueStepUpWithPasskey_blockedChallenge_throwsInvalidChallengeToken_withoutNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            val blocked = PreludeStepUpChallenge.blocked(requestedScope = "prld:sensitive")

            assertThrows(PreludeAuthError.InvalidChallengeToken::class.java) {
                runBlocking { fixture.client.continueStepUpWithPasskey(blocked, FakePasskeyCeremony()) }
            }
            assertEquals(0, fixture.http.requestCount("/v1/session/stepup/continue"))
        }

    @Test
    fun continueStepUpWithPasskey_expiredChallenge_throwsExpiredChallengeToken_withoutCeremony() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            val expiredToken =
                StepUpFixtures.makeChallengeToken(
                    mapOf(
                        "challenge_id" to "chal-1",
                        "current_step" to "verify_passkey",
                        "jti" to "jti-expired",
                        "exp" to StepUpFixtures.BASE_EPOCH - 100,
                    ),
                )
            fixture.http.install(
                "/v1/session/stepup/request",
                PasskeyFixtures.stepUpVerifyPasskey(expiredToken),
            )
            val challenge = fixture.client.requestStepUp(scope = "prld:sensitive")
            val fake = FakePasskeyCeremony()

            assertThrows(PreludeAuthError.ExpiredChallengeToken::class.java) {
                runBlocking { fixture.client.continueStepUpWithPasskey(challenge, fake) }
            }
            assertNull("expired challenge must short-circuit before the ceremony", fake.assertedOptions)
            assertEquals(0, fixture.http.requestCount("/v1/session/stepup/continue"))
        }
}
