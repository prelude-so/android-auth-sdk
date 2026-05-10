package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.HttpHeader
import java.util.Base64

/**
 * `submitStepUpOTP` non-completion paths: blocked / expired
 * challenge handles, server error mapping, and DPoP / bearer
 * attachment policy. Completion + multi-step advancement live in
 * [SubmitStepUpOTPCompletionTest].
 */
class SubmitStepUpOTPTest {

    @Test
    fun submitStepUpOTP_blockedChallenge_throwsInvalidChallengeToken_withoutNetwork() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()

        val blocked = PreludeStepUpChallenge.blocked(requestedScope = "prld:pwd:write")

        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(blocked, code = "123456") }
        }
        // No /otp/check fired — there's no token to bind the proof to.
        assertEquals(0, fixture.http.requestCount("/v1/session/otp/check"))
        Unit
    }

    @Test
    fun submitStepUpOTP_expiredChallenge_throwsInvalidChallengeToken_withoutNetwork() = runBlocking {
        // Server-side, expired challenges surface as `bad_check_code`
        // — indistinguishable from a wrong code by design. Catching
        // expiry locally lets the UI tell the user "your verification
        // expired" rather than just "wrong code".
        //
        // JWT `exp` is in the past relative to the fixture's pinned
        // clock; stub `Date:` matches the same clock so the local
        // expiry guard compares against `now` directly.
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        val alreadyExpiredToken = StepUpFixtures.makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_email",
                "jti" to "jti-expired",
                "exp" to StepUpFixtures.BASE_EPOCH - 100,
            ),
        )
        fixture.http.installAll(
            "/v1/session/stepup/request" to
                StepUpFixtures.stepUpResponse("continue", alreadyExpiredToken),
            // /otp/check intentionally NOT installed — local expiry
            // guard must short-circuit before any round-trip. If it
            // doesn't, the stub fails loudly with "no canned response".
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertThrows(PreludeSessionError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(challenge, code = "123456") }
        }

        assertEquals(
            "expired challenge must short-circuit before /otp/check",
            0,
            fixture.http.requestCount("/v1/session/otp/check"),
        )
    }

    @Test
    fun submitStepUpOTP_badCheckCode_throwsInvalidOTPCode_andLeavesChallengeReusable() = runBlocking {
        // `bad_check_code` = "retry the code" — distinct from a dead
        // challenge. The handle stays usable up to the server's bucket
        // limit.
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.installAll(
            "/v1/session/stepup/request" to
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            "/v1/session/otp/check" to StepUpFixtures.apiError(
                "bad_check_code",
                "wrong",
                status = 401,
            ),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")

        assertThrows(PreludeSessionError.InvalidOTPCode::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(challenge, code = "000000") }
        }

        // Handle still good — same id, same step.
        assertEquals("chal-1", challenge.challengeId)
        assertEquals("verify_email", challenge.currentStep)
    }

    @Test
    fun submitStepUpOTP_otpCheckMissingChallengeToken_surfacesStructuredError() = runBlocking {
        // /otp/check 200 without a `challenge_token` is a server
        // contract violation; surface as MissingChallengeToken.
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.installAll(
            "/v1/session/stepup/request" to
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            "/v1/session/otp/check" to StubHttpSession.Canned.json("""{}"""),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        assertThrows(PreludeSessionError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.submitStepUpOTP(challenge, code = "123456") }
        }
        Unit
    }

    @Test
    fun submitStepUpOTP_attachesChallengeDPoPProof_andOmitsBearer() = runBlocking {
        // /otp/check on the step-up surface is authenticated via the
        // challenge token in the body + a DPoP proof bound to the
        // challenge's `jti`. The proof must:
        //   * pin its `jti` to the challenge token's `jti` — one-shot
        //     ownership of THIS challenge, not the session,
        //   * omit any cached DPoP nonce — the challenge interceptor
        //     is a one-shot path, ambient nonces don't apply,
        //   * carry no bearer — nothing to refresh on this hop.
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        // Seed an ambient nonce so the absence-of-nonce assertion is
        // meaningful: the challenge interceptor must explicitly skip
        // the nonce it would otherwise pick up.
        fixture.keyStore.setNonce(fixture.domain, "ambient-nonce-not-for-challenge")
        fixture.http.installAll(
            "/v1/session/stepup/request" to
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            "/v1/session/otp/check" to StubHttpSession.Canned.json(
                """{"challenge_token":"${StepUpFixtures.verifySmsToken}"}""",
            ),
        )

        val challenge = fixture.client.requestStepUp(scope = "prld:pwd:write")
        fixture.client.submitStepUpOTP(challenge, code = "123456")

        val req = fixture.http.requestsFor("/v1/session/otp/check").single()
        val proof = req.header(HttpHeader.DPOP)
        assertNotNull("/otp/check must carry a challenge-bound DPoP proof", proof)
        assertNull(
            "/otp/check must not carry a bearer token",
            req.header(HttpHeader.AUTHORIZATION),
        )

        // jti pinned to the challenge token (verifyEmailToken's jti).
        val payload = decodePayload(proof!!)
        assertTrue(
            "proof jti must match the challenge token jti; was: $payload",
            "\"jti\":\"jti-otp\"" in payload,
        )
        // Ambient DPoP nonce must NOT have leaked into this one-shot proof.
        assertTrue(
            "challenge proof must not include a nonce; was: $payload",
            "\"nonce\"" !in payload,
        )

        // Body carries the challenge token verbatim — what the server
        // matches against the DPoP `jti`.
        val body = req.bodyAsJson()
        assertEquals(
            StepUpFixtures.verifyEmailToken,
            body["challenge_token"]!!.jsonPrimitive.content,
        )
        assertEquals("123456", body["code"]!!.jsonPrimitive.content)
    }

    private fun decodePayload(proof: String): String =
        String(Base64.getUrlDecoder().decode(proof.split('.')[1]))
}
