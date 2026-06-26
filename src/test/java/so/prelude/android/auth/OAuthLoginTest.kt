package so.prelude.android.auth

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
import java.net.URL
import java.util.Base64

/**
 * `initiateOAuthLogin` / `finalizeOAuthLogin`: PKCE challenge shape,
 * authorization-URL parsing, verifier→finalize binding, and the
 * email-link branch.
 */
class OAuthLoginTest {
    private val authorizePath = "/v1/session/login/oauth/google/authorize"
    private val finalizePath = "/v1/session/login/finalize"

    /** Unsigned, well-formed JWT carrying [payloadJson] as the payload. */
    private fun makeToken(payloadJson: String): String {
        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray())
        return "eyJhbGciOiJIUzI1NiJ9.$b64.sig"
    }

    private fun authorizeOk(url: String = "https://provider.example/auth") = StubHttpSession.Canned.json("""{"authorization_url":"$url"}""")

    /** A context for finalize paths that throw before the verifier is read. */
    private fun anyContext() = OAuthLoginContext(URL("https://provider.example/auth"), "verifier")

    @Test
    fun initiate_sendsPkceChallenge_andReturnsAuthorizationURL() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install(authorizePath, authorizeOk("https://provider.example/auth?state=s1"))

            val context =
                fixture.client.initiateOAuthLogin(
                    InitiateOAuthLoginOptions(OAuthProvider.GOOGLE, "demo://oauth"),
                )

            assertEquals("https://provider.example/auth?state=s1", context.authorizationUrl.toString())
            val body =
                fixture.http
                    .requestsFor(authorizePath)
                    .single()
                    .bodyAsJson()
            assertEquals("demo://oauth", body["redirect_uri"]!!.jsonPrimitive.content)
            assertEquals("S256", body["code_challenge_method"]!!.jsonPrimitive.content)
            assertNotNull(body["code_challenge"])
            Unit
        }

    @Test
    fun initiate_invalidAuthorizationURL_throws() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install(authorizePath, StubHttpSession.Canned.json("{}"))

            val error =
                assertThrows(PreludeAuthError.Generic::class.java) {
                    runBlocking {
                        fixture.client.initiateOAuthLogin(
                            InitiateOAuthLoginOptions(OAuthProvider.GOOGLE, "demo://oauth"),
                        )
                    }
                }
            assertEquals("invalid_authorization_url", error.code)
            Unit
        }

    @Test
    fun finalize_bindsVerifierToInitiateChallenge() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                authorizePath to authorizeOk(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            val context =
                fixture.client.initiateOAuthLogin(
                    InitiateOAuthLoginOptions(OAuthProvider.GOOGLE, "demo://oauth"),
                )
            val token = makeToken("""{"sub":"user-1"}""")
            val result = fixture.client.finalizeOAuthLogin(context, token)

            val user = (result as FinalizeOAuthLoginResult.LoggedIn).user
            assertEquals("user-1", user.profile.userId)

            val authorizeBody =
                fixture.http
                    .requestsFor(authorizePath)
                    .single()
                    .bodyAsJson()
            val finalizeBody =
                fixture.http
                    .requestsFor(finalizePath)
                    .single()
                    .bodyAsJson()
            val challenge = authorizeBody["code_challenge"]!!.jsonPrimitive.content
            val verifier = finalizeBody["code_verifier"]!!.jsonPrimitive.content
            assertEquals(challenge, Pkce.codeChallenge(verifier))
            assertEquals(token, finalizeBody["challenge_token"]!!.jsonPrimitive.content)
            Unit
        }

    /**
     * Two interleaved logins each keep their own PKCE verifier — a
     * later initiate cannot clobber an earlier flow's secret.
     */
    @Test
    fun concurrentLogins_doNotShareVerifier() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                authorizePath to authorizeOk(),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )

            // Both flows initiate before either finalizes — the race window.
            val ctxA =
                fixture.client.initiateOAuthLogin(
                    InitiateOAuthLoginOptions(OAuthProvider.GOOGLE, "demo://oauth"),
                )
            val ctxB =
                fixture.client.initiateOAuthLogin(
                    InitiateOAuthLoginOptions(OAuthProvider.GOOGLE, "demo://oauth"),
                )

            val token = makeToken("""{"sub":"user-1"}""")
            fixture.client.finalizeOAuthLogin(ctxA, token)
            fixture.client.finalizeOAuthLogin(ctxB, token)

            val authorizeBodies = fixture.http.requestsFor(authorizePath).map { it.bodyAsJson() }
            val finalizeBodies = fixture.http.requestsFor(finalizePath).map { it.bodyAsJson() }
            assertEquals(2, authorizeBodies.size)
            assertEquals(2, finalizeBodies.size)

            // Each finalize carried the verifier from its own initiate.
            val challengeA = authorizeBodies[0]["code_challenge"]!!.jsonPrimitive.content
            val challengeB = authorizeBodies[1]["code_challenge"]!!.jsonPrimitive.content
            val verifierA = finalizeBodies[0]["code_verifier"]!!.jsonPrimitive.content
            val verifierB = finalizeBodies[1]["code_verifier"]!!.jsonPrimitive.content
            assertEquals(challengeA, Pkce.codeChallenge(verifierA))
            assertEquals(challengeB, Pkce.codeChallenge(verifierB))
            assertNotEquals(verifierA, verifierB)
            Unit
        }

    @Test
    fun finalize_emptyToken_throwsMissingChallengeToken() {
        val fixture = Fixture.make()
        assertThrows(PreludeAuthError.MissingChallengeToken::class.java) {
            runBlocking { fixture.client.finalizeOAuthLogin(anyContext(), "") }
        }
    }

    @Test
    fun finalize_malformedToken_throwsInvalidChallengeToken() {
        val fixture = Fixture.make()
        assertThrows(PreludeAuthError.InvalidChallengeToken::class.java) {
            runBlocking { fixture.client.finalizeOAuthLogin(anyContext(), "not-a-jwt") }
        }
    }

    @Test
    fun finalize_oauthEmailLink_sendsOTP_andReturnsOtpRequired() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install(
                "/v1/session/otp",
                StubHttpSession.Canned(
                    statusCode = 204,
                    headers = mapOf(HttpHeader.VERIFICATION_TOKEN to "verify-token-1"),
                ),
            )
            val token =
                makeToken(
                    """{"grant_mode":"oauth-email-link","metadata":{"oauth_email":"person@example.com"}}""",
                )

            val result = fixture.client.finalizeOAuthLogin(anyContext(), token)

            val otp = result as FinalizeOAuthLoginResult.OtpRequired
            // The resumable handle captures the verification token from
            // the /otp response, not the challenge token.
            assertEquals("verify-token-1", otp.challenge.verificationToken)
            assertEquals("person@example.com", otp.email)

            // Code delivered via /otp carrying the challenge token; no
            // session is established until it is checked.
            assertEquals(1, fixture.http.requestCount("/v1/session/otp"))
            val otpBody =
                fixture.http
                    .requestsFor("/v1/session/otp")
                    .single()
                    .bodyAsJson()
            assertEquals(token, otpBody["challenge_token"]!!.jsonPrimitive.content)
            assertEquals(0, fixture.http.requestCount(finalizePath))
            Unit
        }

    @Test
    fun finalize_oauthEmailLink_missingVerificationToken_throws() {
        val fixture = Fixture.make()
        // /otp succeeds but omits the verification token header.
        fixture.http.install("/v1/session/otp", StubHttpSession.Canned(statusCode = 204))
        val token = makeToken("""{"grant_mode":"oauth-email-link"}""")

        val error =
            assertThrows(PreludeAuthError.Generic::class.java) {
                runBlocking { fixture.client.finalizeOAuthLogin(anyContext(), token) }
            }
        assertEquals("missing_verification_token", error.code)
    }

    @Test
    fun checkOAuthEmailOTP_replaysVerificationToken_andFinalizes() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                "/v1/session/otp" to
                    StubHttpSession.Canned(
                        statusCode = 204,
                        headers = mapOf(HttpHeader.VERIFICATION_TOKEN to "verify-token-1"),
                    ),
                "/v1/session/otp/check" to OtpFixtures.checkOkResponse(challenge = "login-challenge-1"),
                finalizePath to OtpFixtures.finalizeOkResponse(),
            )
            val linkToken =
                makeToken(
                    """{"grant_mode":"oauth-email-link","metadata":{"oauth_email":"person@example.com"}}""",
                )

            val otp =
                fixture.client.finalizeOAuthLogin(anyContext(), linkToken)
                    as FinalizeOAuthLoginResult.OtpRequired
            val user = fixture.client.checkOAuthEmailOTP("123456", resuming = otp.challenge)
            assertEquals("user-1", user.profile.userId)

            // The check replays the captured verification token and
            // stays session-less (no DPoP); the body authenticates via
            // the code, not a challenge token.
            val checkReq = fixture.http.requestsFor("/v1/session/otp/check").single()
            assertEquals("verify-token-1", checkReq.header(HttpHeader.VERIFICATION_TOKEN))
            assertNull(checkReq.header(HttpHeader.DPOP))
            val checkBody = checkReq.bodyAsJson()
            assertEquals("123456", checkBody["code"]!!.jsonPrimitive.content)
            assertNull(checkBody["challenge_token"])

            // login/finalize establishes the DPoP-bound session and
            // carries the challenge token issued by /otp/check.
            val finalizeReq = fixture.http.requestsFor(finalizePath).single()
            assertNotNull(finalizeReq.header(HttpHeader.DPOP))
            val finalizeBody = finalizeReq.bodyAsJson()
            assertEquals("login-challenge-1", finalizeBody["challenge_token"]!!.jsonPrimitive.content)
            Unit
        }

    @Test
    fun oauthEmailChallenge_redactsVerificationToken() {
        val challenge = OAuthEmailChallenge(verificationToken = "verify.SECRET.tok")
        val s = challenge.toString()
        assertFalse(s, s.contains("verify.SECRET.tok"))
        assertTrue(s, s.contains("redacted"))
    }
}
