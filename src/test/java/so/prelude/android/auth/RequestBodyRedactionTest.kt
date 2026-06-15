package so.prelude.android.auth

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.http.CheckOTPRequestBody
import so.prelude.android.auth.http.FinalizeLoginRequestBody
import so.prelude.android.auth.http.LoginWithPasswordRequestBody
import so.prelude.android.auth.http.MigrateRequestBody
import so.prelude.android.auth.http.StepUpOTPCheckRequestBody

/**
 * Wire bodies that carry plaintext (password / OTP code / step-up
 * challenge token) must not surface the secret through
 * `toString()`. The encoded JSON still goes to the network —
 * redaction targets only stringified surfaces.
 */
class RequestBodyRedactionTest {
    @Test
    fun loginWithPasswordRequestBody_redactsPassword() {
        val body =
            LoginWithPasswordRequestBody(
                identifier = "alice@example.com",
                password = "hunter2",
                dispatchId = "d-1",
            )
        val s = body.toString()
        assertFalse(s, s.contains("hunter2"))
        assertTrue(s, s.contains("redacted"))
        assertTrue(s.contains("alice@example.com"))
    }

    @Test
    fun checkOTPRequestBody_redactsCode() {
        val s = CheckOTPRequestBody(code = "123456").toString()
        assertFalse(s, s.contains("123456"))
        assertTrue(s, s.contains("redacted"))
    }

    @Test
    fun finalizeLoginRequestBody_redactsChallengeTokenAndVerifier() {
        val s =
            FinalizeLoginRequestBody(
                challengeToken = "challenge-secret",
                codeVerifier = "verifier-secret",
            ).toString()
        assertFalse(s, s.contains("challenge-secret"))
        assertFalse(s, s.contains("verifier-secret"))
        assertTrue(s, s.contains("redacted"))
        // Null verifier renders as `null` — presence signal, no value.
        assertTrue(FinalizeLoginRequestBody(challengeToken = "x").toString().contains("codeVerifier=null"))
    }

    @Test
    fun migrateRequestBody_redactsLegacyToken() {
        val body =
            MigrateRequestBody(
                token = "legacy-bearer-secret",
                codeChallenge = "challenge-s256",
                dispatchId = "d-1",
            )
        val s = body.toString()
        assertFalse(s, s.contains("legacy-bearer-secret"))
        assertTrue(s, s.contains("redacted"))
        // The PKCE challenge is a public commitment, not a secret.
        assertTrue(s.contains("challenge-s256"))
    }

    @Test
    fun stepUpOTPCheckRequestBody_redactsCodeAndChallenge() {
        val s = StepUpOTPCheckRequestBody(code = "123456", challengeToken = "challenge-bait").toString()
        assertFalse(s, s.contains("123456"))
        assertFalse(s, s.contains("challenge-bait"))
        assertTrue(s, s.contains("redacted"))
    }
}
