package so.prelude.android.session

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.CheckOTPRequestBody
import so.prelude.android.session.http.LoginWithPasswordRequestBody
import so.prelude.android.session.http.StepUpOTPCheckRequestBody

/**
 * Wire bodies that carry plaintext (password / OTP code / step-up
 * challenge token) must not surface the secret through
 * `toString()`. The encoded JSON still goes to the network —
 * redaction targets only stringified surfaces.
 */
class RequestBodyRedactionTest {

    @Test
    fun loginWithPasswordRequestBody_redactsPassword() {
        val body = LoginWithPasswordRequestBody(
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
    fun stepUpOTPCheckRequestBody_redactsCodeAndChallenge() {
        val s = StepUpOTPCheckRequestBody(code = "123456", challengeToken = "challenge-bait").toString()
        assertFalse(s, s.contains("123456"))
        assertFalse(s, s.contains("challenge-bait"))
        assertTrue(s, s.contains("redacted"))
    }
}
