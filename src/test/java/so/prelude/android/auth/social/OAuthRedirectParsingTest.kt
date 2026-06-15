package so.prelude.android.auth.social

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.PreludeAuthError

class OAuthRedirectParsingTest {
    @Test
    fun parse_challengeToken() {
        val redirect = OAuthRedirect.parse("demo://oauth?challenge_token=challenge-abc")
        assertEquals(OAuthRedirect.Challenge("challenge-abc"), redirect)
    }

    @Test
    fun parse_ignoresStatusParameter() {
        val redirect = OAuthRedirect.parse("demo://oauth?challenge_token=t1&status=otp_required")
        assertEquals(OAuthRedirect.Challenge("t1"), redirect)
    }

    @Test
    fun parse_serverErrorWinsOverToken() {
        val redirect = OAuthRedirect.parse("demo://oauth?error=server_error&challenge_token=t1")
        assertEquals("server_error", (redirect as OAuthRedirect.Failure).code)
    }

    @Test
    fun parse_missingToken() {
        val redirect = OAuthRedirect.parse("demo://oauth")
        assertEquals("missing_challenge_token", (redirect as OAuthRedirect.Failure).code)
    }

    @Test
    fun errorMapping() {
        assertTrue(failure("authentication_failed").error is PreludeAuthError.Unauthorized)
        assertTrue(failure("email_already_in_use").error is PreludeAuthError.Conflict)
        assertTrue(failure("server_error").error is PreludeAuthError.InternalServerError)
        assertTrue(failure("something_new").error is PreludeAuthError.Unauthorized)
        assertTrue(
            OAuthRedirect.parse("demo://oauth").error is PreludeAuthError.MissingChallengeToken,
        )
    }

    @Test
    fun challenge_hasNoError() {
        assertNull(OAuthRedirect.parse("demo://oauth?challenge_token=t1").error)
    }

    private fun failure(code: String): OAuthRedirect = OAuthRedirect.parse("demo://oauth?error=$code&error_description=msg")
}
