package so.prelude.android.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.http.ApiErrorJson

/**
 * Wire `code` → typed [PreludeAuthError] mapping. Covers the
 * codes the backend actually emits today; unrecognised codes must
 * round-trip through [PreludeAuthError.Generic] so callers retain
 * a useful debug signal.
 */
class ErrorMappingTest {
    private fun map(
        code: String,
        message: String = "boom",
    ): PreludeAuthError = PreludeAuthError.from(ApiErrorJson(code = code, message = message))

    @Test
    fun internal_mapsToInternalServerError() {
        // Backend's 500 code is `internal`; `internal_server_error`
        // is kept as a defensive alias.
        assertTrue(map("internal") is PreludeAuthError.InternalServerError)
        assertTrue(map("internal_server_error") is PreludeAuthError.InternalServerError)
    }

    @Test
    fun expiredAndReusedChallengeTokens_areTyped() {
        assertTrue(map("expired_challenge_token") is PreludeAuthError.ExpiredChallengeToken)
        assertTrue(map("token_reused") is PreludeAuthError.TokenReused)
    }

    @Test
    fun dpopAndUnauthorizedFamily_collapsesToUnauthorized() {
        listOf("unauthorized", "invalid_dpop_proof", "dpop_key_mismatch", "missing_dpop_proof", "use_dpop_nonce").forEach { code ->
            assertTrue("$code → Unauthorized", map(code) is PreludeAuthError.Unauthorized)
        }
    }

    @Test
    fun badRequestFamily_collapsesToBadRequest() {
        listOf(
            "bad_request",
            "invalid_identifier",
            "invalid_metadata",
            "invalid_pagination_limit",
            "invalid_pagination_offset",
            "invalid_redirect_uri",
            "invalid_verification_token",
            "oauth_provider_not_configured",
            "oauth_provider_disabled",
            "email_domain_not_verified",
            "insufficient_balance",
        ).forEach { code ->
            assertTrue("$code → BadRequest", map(code) is PreludeAuthError.BadRequest)
        }
    }

    @Test
    fun stepUpStateMachineErrors_collapseToInvalidChallengeToken() {
        listOf(
            "invalid_challenge_token",
            "step_not_completed",
            "step_not_found",
            "step_bypassed",
            "token_mismatch",
        ).forEach { code ->
            assertTrue("$code → InvalidChallengeToken", map(code) is PreludeAuthError.InvalidChallengeToken)
        }
    }

    @Test
    fun forbiddenFamily_includesScopeAndConfig() {
        listOf(
            "forbidden",
            "auth_blocked",
            "scope_not_allowed",
            "not_configured",
            "direct_scope_identifier_mismatch",
            "email_verification_not_allowed",
            "invalid_verify_configuration",
            "suspended_account",
            "invalid_api_key",
            "saml_connection_disabled",
        ).forEach { code ->
            assertTrue("$code → Forbidden", map(code) is PreludeAuthError.Forbidden)
        }
    }

    @Test
    fun resourceState_isTyped() {
        listOf("not_found", "saml_connection_not_configured", "saml_no_connection_for_email").forEach { code ->
            assertTrue("$code → NotFound", map(code) is PreludeAuthError.NotFound)
        }
        listOf("conflict", "identifier_already_exists").forEach { code ->
            assertTrue("$code → Conflict", map(code) is PreludeAuthError.Conflict)
        }
    }

    @Test
    fun samlLoginRequired_isTyped() {
        assertTrue(map("saml_login_required") is PreludeAuthError.SamlLoginRequired)
    }

    @Test
    fun noLoginConfig_isTyped() {
        assertTrue(map("no_login_config") is PreludeAuthError.NoLoginConfig)
    }

    @Test
    fun passkeyFamily_isTyped() {
        assertTrue(map("passkey_not_configured") is PreludeAuthError.PasskeyNotConfigured)
        assertTrue(map("passkey_registration_failed") is PreludeAuthError.PasskeyRegistrationFailed)
        listOf("passkey_step_unavailable", "passkey_authenticator_blocked").forEach { code ->
            assertTrue("$code → PasskeyStepUnavailable", map(code) is PreludeAuthError.PasskeyStepUnavailable)
        }
    }

    @Test
    fun unknownCode_roundTripsThroughGeneric() {
        val err = map("totally_made_up_code", message = "hi") as PreludeAuthError.Generic
        assertEquals("totally_made_up_code", err.code)
        assertEquals("hi", err.displayMessage)
    }
}
