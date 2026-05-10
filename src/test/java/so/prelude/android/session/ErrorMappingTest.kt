package so.prelude.android.session

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.ApiErrorJson

/**
 * Wire `code` → typed [PreludeSessionError] mapping. Covers the
 * codes the backend actually emits today; unrecognised codes must
 * round-trip through [PreludeSessionError.Generic] so callers retain
 * a useful debug signal.
 */
class ErrorMappingTest {
    private fun map(code: String, message: String = "boom"): PreludeSessionError =
        PreludeSessionError.from(ApiErrorJson(code = code, message = message))

    @Test
    fun internal_mapsToInternalServerError() {
        // Backend's 500 code is `internal`; `internal_server_error`
        // is kept as a defensive alias.
        assertTrue(map("internal") is PreludeSessionError.InternalServerError)
        assertTrue(map("internal_server_error") is PreludeSessionError.InternalServerError)
    }

    @Test
    fun expiredAndReusedChallengeTokens_areTyped() {
        assertTrue(map("expired_challenge_token") is PreludeSessionError.ExpiredChallengeToken)
        assertTrue(map("token_reused") is PreludeSessionError.TokenReused)
    }

    @Test
    fun dpopAndUnauthorizedFamily_collapsesToUnauthorized() {
        listOf("unauthorized", "invalid_dpop_proof", "dpop_key_mismatch", "missing_dpop_proof").forEach { code ->
            assertTrue("$code → Unauthorized", map(code) is PreludeSessionError.Unauthorized)
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
        ).forEach { code ->
            assertTrue("$code → BadRequest", map(code) is PreludeSessionError.BadRequest)
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
            assertTrue("$code → InvalidChallengeToken", map(code) is PreludeSessionError.InvalidChallengeToken)
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
        ).forEach { code ->
            assertTrue("$code → Forbidden", map(code) is PreludeSessionError.Forbidden)
        }
    }

    @Test
    fun resourceState_isTyped() {
        assertTrue(map("not_found") is PreludeSessionError.NotFound)
        listOf("conflict", "identifier_already_exists").forEach { code ->
            assertTrue("$code → Conflict", map(code) is PreludeSessionError.Conflict)
        }
    }

    @Test
    fun unknownCode_roundTripsThroughGeneric() {
        val err = map("totally_made_up_code", message = "hi") as PreludeSessionError.Generic
        assertEquals("totally_made_up_code", err.code)
        assertEquals("hi", err.displayMessage)
    }
}
