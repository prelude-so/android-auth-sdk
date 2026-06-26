package so.prelude.android.auth

import so.prelude.android.auth.http.ApiErrorJson

/**
 * Errors surfaced by the Prelude Auth SDK.
 *
 * Subclasses carry a human-readable [message] suitable for logging;
 * sensitive detail lives in the underlying [cause].
 */
sealed class PreludeAuthError(
    message: String? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /** 400 — request is malformed or missing a required field. */
    class BadRequest(
        message: String,
    ) : PreludeAuthError("BadRequest: $message")

    /**
     * 401 — credentials were rejected. A re-login is required. Distinct
     * from [InvalidOTPCode], which is a retry-the-code failure during
     * an otherwise-authenticated OTP exchange.
     */
    class Unauthorized(
        message: String,
    ) : PreludeAuthError("Unauthorized: $message")

    /** 429 — request was throttled by the server's rate limiter. */
    class RateLimited(
        message: String,
    ) : PreludeAuthError("RateLimited: $message")

    /** 5xx — the server encountered an unexpected condition. */
    class InternalServerError(
        message: String,
    ) : PreludeAuthError("InternalServerError: $message")

    /** Server response lacked an expected challenge token. */
    class MissingChallengeToken(
        message: String,
    ) : PreludeAuthError("MissingChallengeToken: $message")

    /**
     * Backend-issued challenge token is invalid, or the step-up state
     * machine cannot progress (step skipped, not completed, missing).
     * Recover via [requestStepUp].
     */
    class InvalidChallengeToken(
        message: String,
    ) : PreludeAuthError("InvalidChallengeToken: $message")

    /**
     * Challenge token expired before it was redeemed. Recover via
     * [requestStepUp].
     */
    class ExpiredChallengeToken(
        message: String,
    ) : PreludeAuthError("ExpiredChallengeToken: $message")

    /**
     * Single-use token was replayed. Surfaces from `/login/finalize`,
     * `/otp/check`, and `/stepup/continue` on a 409.
     */
    class TokenReused(
        message: String,
    ) : PreludeAuthError("TokenReused: $message")

    /**
     * The OTP code submitted during login was wrong or expired.
     * Distinct from [Unauthorized]: this is an authentication failure
     * (retry the code), not an authorization failure (re-login required).
     */
    class InvalidOTPCode(
        message: String,
    ) : PreludeAuthError("InvalidOTPCode: $message")

    /** The current session could not be refreshed. */
    class RefreshFailed(
        message: String,
    ) : PreludeAuthError("RefreshFailed: $message")

    /**
     * Request timed out before the server responded.
     *
     * Declared as a regular `class` — not `data object` — so each
     * `throw` creates a fresh instance and `fillInStackTrace` runs at
     * the throw site. A shared singleton would carry whichever stack
     * trace got captured at class-init, and accumulate suppressed
     * exceptions across unrelated callers.
     */
    class Timeout : PreludeAuthError("Timeout")

    /** The person dismissed the login UI before completing it. */
    class Cancelled : PreludeAuthError("Cancelled")

    /** Client-side configuration is inconsistent (e.g. invalid base URL). */
    class InvalidConfiguration(
        message: String,
    ) : PreludeAuthError("InvalidConfiguration: $message")

    /**
     * Password rejected by the server's policy. Distinct from
     * [Unauthorized] ("wrong password") — this means the password
     * doesn't meet the policy at all.
     */
    class InvalidPassword(
        message: String,
    ) : PreludeAuthError("InvalidPassword: $message")

    /**
     * Caller is authenticated but policy (rate-limit bucket, feature
     * flag, account state) denies this action. Broader than
     * [Unauthorized].
     */
    class Forbidden(
        message: String,
    ) : PreludeAuthError("Forbidden: $message")

    /**
     * Access token lacks a scope the endpoint requires. Distinct from
     * [Forbidden]: fix is to step up for the missing scope and retry.
     */
    class InsufficientScope(
        message: String,
    ) : PreludeAuthError("InsufficientScope: $message")

    /** Resource the request referenced does not exist. */
    class NotFound(
        message: String,
    ) : PreludeAuthError("NotFound: $message")

    /**
     * Resource state conflicts with the request (e.g. duplicate
     * identifier on sign-up).
     */
    class Conflict(
        message: String,
    ) : PreludeAuthError("Conflict: $message")

    /** Network-level failure (DNS, connection reset, TLS, etc.). */
    class Network(
        cause: Throwable,
    ) : PreludeAuthError("Network: ${cause.message}", cause)

    /**
     * Local crypto failure: DPoP key store, signing, or proof-shape
     * error. Distinct from [Network] (no request was sent) and from
     * [Unauthorized] (request reached the server, was rejected at the
     * auth layer).
     *
     * The wrapped [cause] carries the internal `DPoPKeyStoreError`
     * variant for diagnostics; surface to users only as the
     * top-level message.
     */
    class CryptoFailure(
        cause: Throwable,
    ) : PreludeAuthError("CryptoFailure: ${cause.message}", cause)

    /**
     * OTP or other login method refused because the identifier's
     * email domain is enforced to use SAML SSO. Recover by
     * restarting the flow via the SAML initiate endpoint.
     */
    class SamlLoginRequired(
        message: String,
    ) : PreludeAuthError("SamlLoginRequired: $message")

    /**
     * App has no PasskeyConfig set (Relying Party identity is
     * missing). Route the user to a different MFA factor.
     */
    class PasskeyNotConfigured(
        message: String,
    ) : PreludeAuthError("PasskeyNotConfigured: $message")

    /**
     * Server rejected the attestation from the registration
     * ceremony — bad challenge, bad origin, or malformed response.
     */
    class PasskeyRegistrationFailed(
        message: String,
    ) : PreludeAuthError("PasskeyRegistrationFailed: $message")

    /**
     * verify_passkey step cannot be driven — no credentials,
     * assertion failed, or no PasskeyConfig. Fall back to a
     * different step (e.g. SMS OTP).
     */
    class PasskeyStepUnavailable(
        message: String,
    ) : PreludeAuthError("PasskeyStepUnavailable: $message")

    /** Error code not recognised by the SDK. */
    class Generic(
        val code: String,
        val displayMessage: String,
    ) : PreludeAuthError("$code: $displayMessage")

    companion object
}

/**
 * Map a backend [ApiErrorJson] payload to the most-specific
 * [PreludeAuthError]. Falls back to [PreludeAuthError.Generic] for
 * codes the SDK doesn't recognise.
 */
internal fun PreludeAuthError.Companion.from(apiError: ApiErrorJson): PreludeAuthError {
    val message = apiError.displayMessage
    return when (apiError.code) {
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
        -> PreludeAuthError.BadRequest(message)

        "unauthorized",
        "invalid_dpop_proof",
        "dpop_key_mismatch",
        "missing_dpop_proof",
        "use_dpop_nonce",
        -> PreludeAuthError.Unauthorized(message)

        "bad_check_code" -> PreludeAuthError.InvalidOTPCode(message)

        "rate_limited", "too_many_requests" -> PreludeAuthError.RateLimited(message)

        // Backend emits `internal`; `internal_server_error` is kept
        // as a defensive alias.
        "internal", "internal_server_error" -> PreludeAuthError.InternalServerError(message)

        "missing_challenge_token" -> PreludeAuthError.MissingChallengeToken(message)

        "invalid_challenge_token",
        "step_not_completed",
        "step_not_found",
        "step_bypassed",
        "token_mismatch",
        -> PreludeAuthError.InvalidChallengeToken(message)

        "expired_challenge_token" -> PreludeAuthError.ExpiredChallengeToken(message)

        "token_reused" -> PreludeAuthError.TokenReused(message)

        "invalid_password" -> PreludeAuthError.InvalidPassword(message)

        // `auth_blocked` is the server's catch-all "auth policy
        // rejected this request"; `scope_not_allowed` is step-up's
        // specific refusal ("this session can't grant that scope");
        // `not_configured` / `direct_scope_identifier_mismatch` are
        // step-up policy refusals; `email_verification_not_allowed`
        // is OTP's "email channel is disabled" refusal;
        // `invalid_verify_configuration` / `suspended_account` /
        // `invalid_api_key` are app-level policy denials;
        // `saml_connection_disabled` is a disabled SSO connection.
        // All fold into `Forbidden` so UIs can branch on a single case.
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
        -> PreludeAuthError.Forbidden(message)

        "insufficient_scope" -> PreludeAuthError.InsufficientScope(message)

        "saml_login_required" -> PreludeAuthError.SamlLoginRequired(message)

        "passkey_not_configured" -> PreludeAuthError.PasskeyNotConfigured(message)

        "passkey_registration_failed" -> PreludeAuthError.PasskeyRegistrationFailed(message)

        "passkey_step_unavailable" -> PreludeAuthError.PasskeyStepUnavailable(message)

        // `saml_connection_not_configured` and `saml_no_connection_for_email`
        // are 404 "resource not found" conditions for SAML connections.
        "not_found",
        "saml_connection_not_configured",
        "saml_no_connection_for_email",
        -> PreludeAuthError.NotFound(message)

        "conflict", "identifier_already_exists" -> PreludeAuthError.Conflict(message)

        else -> PreludeAuthError.Generic(code = apiError.code, displayMessage = message)
    }
}
