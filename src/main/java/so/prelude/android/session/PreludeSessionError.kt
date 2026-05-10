package so.prelude.android.session

import so.prelude.android.session.http.ApiErrorJson

/**
 * Errors surfaced by the Prelude session SDK.
 *
 * Subclasses carry a human-readable [message] suitable for logging;
 * sensitive detail lives in the underlying [cause].
 */
sealed class PreludeSessionError(
    message: String? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /** 400 — request is malformed or missing a required field. */
    class BadRequest(message: String) : PreludeSessionError("BadRequest: $message")

    /**
     * 401 — credentials were rejected. A re-login is required. Distinct
     * from [InvalidOTPCode], which is a retry-the-code failure during
     * an otherwise-authenticated OTP exchange.
     */
    class Unauthorized(message: String) : PreludeSessionError("Unauthorized: $message")

    /** 429 — request was throttled by the server's rate limiter. */
    class RateLimited(message: String) : PreludeSessionError("RateLimited: $message")

    /** 5xx — the server encountered an unexpected condition. */
    class InternalServerError(message: String) :
        PreludeSessionError("InternalServerError: $message")

    /** Server response lacked an expected challenge token. */
    class MissingChallengeToken(message: String) :
        PreludeSessionError("MissingChallengeToken: $message")

    /**
     * Backend-issued challenge token is invalid, or the step-up state
     * machine cannot progress (step skipped, not completed, missing).
     * Recover via [requestStepUp].
     */
    class InvalidChallengeToken(message: String) :
        PreludeSessionError("InvalidChallengeToken: $message")

    /**
     * Challenge token expired before it was redeemed. Recover via
     * [requestStepUp].
     */
    class ExpiredChallengeToken(message: String) :
        PreludeSessionError("ExpiredChallengeToken: $message")

    /**
     * Single-use token was replayed. Surfaces from `/login/finalize`,
     * `/otp/check`, and `/stepup/continue` on a 409.
     */
    class TokenReused(message: String) :
        PreludeSessionError("TokenReused: $message")

    /**
     * The OTP code submitted during login was wrong or expired.
     * Distinct from [Unauthorized]: this is an authentication failure
     * (retry the code), not an authorization failure (re-login required).
     */
    class InvalidOTPCode(message: String) :
        PreludeSessionError("InvalidOTPCode: $message")

    /** The current session could not be refreshed. */
    class RefreshFailed(message: String) : PreludeSessionError("RefreshFailed: $message")

    /**
     * Request timed out before the server responded.
     *
     * Declared as a regular `class` — not `data object` — so each
     * `throw` creates a fresh instance and `fillInStackTrace` runs at
     * the throw site. A shared singleton would carry whichever stack
     * trace got captured at class-init, and accumulate suppressed
     * exceptions across unrelated callers.
     */
    class Timeout : PreludeSessionError("Timeout")

    /** Client-side configuration is inconsistent (e.g. invalid base URL). */
    class InvalidConfiguration(message: String) :
        PreludeSessionError("InvalidConfiguration: $message")

    /**
     * Password rejected by the server's policy. Distinct from
     * [Unauthorized] ("wrong password") — this means the password
     * doesn't meet the policy at all.
     */
    class InvalidPassword(message: String) :
        PreludeSessionError("InvalidPassword: $message")

    /**
     * Caller is authenticated but policy (rate-limit bucket, feature
     * flag, account state) denies this action. Broader than
     * [Unauthorized].
     */
    class Forbidden(message: String) : PreludeSessionError("Forbidden: $message")

    /**
     * Access token lacks a scope the endpoint requires. Distinct from
     * [Forbidden]: fix is to step up for the missing scope and retry.
     */
    class InsufficientScope(message: String) :
        PreludeSessionError("InsufficientScope: $message")

    /** Resource the request referenced does not exist. */
    class NotFound(message: String) : PreludeSessionError("NotFound: $message")

    /**
     * Resource state conflicts with the request (e.g. duplicate
     * identifier on sign-up).
     */
    class Conflict(message: String) : PreludeSessionError("Conflict: $message")

    /** Network-level failure (DNS, connection reset, TLS, etc.). */
    class Network(cause: Throwable) : PreludeSessionError("Network: ${cause.message}", cause)

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
    class CryptoFailure(cause: Throwable) :
        PreludeSessionError("CryptoFailure: ${cause.message}", cause)

    /**
     * Anti-fraud signals dispatch failed. Wraps the underlying
     * [so.prelude.android.session.signals.PreludeSignalsDispatcher]
     * failure (network, invalid key, malformed response) so callers
     * see a structured [PreludeSessionError] rather than a leaked
     * implementation exception.
     */
    class SignalsDispatchFailed(cause: Throwable) :
        PreludeSessionError("SignalsDispatchFailed: ${cause.message}", cause)

    /** Error code not recognised by the SDK. */
    class Generic(val code: String, val displayMessage: String) :
        PreludeSessionError("$code: $displayMessage")

    companion object
}

/**
 * Map a backend [ApiErrorJson] payload to the most-specific
 * [PreludeSessionError]. Falls back to [PreludeSessionError.Generic] for
 * codes the SDK doesn't recognise.
 */
internal fun PreludeSessionError.Companion.from(apiError: ApiErrorJson): PreludeSessionError {
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
        -> PreludeSessionError.BadRequest(message)
        "unauthorized",
        "invalid_dpop_proof",
        "dpop_key_mismatch",
        "missing_dpop_proof",
        -> PreludeSessionError.Unauthorized(message)
        "bad_check_code" -> PreludeSessionError.InvalidOTPCode(message)
        "rate_limited", "too_many_requests" -> PreludeSessionError.RateLimited(message)
        // Backend emits `internal`; `internal_server_error` is kept
        // as a defensive alias.
        "internal", "internal_server_error" -> PreludeSessionError.InternalServerError(message)
        "missing_challenge_token" -> PreludeSessionError.MissingChallengeToken(message)
        "invalid_challenge_token",
        "step_not_completed",
        "step_not_found",
        "step_bypassed",
        "token_mismatch",
        -> PreludeSessionError.InvalidChallengeToken(message)
        "expired_challenge_token" -> PreludeSessionError.ExpiredChallengeToken(message)
        "token_reused" -> PreludeSessionError.TokenReused(message)
        "invalid_password" -> PreludeSessionError.InvalidPassword(message)
        // `auth_blocked` is the server's catch-all "auth policy
        // rejected this request"; `scope_not_allowed` is step-up's
        // specific refusal ("this session can't grant that scope");
        // `not_configured` / `direct_scope_identifier_mismatch` are
        // step-up policy refusals; `email_verification_not_allowed`
        // is OTP's "email channel is disabled" refusal. All fold
        // into `Forbidden` so UIs can branch on a single case.
        "forbidden",
        "auth_blocked",
        "scope_not_allowed",
        "not_configured",
        "direct_scope_identifier_mismatch",
        "email_verification_not_allowed",
        -> PreludeSessionError.Forbidden(message)
        "insufficient_scope" -> PreludeSessionError.InsufficientScope(message)
        "not_found" -> PreludeSessionError.NotFound(message)
        "conflict", "identifier_already_exists" -> PreludeSessionError.Conflict(message)
        else -> PreludeSessionError.Generic(code = apiError.code, displayMessage = message)
    }
}
