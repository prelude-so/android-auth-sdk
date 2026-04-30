package so.prelude.android.session

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.session.http.ChallengeTokenResponse
import so.prelude.android.session.http.CheckOTPRequestBody
import so.prelude.android.session.http.JSON_MEDIA_TYPE
import so.prelude.android.session.http.StartOTPLoginRequestBody
import so.prelude.android.session.http.WIRE_JSON
import so.prelude.android.session.http.WireIdentifier

/*
 * OTP login surface for [PreludeSessionClient].
 *
 * Three public entry points plus one internal helper:
 *
 *   - [startOTPLogin]  — unauthenticated, no DPoP / no bearer; attaches
 *     a `dispatch_id` from [PreludeSignalsDispatcher] when configured.
 *   - [retryOTP]       — unauthenticated; asks the server to re-send
 *     the most recently issued OTP. No DPoP.
 *   - [checkOTP]       — DPoP-signed; submits the code, exchanges the
 *     resulting challenge token on `/login/finalize`, and returns the
 *     authenticated [PreludeUser]. The same `finalizeLogin` helper is
 *     reused across login surfaces.
 *
 * Contract: only [finalizeLogin] (post-login) and `refresh()` (post-
 * rotation) write to the refresh-token store. Other call sites that
 * happen to see `X-Refresh-Token` leave it alone — keeps the refresh-
 * token lifecycle (issued → rotated → revoked) reviewable in a single
 * place.
 */

/**
 * Start an OTP login by sending a one-time code to the recipient
 * named in [StartOTPLoginOptions.identifier].
 *
 * Unauthenticated: no DPoP proof, no bearer token. When the client was
 * constructed with a [PreludeSignalsDispatcher] the helper dispatches a
 * fresh signals envelope and attaches the resulting `dispatch_id` to
 * the request body.
 *
 * Throws [PreludeSessionError.BadRequest] for an invalid identifier
 * shape, [PreludeSessionError.RateLimited] when the dispatch bucket is
 * exhausted, and [PreludeSessionError.Forbidden] when the email
 * verification feature is disabled.
 */
suspend fun PreludeSessionClient.startOTPLogin(options: StartOTPLoginOptions) {
    val dispatchId = dispatchSignalsIfConfigured()

    val body = StartOTPLoginRequestBody(
        identifier = WireIdentifier(
            type = options.identifier.type.wireValue,
            value = options.identifier.value,
        ),
        loginConfigId = options.loginConfigId,
        dispatchId = dispatchId,
    )

    val request = buildSessionRequest("otp")
        .method("POST", WIRE_JSON.encodeToString(body).toRequestBody(JSON_MEDIA_TYPE))
        .build()

    httpClient.sendExpectingNoBody(request)
}

/**
 * Ask the server to re-send the most recently issued OTP.
 *
 * Unauthenticated and idempotent on the client; the server enforces
 * its own retry budget and returns [PreludeSessionError.RateLimited] when
 * exhausted.
 *
 * Deliberately does *not* dispatch a fresh signals envelope: the
 * server keys the resend off the channel opened by [startOTPLogin],
 * so a second `dispatch_id` would double-bill the rate-limit bucket
 * and provide no additional anti-fraud coverage.
 */
suspend fun PreludeSessionClient.retryOTP() {
    val request = buildSessionRequest("otp/retry").build()
    httpClient.sendExpectingNoBody(request)
}

/**
 * Submit an OTP [code] to complete the login flow.
 *
 * Two-step credential exchange:
 *
 *   1. `POST /otp/check` returns a short-lived single-use
 *      `challenge_token` (DPoP-signed so the server can bind the
 *      challenge to this device's keypair).
 *   2. [finalizeLogin] exchanges the challenge on `/login/finalize`
 *      for the access + refresh token (also DPoP-signed).
 *
 * Both hops route through the [DPoPInterceptor]; neither attaches the
 * [AutoRefreshInterceptor] — there's no bearer to refresh until
 * `/login/finalize` returns one.
 *
 * Throws [PreludeSessionError.InvalidOTPCode] for a wrong / expired code,
 * [PreludeSessionError.MissingChallengeToken] when `/otp/check` returns
 * a 200 without the expected token (defensive — the server contract
 * promises one), and [PreludeSessionError.InvalidChallengeToken] when
 * the issued token is malformed.
 */
suspend fun PreludeSessionClient.checkOTP(code: String): PreludeUser {
    val checkBody = WIRE_JSON.encodeToString(CheckOTPRequestBody(code = code))
    val request = buildSessionRequest("otp/check")
        .method("POST", checkBody.toRequestBody(JSON_MEDIA_TYPE))
        .build()

    val (response, _) = httpClient.sendJson(
        request = request,
        deserializer = ChallengeTokenResponse.serializer(),
        interceptors = listOf(dpopInterceptor),
    )

    val challengeToken = response.challengeToken
    if (challengeToken.isNullOrEmpty()) {
        // The server contract promises a `challenge_token` on a 200
        // /otp/check response; surfacing a structured error here makes
        // a backend regression actionable instead of opaque.
        throw PreludeSessionError.MissingChallengeToken(
            "Missing challenge token from OTP check response",
        )
    }

    return finalizeLogin(challengeToken)
}
