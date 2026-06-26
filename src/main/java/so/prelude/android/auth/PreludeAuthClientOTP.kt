package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.http.ChallengeTokenResponse
import so.prelude.android.auth.http.CheckOTPRequestBody
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.SendOTPRequestBody
import so.prelude.android.auth.http.StartOTPLoginRequestBody
import so.prelude.android.auth.http.WIRE_JSON
import so.prelude.android.auth.http.WireIdentifier

/*
 * OTP login surface for [PreludeAuthClient].
 *
 * Three public entry points plus the internal [sendOTP] helper:
 *
 *   - [startOTPLogin]  — unauthenticated, no DPoP / no bearer; attaches
 *     a `dispatch_id` from [PreludeSignalsDispatcher] when configured.
 *   - [resendOTP]       — unauthenticated; asks the server to re-send
 *     the most recently issued OTP. No DPoP.
 *   - [checkOTP]       — unauthenticated. The OTP code in the body is
 *     the entire credential; no session key exists yet, so a DPoP
 *     proof has nothing legitimate to bind to. The device-to-token
 *     binding happens one step later,on `/login/finalize`, which
 *     [finalizeLogin] handles.
 *   - [sendOTP]        — internal; fires `POST /otp` for an in-flight
 *     challenge token. No DPoP.
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
 * Throws [PreludeAuthError.BadRequest] for an invalid identifier
 * shape, [PreludeAuthError.RateLimited] when the dispatch bucket is
 * exhausted, and [PreludeAuthError.Forbidden] when the email
 * verification feature is disabled.
 */
suspend fun PreludeAuthClient.startOTPLogin(options: StartOTPLoginOptions) {
    val dispatchId = dispatchSignalsIfConfigured()

    val body =
        StartOTPLoginRequestBody(
            identifier =
                WireIdentifier(
                    type = options.identifier.type.wireValue,
                    value = options.identifier.value,
                ),
            loginConfigId = options.loginConfigId,
            dispatchId = dispatchId,
        )

    val request =
        buildSessionRequest("otp")
            .method("POST", WIRE_JSON.encodeToString(body).toRequestBody(JSON_MEDIA_TYPE))
            .build()

    httpClient.sendExpectingNoBody(request)
}

/**
 * Ask the server to re-send the most recently issued OTP.
 *
 * Unauthenticated and idempotent on the client; the server enforces
 * its own retry budget and returns [PreludeAuthError.RateLimited] when
 * exhausted.
 *
 * Deliberately does *not* dispatch a fresh signals envelope: the
 * server keys the resend off the channel opened by [startOTPLogin],
 * so a second `dispatch_id` would double-bill the rate-limit bucket
 * and provide no additional anti-fraud coverage.
 */
suspend fun PreludeAuthClient.resendOTP() {
    val request = buildSessionRequest("otp/retry").build()
    httpClient.sendExpectingNoBody(request)
}

/**
 * Submit an OTP [code] to complete the login flow.
 *
 * Two-step credential exchange:
 *
 *   1. `POST /otp/check` — unauthenticated. The OTP code is the
 *      whole credential; no DPoP proof is attached because no
 *      session key exists yet to bind one to. Returns a short-lived
 *      single-use `challenge_token`.
 *   2. [finalizeLogin] exchanges the challenge on `/login/finalize`
 *      for the access + refresh token. That hop **is** DPoP-signed
 *      — it's where the issued tokens get bound to the device key.
 *
 * Throws [PreludeAuthError.InvalidOTPCode] for a wrong / expired code,
 * [PreludeAuthError.MissingChallengeToken] when `/otp/check` returns
 * a 200 without the expected token (defensive — the server contract
 * promises one), and [PreludeAuthError.InvalidChallengeToken] when
 * the issued token is malformed.
 */
suspend fun PreludeAuthClient.checkOTP(code: String): PreludeUser {
    // Plain login: the cookie set by `/otp` resolves the flow, so no
    // verification token is replayed.
    return finalizeOTPCheck(code = code, verificationToken = null)
}

/**
 * Submit an OTP [code] to `/otp/check` and exchange the returned
 * challenge token for a session.
 *
 * [verificationToken], when set, is replayed as the
 * `X-Verification-Token` header to resume a session-less flow; a plain
 * login leaves it null. Unauthenticated either way: the code in the
 * body is the whole credential, so no DPoP — the device-to-token
 * binding happens one step later, on `/login/finalize`.
 */
internal suspend fun PreludeAuthClient.finalizeOTPCheck(
    code: String,
    verificationToken: String?,
): PreludeUser {
    val checkBody = WIRE_JSON.encodeToString(CheckOTPRequestBody(code = code))
    val builder =
        buildSessionRequest("otp/check")
            .method("POST", checkBody.toRequestBody(JSON_MEDIA_TYPE))
    if (!verificationToken.isNullOrEmpty()) {
        builder.header(HttpHeader.VERIFICATION_TOKEN, verificationToken)
    }

    val (response, _) =
        httpClient.sendJson(
            request = builder.build(),
            deserializer = ChallengeTokenResponse.serializer(),
        )

    val challengeToken = response.challengeToken
    if (challengeToken.isNullOrEmpty()) {
        // The server contract promises a `challenge_token` on a 200
        // /otp/check response; surfacing a structured error here makes
        // a backend regression actionable instead of opaque.
        throw PreludeAuthError.MissingChallengeToken(
            "Missing challenge token from OTP check response",
        )
    }

    return finalizeLogin(challengeToken)
}

/**
 * Trigger OTP delivery (`POST /otp`) for an in-flight challenge.
 *
 * Unauthenticated: the challenge token in the body identifies the
 * caller and carries its PKCE binding, so no DPoP. A configured
 * [PreludeSignalsDispatcher] attaches a fresh `dispatch_id`.
 *
 * Returns the issued `X-Verification-Token`, if any, so a session-less
 * flow can replay it on `/otp/check` instead of relying on a cookie.
 */
internal suspend fun PreludeAuthClient.sendOTP(challengeToken: String): String? {
    val dispatchId = dispatchSignalsIfConfigured()
    val payload =
        WIRE_JSON.encodeToString(
            SendOTPRequestBody(challengeToken = challengeToken, dispatchId = dispatchId),
        )
    val request =
        buildSessionRequest("otp")
            .method("POST", payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()
    val response = httpClient.perform(request)
    httpClient.throwIfNonSuccess(response)
    return response.headers[HttpHeader.VERIFICATION_TOKEN]
}
