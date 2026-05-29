package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.http.ChallengeTokenResponse
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.LoginWithPasswordRequestBody
import so.prelude.android.auth.http.WIRE_JSON

/*
 * Password login surface for [PreludeAuthClient].
 *
 * Single public entry point that delegates to the shared
 * [finalizeLogin] helper — no new internal machinery, just a different
 * first hop.
 *
 * Contract: only [finalizeLogin] (post-login) and `refresh()` (post-
 * rotation) write to the refresh-token store. Keeping the refresh-
 * token lifecycle (issued → rotated → revoked) reviewable in a single
 * place is worth the extra plumbing on every login surface.
 */

/**
 * Log in with an email identifier and a password.
 *
 * Two-step credential exchange — same shape as OTP, different first
 * hop:
 *
 *   1. `POST /login/email/password` (unauthenticated, no DPoP) returns
 *      a short-lived single-use `challenge_token`.
 *   2. [finalizeLogin] exchanges the challenge on `/login/finalize`
 *      (DPoP-signed) for the access + refresh token.
 *
 * The first hop is intentionally unauthenticated: the device has no
 * keypair bound to a session yet, so requiring DPoP would create a
 * chicken-and-egg problem on every fresh install. The second hop
 * runs through [DPoPInterceptor] so the access + refresh token are
 * bound to the device's keypair from the moment they're minted.
 *
 * When a [PreludeSignalsDispatcher] is configured, the helper dispatches
 * a fresh signals envelope and attaches the resulting `dispatch_id`
 * to the request body. Dispatcher failures are swallowed and logged;
 * the login proceeds without `dispatch_id` so anti-fraud coverage
 * degrades gracefully rather than blocking authentication.
 *
 * Distinguishes [PreludeAuthError.InvalidPassword] (the password
 * failed the server's policy — fix is a stronger password) from
 * [PreludeAuthError.Unauthorized] (bad credentials — fix is a
 * different password) so callers can branch on the recovery path,
 * and surfaces [PreludeAuthError.MissingChallengeToken] when
 * `/login/email/password` returns a 200 without the expected token
 * (defensive — the server contract promises one). Any other error
 * the HTTP layer can return propagates verbatim — most commonly
 * [PreludeAuthError.BadRequest] for an invalid email shape,
 * [PreludeAuthError.RateLimited] when the login bucket is exhausted,
 * [PreludeAuthError.Forbidden] for `auth_blocked`, and
 * [PreludeAuthError.InvalidChallengeToken] from the `/login/finalize`
 * hop. Network failures surface as [PreludeAuthError.Network] /
 * [PreludeAuthError.Timeout]; unmapped server codes as
 * [PreludeAuthError.Generic].
 *
 * The SDK never persists the password. It is unwrapped from
 * [RedactedString] only to be encoded into the request body, but
 * note that on the JVM that plaintext lives, in practice, in
 * several immutable [String] copies (the unwrapped value, the
 * encoded JSON, and inside the OkHttp request body) until garbage
 * collection — there's no reliable wipe. The wrapper protects
 * against accidental [toString] / `Log.d` leakage; it does not
 * make the plaintext unobservable on a live heap.
 *
 * Logout-during-finalize races are handled by the
 * [PreludeAuthClient.sessionEpoch] guard inside [finalizeLogin]:
 * a concurrent [logout] that bumps the counter mid-call surfaces as
 * [PreludeAuthError.Unauthorized] instead of resurrecting the session
 * the caller just revoked.
 */
suspend fun PreludeAuthClient.loginWithPassword(options: LoginWithPasswordOptions): PreludeUser {
    val dispatchId = dispatchSignalsIfConfigured()

    val body =
        LoginWithPasswordRequestBody(
            identifier = options.identifier,
            password = options.password.value,
            dispatchId = dispatchId,
        )

    // Encode and attach in one chained expression so the only named
    // local holding the plaintext is `body` above; the encoded JSON
    // and the OkHttp `RequestBody` retain their own references for
    // the duration of the call. JVM `String`s can't be wiped, so
    // this isn't a security boundary — it's a "minimise the named
    // references a future contributor could accidentally log"
    // boundary.
    val request =
        buildSessionRequest("login/email/password")
            .method("POST", WIRE_JSON.encodeToString(body).toRequestBody(JSON_MEDIA_TYPE))
            .build()

    val (response, _) =
        httpClient.sendJson(
            request = request,
            deserializer = ChallengeTokenResponse.serializer(),
            // Unauthenticated endpoint — no DPoP, no bearer. The DPoP
            // interceptor would happily mint a proof here, but the server
            // doesn't expect one and signing with a key the user hasn't
            // bound to a session yet leaks the device's `jkt` into the
            // anti-fraud audit log against an unauthenticated identity.
            interceptors = emptyList(),
        )

    val challengeToken = response.challengeToken
    if (challengeToken.isNullOrEmpty()) {
        // Server contract promises a `challenge_token` on a 200
        // response; surfacing a structured error makes a backend
        // regression actionable instead of opaque.
        throw PreludeAuthError.MissingChallengeToken(
            "Missing challenge token from password login response",
        )
    }

    return finalizeLogin(challengeToken)
}
