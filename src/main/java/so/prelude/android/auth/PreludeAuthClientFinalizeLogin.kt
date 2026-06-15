package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.http.FinalizeLoginRequestBody
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.RefreshTokenResponse
import so.prelude.android.auth.http.WIRE_JSON
import so.prelude.android.auth.store.RefreshTokenRecord

/*
 * Shared finalize-login helper for [PreludeAuthClient].
 *
 * Every login surface (OTP, password, OAuth, migration, sign-up)
 * funnels through this single helper to exchange a challenge token
 * for an access token, persist the rotated refresh token, and return
 * the authenticated user. Lives in its own file because it is shared
 * across all login methods, not owned by any one of them.
 */

/**
 * Exchange a challenge token for an access token, persist the issued
 * refresh token, and return the authenticated user.
 *
 * Shared helper for every login surface (OTP today, more on the way).
 *
 * Persistence ordering matches refresh: rotated refresh token is
 * written **before** the access token, so a disk failure here doesn't
 * leave us with a fresh access token alongside a stale refresh on
 * disk.
 *
 * Logout-during-finalize race: the [PreludeAuthClient.sessionEpoch]
 * guard pairs with the one in [doRefresh]. Capture the epoch at entry,
 * then re-check after the network call and JWT decode but **before**
 * any store mutation — a [logout] that bumped the counter mid-flight
 * has already wiped the stores we'd be about to write to, and we
 * surface as [PreludeAuthError.Unauthorized] instead of resurrecting a
 * session the caller just revoked.
 *
 * @param codeVerifier PKCE verifier matching the `code_challenge`
 *   sent at the start of the flow; `null` when the flow didn't bind
 *   one.
 * @param startEpoch [PreludeAuthClient.sessionEpoch] observed when the
 *   surrounding flow began; defaults to capture at entry. Multi-hop
 *   flows ([migrate]) pass the value captured before their FIRST hop,
 *   so a logout that completes between the hops — invisible to a
 *   capture made here — still fails the re-check below.
 */
internal suspend fun PreludeAuthClient.finalizeLogin(
    challengeToken: String,
    codeVerifier: String? = null,
    // Epoch guard: captured before the network call, re-checked before
    // any store mutation. Pairs with the bump inside `logout()`.
    startEpoch: Long = sessionEpoch.get(),
): PreludeUser {
    // Carry over a refresh token from a previous session, if any, so the
    // server can revoke that session once the new one is established and
    // avoid leaving it dangling across a re-login. Captured before the
    // round-trip, since the response rotates the stored token below.
    val previousRefreshToken = refreshTokenStore.get(domain)?.refreshToken

    val finalizeBody =
        WIRE_JSON.encodeToString(
            FinalizeLoginRequestBody(
                challengeToken = challengeToken,
                codeVerifier = codeVerifier,
            ),
        )
    val requestBuilder =
        buildSessionRequest("login/finalize")
            .method("POST", finalizeBody.toRequestBody(JSON_MEDIA_TYPE))
    if (!previousRefreshToken.isNullOrEmpty()) {
        requestBuilder.header(HttpHeader.REFRESH_TOKEN, previousRefreshToken)
    }
    val request = requestBuilder.build()

    val (body, http) =
        httpClient.sendJson(
            request = request,
            deserializer = RefreshTokenResponse.serializer(),
            interceptors = listOf(dpopInterceptor),
        )

    if (body.accessToken.isEmpty()) {
        // 200 with an empty access token — defensive guard against a
        // backend regression. Surface as `Generic` (not `RefreshFailed`):
        // this isn't a refresh, and the auto-refresh interceptor isn't
        // on the chain to swallow it.
        throw PreludeAuthError.Generic(
            code = "missing_access_token",
            displayMessage = "login/finalize response did not include an access token",
        )
    }

    // Epoch guard: a [logout] that landed while /login/finalize was
    // in flight has already wiped the stores we're about to write.
    // Surface as `Unauthorized` so the caller treats it like a
    // revoked session rather than a successful login.
    if (sessionEpoch.get() != startEpoch) {
        throw PreludeAuthError.Unauthorized("session revoked during login")
    }

    // Persist the initial refresh token verbatim. `/login/finalize`
    // returns the rotated token via the `X-Refresh-Token` header, not
    // in the body — same shape as `/refresh`.
    val refreshToken = http.headers[HttpHeader.REFRESH_TOKEN]
    if (!refreshToken.isNullOrEmpty()) {
        val refreshExpiresAt = http.headers[HttpHeader.REFRESH_TOKEN_EXPIRES_AT]
        refreshTokenStore.set(
            domain = domain,
            record =
                RefreshTokenRecord(
                    refreshToken = refreshToken,
                    refreshTokenExpiresAt = refreshExpiresAt,
                ),
        )
    }

    // Decode-and-validate the new access token BEFORE persisting it.
    // Storing first would land a malformed JWT in the cache and the
    // next refresh()'s fast path would throw on it forever — same
    // stuck-state failure mode the doRefresh ordering guards against.
    //
    // The shared JWT decoder reuses [PreludeAuthError.InvalidChallengeToken]
    // for any malformed JWT, including the access token the server just
    // minted. Surfacing that name on a successful credential exchange
    // misattributes the failure (the *challenge* token was fine —
    // /otp/check accepted it and /login/finalize returned a 200), so
    // re-map to a structured access-token error. Defensive guard
    // against a backend regression; never expected to fire in practice.
    val user =
        try {
            makeUser(body.accessToken)
        } catch (_: PreludeAuthError.InvalidChallengeToken) {
            throw PreludeAuthError.Generic(
                code = "invalid_access_token",
                displayMessage = "login/finalize returned a malformed access token",
            )
        }

    storeAccessToken(
        accessToken = body.accessToken,
        serverExpiresAt = body.expiresAt,
        timeDiffSec = http.timeDiffSec,
    )

    return user
}
