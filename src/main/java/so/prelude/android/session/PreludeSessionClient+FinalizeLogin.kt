package so.prelude.android.session

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.session.http.FinalizeLoginRequestBody
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.http.JSON_MEDIA_TYPE
import so.prelude.android.session.http.RefreshTokenResponse
import so.prelude.android.session.http.WIRE_JSON
import so.prelude.android.session.store.RefreshTokenRecord

/*
 * Shared finalize-login helper for [PreludeSessionClient].
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
 * Logout-during-finalize race: the [PreludeSessionClient.sessionEpoch]
 * guard pairs with the one in [doRefresh]. Capture the epoch at entry,
 * then re-check after the network call and JWT decode but **before**
 * any store mutation — a [logout] that bumped the counter mid-flight
 * has already wiped the stores we'd be about to write to, and we
 * surface as [PreludeSessionError.Unauthorized] instead of resurrecting a
 * session the caller just revoked.
 */
internal suspend fun PreludeSessionClient.finalizeLogin(challengeToken: String): PreludeUser {
    // Epoch guard: capture before the network call, re-check before
    // any store mutation. Pairs with the bump inside `logout()`.
    val startEpoch = sessionEpoch.get()

    val finalizeBody = WIRE_JSON.encodeToString(
        FinalizeLoginRequestBody(challengeToken = challengeToken),
    )
    val request = buildSessionRequest("login/finalize")
        .method("POST", finalizeBody.toRequestBody(JSON_MEDIA_TYPE))
        .build()

    val (body, http) = httpClient.sendJson(
        request = request,
        deserializer = RefreshTokenResponse.serializer(),
        interceptors = listOf(dpopInterceptor),
    )

    if (body.accessToken.isEmpty()) {
        // 200 with an empty access token — defensive guard against a
        // backend regression. Surface as `Generic` (not `RefreshFailed`):
        // this isn't a refresh, and the auto-refresh interceptor isn't
        // on the chain to swallow it.
        throw PreludeSessionError.Generic(
            code = "missing_access_token",
            displayMessage = "login/finalize response did not include an access token",
        )
    }

    // Epoch guard: a [logout] that landed while /login/finalize was
    // in flight has already wiped the stores we're about to write.
    // Surface as `Unauthorized` so the caller treats it like a
    // revoked session rather than a successful login.
    if (sessionEpoch.get() != startEpoch) {
        throw PreludeSessionError.Unauthorized("session revoked during login")
    }

    // Persist the initial refresh token verbatim. `/login/finalize`
    // returns the rotated token via the `X-Refresh-Token` header, not
    // in the body — same shape as `/refresh`.
    val refreshToken = http.headers[HttpHeader.REFRESH_TOKEN]
    if (!refreshToken.isNullOrEmpty()) {
        val refreshExpiresAt = http.headers[HttpHeader.REFRESH_TOKEN_EXPIRES_AT]
        refreshTokenStore.set(
            domain = domain,
            record = RefreshTokenRecord(
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
    // The shared JWT decoder reuses [PreludeSessionError.InvalidChallengeToken]
    // for any malformed JWT, including the access token the server just
    // minted. Surfacing that name on a successful credential exchange
    // misattributes the failure (the *challenge* token was fine —
    // /otp/check accepted it and /login/finalize returned a 200), so
    // re-map to a structured access-token error. Defensive guard
    // against a backend regression; never expected to fire in practice.
    val user = try {
        makeUser(body.accessToken)
    } catch (_: PreludeSessionError.InvalidChallengeToken) {
        throw PreludeSessionError.Generic(
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
