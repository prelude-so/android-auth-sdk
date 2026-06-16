package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.crypto.Pkce
import so.prelude.android.auth.http.ChallengeTokenResponse
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.MigrateRequestBody
import so.prelude.android.auth.http.WIRE_JSON

/*
 * Migration surface for [PreludeAuthClient]: exchange a legacy
 * bearer token for a Prelude session.
 */

/**
 * Exchange a legacy bearer token for a Prelude session.
 *
 * Two-step credential exchange:
 *
 *   1. `POST /migration` validates the legacy token and returns a
 *      short-lived, single-use `challenge_token`. Unauthenticated —
 *      the legacy token in the body is the entire credential.
 *   2. `POST /login/finalize` (DPoP-signed) redeems the challenge
 *      together with the PKCE `code_verifier`, binding the issued
 *      access and refresh tokens to this device's key.
 *
 * Safe to call on every launch: a valid cached session returns
 * immediately without spending the legacy token, and concurrent
 * callers share a single in-flight exchange. The exchange is not
 * abandoned when an awaiting caller is cancelled.
 *
 * When the client was constructed with a
 * [so.prelude.android.auth.signals.PreludeSignalsDispatcher], a
 * `dispatch_id` is attached to the request; dispatcher failures are
 * logged and ignored so they never block the migration.
 *
 * A [logout] racing the exchange wins: persistence is aborted and
 * the migration surfaces as [PreludeAuthError.Unauthorized].
 *
 * Throws [PreludeAuthError.BadRequest] when migration is not
 * configured for the app or the legacy token is rejected,
 * [PreludeAuthError.MissingChallengeToken] when the server omits the
 * promised challenge token, and [PreludeAuthError.TokenReused] when
 * the challenge was already redeemed. Network failures surface as
 * [PreludeAuthError.Network] or [PreludeAuthError.Timeout].
 */
suspend fun PreludeAuthClient.migrate(options: MigrateOptions): PreludeUser {
    // Already migrated: return the cached session without spending
    // the legacy token again.
    accessTokenCache.get(domain)?.let { return makeUserForMigrate(it.accessToken) }

    return inflightMigrate.runOrJoin(
        // Re-checked under the slot's lock: a caller that just
        // finished may have populated the cache while we queued.
        precheck = { accessTokenCache.get(domain)?.let { makeUserForMigrate(it.accessToken) } },
        block = { doMigrate(options.token.value) },
    )
}

private suspend fun PreludeAuthClient.doMigrate(token: String): PreludeUser {
    // Nothing is persisted mid-flow; an app killed here simply
    // re-runs the migration on next launch.
    //
    // Epoch guard: captured before the FIRST hop and threaded into
    // [finalizeLogin]'s pre-persist re-check. A capture at finalize
    // entry would miss a logout that completes between the hops, and
    // this task outlives a cancelled caller — it would persist a
    // fresh session after that logout returned.
    val startEpoch = sessionEpoch.get()
    val codeVerifier = Pkce.generateCodeVerifier()
    val dispatchId = dispatchSignalsIfConfigured()

    val body =
        MigrateRequestBody(
            token = token,
            codeChallenge = Pkce.codeChallenge(codeVerifier),
            dispatchId = dispatchId,
        )

    val request =
        buildSessionRequest("migration")
            .method("POST", WIRE_JSON.encodeToString(body).toRequestBody(JSON_MEDIA_TYPE))
            .build()

    val (response, _) =
        httpClient.sendJson(
            request = request,
            deserializer = ChallengeTokenResponse.serializer(),
            // Unauthenticated: no session key exists yet to bind a
            // DPoP proof to.
            interceptors = emptyList(),
        )

    val challengeToken = response.challengeToken
    if (challengeToken.isNullOrEmpty()) {
        // The server promises a challenge token on a 200 response;
        // a structured error makes a regression actionable.
        throw PreludeAuthError.MissingChallengeToken(
            "Missing challenge token from migration response",
        )
    }

    return finalizeLogin(challengeToken, codeVerifier, startEpoch)
}

/**
 * Decode a cached access token. A malformed token would surface from
 * the JWT decoder as [PreludeAuthError.InvalidChallengeToken]; re-map
 * it, since no challenge token is involved here.
 */
private fun PreludeAuthClient.makeUserForMigrate(accessToken: String): PreludeUser =
    try {
        makeUser(accessToken)
    } catch (_: PreludeAuthError.InvalidChallengeToken) {
        throw PreludeAuthError.Generic(
            code = "invalid_access_token",
            displayMessage = "cached access token is malformed",
        )
    }
