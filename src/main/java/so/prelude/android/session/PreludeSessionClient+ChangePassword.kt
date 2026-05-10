package so.prelude.android.session

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.session.http.ChangePasswordRequestBody
import so.prelude.android.session.http.JSON_MEDIA_TYPE
import so.prelude.android.session.http.WIRE_JSON

/*
 * Change-password surface for [PreludeSessionClient].
 *
 * One public entry point ([changePassword]) that posts the new
 * password against the authenticated session, then drops the
 * session-local `prld:pwd:write` scope by draining any racing
 * refresh, invalidating the cache, and minting a replacement
 * access token through the in-flight slot.
 *
 * The endpoint requires `prld:pwd:write` — obtain it via
 * [requestStepUp] + [submitStepUpOTP]. Sessions without that scope
 * surface as [PreludeSessionError.InsufficientScope] and the local
 * cache is left untouched (the change didn't land, so the scope
 * isn't actually spent).
 *
 * Post-success bookkeeping uses the same drain-and-replace shape as
 * [refreshAfterStepUp]:
 *
 *   1. The server consumes `prld:pwd:write` on a successful reset.
 *      A vanilla `refresh()` racing in [PreludeSessionClient.inflightRefresh]
 *      could have been processed *before* the server consumed the
 *      scope and would mint a still-scoped access token. Piggybacking
 *      on it via [Inflight.runOrJoin] would land that scoped token
 *      in the cache and resurrect the leak the bookkeeping is
 *      supposed to prevent. We drain the slot, then install our own
 *      task so any sibling [refresh] caller arriving after install
 *      piggybacks on the scope-dropping result instead.
 *
 *   2. Inside the installed task, [invalidateCache] runs *before*
 *      [doRefresh] so any post-drain cache write the vanilla refresh
 *      left behind is clobbered before we mint. Same pattern as
 *      [refreshAfterStepUp], for the same reason.
 *
 *   3. Failures inside the replace block are *non-fatal*: the
 *      password change already succeeded, and the auto-refresh
 *      interceptor will re-run the same refresh on the next
 *      protected call. Cancellation propagates so structured
 *      concurrency stays correct.
 */

/**
 * Change the currently-authenticated user's password.
 *
 * Requires the session to carry `prld:pwd:write` — obtain it via
 * [requestStepUp] + [submitStepUpOTP]. Sessions without it surface
 * as [PreludeSessionError.InsufficientScope]. The scope is consumed by
 * the server on success, so a second [changePassword] without a
 * fresh step-up will fail with the same error.
 *
 * On success the SDK drains any in-flight refresh, invalidates the
 * cached access token, and mints a replacement through the in-flight
 * slot so the next mint drops the now-spent `prld:pwd:write` scope;
 * a leaked access token can therefore not change the password again
 * without re-stepping up. A thrown error means the change itself did
 * not land — the cache and refresh token are left as-is so the
 * original (still-scoped) bearer remains usable for a retry.
 *
 * The request runs through `[autoRefreshInterceptor, dpopInterceptor]`
 * (in that order — auto-refresh outermost so a 401-driven retry
 * re-signs with a fresh DPoP proof).
 *
 * The plaintext is wrapped in [RedactedString] so the caller's
 * stack frames and any structured logging can't accidentally leak
 * it. JVM `String`s can't be wiped, so the underlying bytes still
 * live on the heap until garbage collection — see [RedactedString]
 * for the full caveat.
 *
 * Throws on the request itself:
 *   - [PreludeSessionError.InsufficientScope] when the session lacks
 *     `prld:pwd:write`.
 *   - [PreludeSessionError.InvalidPassword] when the new password fails
 *     the server's policy.
 *   - [PreludeSessionError.BadRequest] when password auth is not
 *     configured / disabled for the app.
 *   - [PreludeSessionError.Forbidden] for `auth_blocked` and other
 *     policy denials.
 *   - [PreludeSessionError.Unauthorized] when the session is expired
 *     and the auto-refresh interceptor cannot recover it.
 *   - [PreludeSessionError.RateLimited] when the per-session bucket is
 *     exhausted.
 *   - [PreludeSessionError.Network] / [PreludeSessionError.Timeout] for
 *     transport failures.
 *   - [PreludeSessionError.InternalServerError] for 5xx.
 *   - [PreludeSessionError.Generic] for any other unmapped server code
 *     (e.g. `not_found` — the SDK does not enumerate this
 *     separately today).
 *
 * Post-success bookkeeping (drain → invalidate → refresh) is
 * best-effort: failures there do not propagate to the caller.
 */
suspend fun PreludeSessionClient.changePassword(newPassword: RedactedString) {
    val body = ChangePasswordRequestBody(password = newPassword.value)

    // Encode and attach in one chained expression so the only named
    // local holding the plaintext is `body` above; the encoded JSON
    // and the OkHttp `RequestBody` retain their own references for
    // the duration of the call. Same minimisation as
    // `loginWithPassword` — see that file for the JVM-specific
    // caveat (immutable `String`s can't be wiped).
    val request = buildSessionRequest("me/password/reset")
        .method("POST", WIRE_JSON.encodeToString(body).toRequestBody(JSON_MEDIA_TYPE))
        .build()

    // No DPoP on `/me/password/reset`: the server runs only the
    // bearer-checking authorization middleware on this route — the
    // access token + `prld:pwd:write` scope is the entire credential.
    // Sending a proof would be ignored at best; on strict proxies it
    // is dead weight that can short-circuit the request before the
    // server can return its real status. The auto-refresh path still
    // recovers a stale bearer: a 401 here triggers [refresh], which
    // signs `/refresh` with [dpopInterceptor] itself.
    //
    // Clear the step-up handle on every outcome via `finally`: the
    // request was driven by `prld:pwd:write` either way, and leaving
    // a stale challenge visible after a failed reset is no more
    // useful than after a successful one. Caller retries by re-
    // requesting step-up — the unscoped flow is the same.
    try {
        httpClient.sendExpectingNoBody(
            request = request,
            interceptors = listOf(autoRefreshInterceptor),
        )
    } finally {
        setActiveStepUp(null)
    }

    // Post-success only: drop `prld:pwd:write` locally so a leaked
    // access token can't change the password again without re-
    // stepping up. The server already consumed the scope on the
    // successful reset above; this ensures the SDK's local view
    // matches. Skipped on failure — the scope wasn't consumed
    // server-side, so the cache should keep reflecting that.
    dropConsumedScopeAfterChangePassword()
}

/**
 * Drain any in-flight refresh, then install a cache-invalidating
 * refresh in [PreludeSessionClient.inflightRefresh] so the next mint
 * drops the just-consumed `prld:pwd:write` scope.
 *
 * The drain is load-bearing for the security claim of this surface:
 * a vanilla [refresh] racing in the slot may have been processed
 * server-side *before* the password reset consumed the scope and
 * would return a still-scoped access token. Joining that result via
 * [Inflight.runOrJoin] would land the scoped token in the cache —
 * exactly the replay-leak the bookkeeping is supposed to prevent.
 * Uses the [Inflight.replace] shape `refreshAfterStepUp` already
 * uses for the symmetric "must drop a wrongly-scoped token" race.
 *
 * The cache invalidation runs *inside* the installed task so any
 * post-drain cache write the vanilla refresh left behind is clobbered
 * before we mint. Same ordering rationale as `refreshAfterStepUp`.
 *
 * Failures here are non-fatal: the password change itself already
 * succeeded and the API contract has been honoured. The next
 * protected call's [AutoRefreshInterceptor] will drive the same
 * refresh on a 401, so a transient hiccup self-heals on the next
 * authenticated request. Cancellation propagates verbatim so
 * structured concurrency stays correct — same cancellation
 * handling as [PreludeSessionClient.dispatchSignalsIfConfigured].
 *
 * Catches [Exception] (not [Throwable]) so JVM [Error] subclasses
 * (`OutOfMemoryError`, `LinkageError`, ...) keep their default
 * propagation. Private to this file: the precise sequencing
 * (drain → invalidate → mint, all inside one `replace`) is a
 * contract of this surface, not a general-purpose helper.
 */
private suspend fun PreludeSessionClient.dropConsumedScopeAfterChangePassword() {
    try {
        inflightRefresh.replace {
            invalidateCache()
            doRefresh()
        }
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        // Storage hiccup or refresh-side failure — non-fatal. The
        // password change already succeeded; the auto-refresh
        // interceptor will drive the same drop on the next
        // protected call.
    }
}
