package so.prelude.android.auth

import kotlinx.coroutines.sync.withLock
import so.prelude.android.auth.http.ListSessionsResponse
import so.prelude.android.auth.http.SessionViewResponse
import java.time.Instant
import java.time.format.DateTimeParseException

/*
 * List + revoke surfaces for [PreludeAuthClient].
 *
 * Both routes are protected — DPoP-bound and bearer-authenticated —
 * so the request runs through `[autoRefreshInterceptor, dpopInterceptor]`
 * (auto-refresh outermost so a 401 driven by an expired access token
 * is recovered transparently; DPoP innermost so the proof signs the
 * final outgoing headers, including the refreshed bearer). Same
 * composition as `requestStepUp` / `changePassword` and the rest of
 * the protected surface.
 *
 * Local-state cleanup after a successful revoke mirrors the JS
 * sibling: a target that includes the calling session ([PreludeRevokeTarget.All],
 * [PreludeRevokeTarget.Mine], or [PreludeRevokeTarget.Session] whose
 * id matches the cached `sid`) wipes the per-domain stores and bumps
 * the session epoch, so a refresh racing the wipe surfaces as
 * [PreludeAuthError.Unauthorized] instead of resurrecting the
 * session the caller just revoked. The wipe runs *after* the server
 * round-trip — unlike `logout`, where pre-wiping is a security
 * property — because revoke is an explicit user action and a
 * transport failure should leave the caller able to retry without
 * having to log back in.
 *
 * Concurrent callers serialise on [PreludeAuthClient.revokeMutex]
 * rather than dedup-coalesce: targets vary, so two callers with
 * different intents must not share one round-trip's outcome. The
 * mutex prevents the wasted-double-request and double-wipe cases;
 * the second of two same-target callers may legitimately observe
 * `Unauthorized` once the first has already revoked the calling
 * session, which is the truthful answer and a UI concern to debounce.
 */

// MARK: - List

/**
 * Fetch a page of active sessions for the authenticated user.
 *
 * `GET /v1/session/me/list?limit=&offset=` — both query params are
 * omitted when [PreludeListSessionsOptions.limit] /
 * [PreludeListSessionsOptions.offset] are `null`, so the server picks
 * its own defaults. Deferring to the server here means a default
 * change lands without a client release.
 *
 * Throws the standard transport hierarchy
 * ([PreludeAuthError.Network], [PreludeAuthError.Timeout]),
 * [PreludeAuthError.Unauthorized] when the session is expired and
 * the auto-refresh interceptor cannot recover it, and
 * [PreludeAuthError.Generic] (`code = "decoding_failed"`) when a
 * timestamp in the response can't be parsed as ISO 8601 — see
 * [SessionViewResponse.toPublic] for why we fail the whole page
 * rather than dropping the bad entry.
 */
suspend fun PreludeAuthClient.listSessions(
    options: PreludeListSessionsOptions = PreludeListSessionsOptions(),
): PreludeListSessionsResponse {
    // `addQueryParameter` percent-encodes per RFC 3986, so callers
    // can't accidentally inject query-string structure via numeric
    // overflow text or future non-numeric option types.
    val url =
        sessionUrl("me/list")
            .apply {
                options.limit?.let { addQueryParameter("limit", it.toString()) }
                options.offset?.let { addQueryParameter("offset", it.toString()) }
            }.build()

    val request = buildSessionRequest(url, method = "GET").build()

    val (body, _) =
        httpClient.sendJson(
            request = request,
            deserializer = ListSessionsResponse.serializer(),
            interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
        )

    return PreludeListSessionsResponse(
        sessions = body.sessions.map { it.toPublic() },
        total = body.total,
        limit = body.limit,
        offset = body.offset,
    )
}

// MARK: - Revoke

/**
 * Revoke one or more sessions for the authenticated user.
 *
 * `POST /v1/session/me/revoke?target=&session_id=` — the
 * `session_id` query param is attached only for
 * [PreludeRevokeTarget.Session]; the type system enforces that the
 * id is provided when (and only when) the target needs one.
 *
 * On success and when [target] kills the calling session
 * ([PreludeRevokeTarget.All], [PreludeRevokeTarget.Mine], or a
 * [PreludeRevokeTarget.Session] whose id matches the cached `sid`)
 * the SDK drains any in-flight refresh, clears the per-domain stores
 * (DPoP key + nonce, refresh token, access-token cache) and bumps
 * [PreludeAuthClient.sessionEpoch] — so a refresh racing the wipe
 * surfaces as [PreludeAuthError.Unauthorized] instead of
 * resurrecting a session the caller just revoked. Order is
 * **drain → wipe → bump**, matching `logout`'s invariants for the
 * same reason: a refresh that started before the wipe captures the
 * pre-bump epoch and bails on its post-network check; one that
 * starts after the wipe reads empty stores and is rejected by the
 * server.
 *
 * Unlike `logout`, the wipe runs *after* the server round-trip
 * succeeds. Revoke is an explicit user action — a transport failure
 * should leave the caller able to retry without re-logging in. (For
 * `logout` the security argument runs the other way: wipe first so a
 * failed `/revoke` still leaves the device locally logged out.)
 *
 * Throws the standard transport / auth hierarchy
 * ([PreludeAuthError.Network], [PreludeAuthError.Timeout],
 * [PreludeAuthError.Unauthorized], [PreludeAuthError.RateLimited],
 * [PreludeAuthError.Forbidden]) and
 * [PreludeAuthError.Generic] for any other unmapped server code
 * (e.g. `not_found` for an unknown session id — the SDK does not
 * enumerate this separately today).
 */
suspend fun PreludeAuthClient.revokeSessions(target: PreludeRevokeTarget) =
    revokeMutex.withLock {
        // Capture `sid` BEFORE the round-trip so the wipe-and-bump
        // decision is a pure function of pre-call state. Reading after
        // the network call would be timing-sensitive: a concurrent
        // [invalidateCache] or an auto-refresh that rotated the cached
        // token between request build and response landing could shift
        // the cached `sid` and cause us to skip a wipe we should have
        // run (or vice versa). The pre-call snapshot is what the
        // server's just-revoked id would have matched against.
        val priorSessionId = getSessionId()

        val url =
            sessionUrl("me/revoke")
                .addQueryParameter("target", target.wireValue)
                .apply {
                    if (target is PreludeRevokeTarget.Session) {
                        addQueryParameter("session_id", target.sessionId)
                    }
                }.build()

        val request = buildSessionRequest(url).build()

        httpClient.sendExpectingNoBody(
            request = request,
            interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
        )

        if (revocationTouchesCurrentSession(target, priorSessionId)) {
            // Drain any in-flight refresh so the wipe doesn't race a
            // mid-rotation refresh writing tokens back into the stores
            // we're about to empty. Same drain rationale as `logout` —
            // see the file header in `PreludeAuthClient+Logout.kt`.
            inflightRefresh.joinIfRunning()
            // Capture (don't propagate) any wipe failure so the bump
            // below ALWAYS runs. A partial wipe still has to win the
            // snapshot-guard race against a concurrent `doRefresh` —
            // letting the throw skip the bump leaves a window where a
            // refresh whose snapshot matches the unbumped epoch passes
            // its post-network check and writes rotated tokens back
            // into the partially-emptied stores. Same precedence /
            // re-throw shape as `logout`.
            val wipeError: Throwable? =
                try {
                    clearAllStores()
                    null
                } catch (e: Throwable) {
                    e
                }
            // Bump AFTER the wipe so a refresh whose snapshot read
            // pre-wipe tokens captured the pre-bump epoch — its
            // post-network check sees the mismatch and bails before
            // persisting rotated tokens back into stores we just
            // emptied. Always runs, even on a partial wipe failure
            // (see capture above).
            sessionEpoch.getAndIncrement()
            // Re-throw so the caller sees the partial state and knows
            // to retry. The bump is already in place by the time this
            // unwinds.
            wipeError?.let { throw it }
        }
    }

// MARK: - Internals

/**
 * Whether [target] revokes the calling session — drives the
 * post-revoke wipe-and-bump above.
 *
 * `Session` matches [target]'s id against [priorSessionId], the `sid`
 * snapshot captured BEFORE the round-trip, so revoking a sibling
 * device leaves THIS client untouched. A null `priorSessionId` (e.g.
 * token cache cleared between calls) reads as "not us" and skips the
 * wipe — safer than wiping on a maybe-match.
 */
private fun revocationTouchesCurrentSession(
    target: PreludeRevokeTarget,
    priorSessionId: String?,
): Boolean =
    when (target) {
        PreludeRevokeTarget.All, PreludeRevokeTarget.Mine -> true
        PreludeRevokeTarget.Others -> false
        is PreludeRevokeTarget.Session -> priorSessionId != null && priorSessionId == target.sessionId
    }

/**
 * Map a wire entry to its public type.
 *
 * Timestamps are parsed with [Instant.parse] (ISO 8601 UTC). A bad
 * timestamp throws [DateTimeParseException], which we re-wrap as a
 * structured [PreludeAuthError.Generic] in [listSessions] — the
 * caller never sees a JDK exception.
 *
 * We deliberately fail the whole page rather than skipping the bad
 * entry: a session whose timestamps don't parse is more likely a
 * server contract drift than a one-off corruption, and a partial
 * page would mask the regression behind a "looks fine, just shorter"
 * UI symptom.
 */
private fun SessionViewResponse.toPublic(): PreludeSessionView =
    PreludeSessionView(
        id = id,
        deviceModel = deviceModel,
        deviceType = PreludeSessionDeviceType.fromWire(deviceType),
        osVersion = osVersion,
        countryCode = countryCode,
        createdAt = parseInstant(createdAt, "created_at"),
        lastSeenAt = parseInstant(lastSeenAt, "last_seen_at"),
        expiresAt = parseInstant(expiresAt, "expires_at"),
    )

/**
 * ISO 8601 → [Instant], surfacing parse failures as the SDK's
 * structured decode error so the caller never sees a JDK
 * [DateTimeParseException].
 *
 * [field] is included in the message so a future server contract
 * drift (e.g. a non-ISO 8601 timestamp on a single field) is
 * actionable instead of opaque.
 */
private fun parseInstant(
    value: String,
    field: String,
): Instant =
    try {
        Instant.parse(value)
    } catch (e: DateTimeParseException) {
        throw PreludeAuthError.Generic(
            code = "decoding_failed",
            displayMessage = "Failed to parse `$field` as ISO 8601: $value",
        )
    }
