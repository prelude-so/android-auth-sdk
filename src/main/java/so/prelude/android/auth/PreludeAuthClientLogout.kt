package so.prelude.android.auth

import kotlinx.coroutines.CancellationException
import okhttp3.Request
import so.prelude.android.auth.dpop.DPoPKey
import so.prelude.android.auth.dpop.createDPoPProof
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.http.dpopHtu

/*
 * Logout surface for [PreludeAuthClient].
 *
 * Concurrency invariants:
 *
 *   1. Wait for any in-flight refresh before snapshotting the refresh
 *      token, so `/revoke` signs itself with the post-rotation token
 *      instead of one the server has already retired. The drain runs
 *      inside the dedup block so coalesced callers piggyback on the
 *      elected caller's join.
 *
 *   2. Coalesce concurrent callers via [PreludeAuthClient.inflightLogout]
 *      so N parallel `logout()` calls produce one `/revoke` round-trip.
 *      Without dedup the second caller would hit "already revoked" and
 *      surface a spurious [PreludeAuthError.Unauthorized].
 *
 *   3. Order is **snapshot → wipe → bump → /revoke**. Bumping
 *      [PreludeAuthClient.sessionEpoch] AFTER the wipe is load-
 *      bearing for the resurrection guard: any refresh whose snapshot
 *      read pre-wipe tokens captured the pre-bump epoch, so its post-
 *      network check sees the mismatch and bails before persisting
 *      rotated tokens back into stores we just emptied. A refresh that
 *      starts after the wipe reads an empty store and is rejected by
 *      the server.
 *
 *   4. Wipe local state BEFORE the `/revoke` round-trip. A failed
 *      server call therefore still leaves the client locally logged
 *      out — the stores are already empty.
 *
 *   5. Best-effort wipe: every store delete is attempted regardless of
 *      earlier failures, then the first captured error is re-thrown
 *      after `/revoke` so callers know local state is partial. The
 *      wipe error wins over a `/revoke` failure: a stale credential
 *      left on a (potentially compromised) device is more dangerous
 *      than a server session the server's TTL eventually clears, and
 *      silencing the wipe error would also hide the partial state from
 *      the caller, who would then have no signal that a retry is
 *      needed.
 */

/**
 * Revoke the current session on the server and wipe every
 * domain-scoped credential this client owns.
 *
 * Local state is wiped *before* `POST /revoke` fires. A failed server
 * round-trip therefore still leaves the client locally logged out, and
 * a concurrent [refresh] can't resurrect the session after this
 * returns — the stores it would need to write into are already empty.
 *
 * Concurrent callers share a single round-trip via
 * [PreludeAuthClient.inflightLogout]. The first caller does the
 * work; any others arriving before it completes join the same task and
 * observe the same outcome (success or thrown error).
 *
 * Errors propagate from two sources, with the **wipe error winning
 * over the `/revoke` error** when both occur:
 *
 *   - `TokenStoreError` / `DPoPKeyStoreError` from the local
 *     wipe — surfaces a partial-state so the caller can retry.
 *   - The standard HTTP error hierarchy (e.g. [PreludeAuthError.Network],
 *     [PreludeAuthError.Timeout], [PreludeAuthError.Unauthorized] for
 *     an already-revoked session) from `/revoke`.
 *
 * No-op on the network side when the client has no DPoP key or refresh
 * token — there's nothing to revoke against. The local wipe still runs.
 */
suspend fun PreludeAuthClient.logout() {
    // Coalesce concurrent callers onto one round-trip. Drain, snapshot,
    // wipe, bump, and `/revoke` all live inside the dedup block so
    // coalesced callers piggyback on the elected caller's work.
    inflightLogout.runOrJoin {
        // Drain any in-flight refresh so the snapshot below reads the
        // rotated token: `/revoke` with a spent one is rejected.
        inflightRefresh.joinIfRunning()
        doLogout()
    }
}

/**
 * Snapshot, wipe, bump epoch, then `/revoke`. Internal so the public
 * [logout] entry point can wrap us in dedup bookkeeping without that
 * concern leaking into the I/O sequence itself.
 *
 * Order is **snapshot → wipe → bump → /revoke** — see invariant (3) in
 * the file header.
 */
private suspend fun PreludeAuthClient.doLogout() {
    // Snapshot before the wipe: `/revoke` must sign with the session's
    // pinned DPoP keypair, but [DPoPInterceptor] would `getOrCreate`
    // against the now-empty store and mint a proof whose `jkt` doesn't
    // match the one the server pinned at login. The reads use
    // `runCatching` so a corrupted entry can't abort the wipe below.
    val dpopKey: DPoPKey? =
        runCatching { keyStore.get(domain) }
            .rethrowingCancellation()
            .getOrNull()
    val dpopNonce: String? =
        runCatching { keyStore.getNonce(domain) }
            .rethrowingCancellation()
            .getOrNull()
    val dpopSkewMs: Long =
        runCatching { keyStore.getClockSkewMs(domain) }
            .rethrowingCancellation()
            .getOrNull() ?: 0L
    val refreshToken: String? =
        runCatching {
            refreshTokenStore.get(domain)?.refreshToken
        }.rethrowingCancellation().getOrNull()

    // Wipe; capture (don't throw) any error so a partial failure
    // doesn't abandon the server session. The wipe error is re-surfaced
    // below — see the precedence rules in the file header — but only
    // after `/revoke` has had its chance to fire.
    val wipeError: Throwable? =
        try {
            clearAllStores()
            null
        } catch (e: Throwable) {
            e
        }

    // Bump AFTER the wipe — see invariant (3). A pre-wipe bump leaves a
    // window where a refresh starting between the bump and the wipe
    // captures the post-bump epoch, reads pre-wipe tokens, passes its
    // post-network check, and resurrects the session.
    sessionEpoch.getAndIncrement()

    // No credentials on file — there's nothing to revoke against, so
    // skip the round-trip and surface any wipe error if one occurred.
    if (dpopKey == null || refreshToken.isNullOrEmpty()) {
        wipeError?.let { throw it }
        return
    }

    // Build the `/revoke` request, signing the DPoP proof inline. A
    // signing failure is unrecoverable without the original DPoP private
    // key, so degrade to skipping `/revoke`: the local wipe already ran
    // and the server session expires on its own via TTL.
    val request =
        runCatching {
            buildRevokeRequest(dpopKey, dpopNonce, dpopSkewMs, refreshToken)
        }.rethrowingCancellation().getOrNull()
            ?: run {
                wipeError?.let { throw it }
                return
            }

    // Send `/revoke` and capture (don't throw) any failure: the wipe
    // error wins over it — see invariant (5) in the file header.
    val revokeError =
        runCatching {
            httpClient.sendExpectingNoBody(request)
        }.rethrowingCancellation().exceptionOrNull()

    wipeError?.let { throw it }
    revokeError?.let { throw it }
}

/**
 * Build the `POST /v1/session/revoke` request, signed inline against
 * the snapshotted DPoP key and nonce. Bypasses [DPoPInterceptor]
 * because by the time we get here the keystore is empty, and the
 * interceptor would mint a fresh keypair whose `jkt` doesn't match the
 * one the server pinned at login.
 */
private fun PreludeAuthClient.buildRevokeRequest(
    dpopKey: DPoPKey,
    dpopNonce: String?,
    dpopSkewMs: Long,
    refreshToken: String,
): Request {
    val request =
        buildSessionRequest("revoke")
            .header(HttpHeader.REFRESH_TOKEN, refreshToken)
            .build()

    val proof =
        createDPoPProof(
            key = dpopKey,
            method = request.method,
            url = dpopHtu(request, hostOverride),
            nonce = dpopNonce,
            clockSkewMs = dpopSkewMs,
        )
    return request.newBuilder().header(HttpHeader.DPOP, proof).build()
}

/**
 * `runCatching` catches every [Throwable] — including
 * [CancellationException] — so chaining straight to [Result.getOrNull]
 * (or [Result.exceptionOrNull]) silently eats cooperative cancellation
 * and lets a cancelled coroutine carry on past the catch. This rethrows
 * [CancellationException] before the terminal accessor runs.
 *
 * Returns the [Result] unchanged on success or any non-cancellation
 * failure so callers can chain their preferred accessor.
 */
private fun <T> Result<T>.rethrowingCancellation(): Result<T> = onFailure { if (it is CancellationException) throw it }

/**
 * Delete every domain-scoped credential this client owns: DPoP
 * keypair, DPoP nonce, refresh token, access-token cache.
 *
 * Best-effort — every delete is attempted regardless of earlier
 * failures, then the first captured error is re-thrown. Keeping all
 * four deletes on the same code path means a partial wipe is the worst
 * case rather than an "early throw skipped the cache delete"
 * pathological state.
 *
 * Internal so [logout] can call it; not part of the public surface.
 */
internal fun PreludeAuthClient.clearAllStores() {
    var firstError: Throwable? = null

    fun attempt(body: () -> Unit) {
        try {
            body()
        } catch (e: Throwable) {
            if (firstError == null) firstError = e
        }
    }

    // [AndroidKeystoreStore.delete] also wipes the per-domain nonce and
    // clock skew, but a failing keystore op would skip that; the explicit
    // deletes below are no-ops on the success path.
    attempt { keyStore.delete(domain) }
    attempt { keyStore.deleteNonce(domain) }
    attempt { keyStore.deleteClockSkewMs(domain) }
    attempt { refreshTokenStore.delete(domain) }
    attempt { accessTokenCache.clear(domain) }
    // Wipe per-host cookies: the jar buckets by request URL host, which
    // diverges from [domain] whenever `hostOverride` is set. Without this,
    // the next login would see markers from the revoked session.
    attempt { httpClient.cookieJar?.clear(baseUrl.host.lowercase()) }
    // In-memory step-up handle, not a store — `AtomicReference.set`
    // can't throw, so it lives outside `attempt`. Logically part of
    // the wipe: a stale challenge that survives logout would let a
    // post-logout observer believe a flow is still in progress.
    setActiveStepUp(null)

    firstError?.let { throw it }
}
