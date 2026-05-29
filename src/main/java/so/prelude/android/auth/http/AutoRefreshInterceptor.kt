package so.prelude.android.auth.http

import kotlinx.coroutines.CancellationException
import okhttp3.Request
import okhttp3.Response

/**
 * Attaches `Authorization: Bearer <access token>` to every request
 * and transparently recovers from 401 responses: invalidate the
 * cached token, refresh, and retry once.
 *
 * Compose first in the chain (outermost) so the bearer is attached
 * before DPoP signs the request and harvests its nonce — DPoP must
 * see the final outgoing headers.
 *
 * If the refresh itself fails the interceptor returns the
 * **original** 401 (never the retry response, never a thrown
 * error). Throwing here would bubble into outer retry loops,
 * which would then loop forever on what is fundamentally a
 * non-transient auth failure. The retry's own errors are *not*
 * caught: a network blip on the retry of a now-authenticated
 * request should propagate so the caller can distinguish
 * transport from auth.
 *
 * Dependencies are injected as suspend lambdas. The owning
 * [so.prelude.android.auth.PreludeAuthClient] supplies
 * closures that route through the in-flight refresh dedup so the
 * single-use refresh token is never spent twice.
 *
 * @param getAccessToken returns the cached token verbatim,
 *   ignoring expiration (server is the authority). Returns the
 *   empty string when none is cached — the resulting
 *   `Authorization: Bearer ` correctly elicits a 401 and triggers
 *   the refresh path below.
 * @param invalidateCache marks the cached token stale after a 401
 *   so other code paths stop handing out the bad token. Allowed
 *   to throw — a real storage failure here is more important than
 *   a stale 401.
 * @param refreshSession performs the refresh round-trip and
 *   returns the new access token. May throw on any refresh-side
 *   failure; the interceptor swallows it and returns the original
 *   401 to the caller.
 */
internal class AutoRefreshInterceptor(
    private val getAccessToken: suspend () -> String,
    private val invalidateCache: suspend () -> Unit,
    private val refreshSession: suspend () -> String,
) : PreludeInterceptor {
    override suspend fun intercept(
        request: Request,
        next: SendFunction,
    ): Response {
        val sentToken = getAccessToken()
        val response = next(request.withBearer(sentToken))

        if (response.code != 401) return response

        // A sibling caller may have refreshed while our 401 was
        // in flight. If the cache now holds a different token,
        // skip invalidate+refresh — `invalidateCache` would
        // re-expire the fresh entry and force a redundant
        // /refresh round-trip.
        val fresh = getAccessToken()
        if (fresh.isNotEmpty() && fresh != sentToken) {
            response.close()
            return next(request.withBearer(fresh))
        }

        try {
            invalidateCache()
        } catch (e: Throwable) {
            // Storage failure during invalidate is not something we can
            // recover from inline — the contract is that it propagates.
            // Before throwing out, close the 401 so its connection goes
            // back to OkHttp's pool now rather than waiting for the
            // body's finalizer. `Throwable` (not `Exception`) so
            // cancellation also closes; we re-throw verbatim, so
            // cooperative cancellation still propagates.
            response.close()
            throw e
        }

        val newToken =
            try {
                refreshSession()
            } catch (e: CancellationException) {
                // Cooperative cancellation must propagate; otherwise structured
                // concurrency breaks (parent coroutines hang waiting for an
                // already-cancelled child). Closing the response keeps the
                // OkHttp connection from being orphaned mid-cancel.
                response.close()
                throw e
            } catch (_: Exception) {
                // Refresh itself failed — return the ORIGINAL 401 so upstream
                // retry loops treat auth as non-transient. Crucially we do NOT
                // wrap the retry below in this catch: a transient network error
                // on the retry of a now-authenticated request must propagate
                // so the caller can distinguish auth issues from transport.
                //
                // `Exception` (not `Throwable`) so JVM-level `Error` subtypes
                // (`OutOfMemoryError`, `StackOverflowError`, `LinkageError`,
                // …) propagate. Swallowing those would surface as a phantom
                // 401 to the caller and lose any chance of crashing on the
                // real fault. `CancellationException` is a `RuntimeException`
                // and would be caught here, but the explicit handler above
                // claims it first.
                return response
            }

        // Refresh succeeded — close the 401 to release its connection back
        // to OkHttp's pool before issuing the retry. Skipping this would
        // hold a slot in the pool until GC ran the body's finalizer.
        response.close()
        return next(request.withBearer(newToken))
    }

    /**
     * Replace any pre-existing `Authorization` header. We use
     * `header()` rather than `addHeader()` so a caller-supplied
     * placeholder (or a leftover from a prior interceptor in a
     * misconfigured chain) is overwritten, not stacked.
     */
    private fun Request.withBearer(token: String): Request = newBuilder().header(HttpHeader.AUTHORIZATION, "Bearer $token").build()
}
