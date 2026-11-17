package so.prelude.android.auth.http

import kotlinx.coroutines.CancellationException
import okhttp3.Request
import okhttp3.Response

/**
 * Attaches `Authorization: Bearer <access token>` to every request
 * and transparently recovers from 401 responses: expire the
 * rejected token (only if it is still cached), refresh when needed,
 * and retry once.
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
 * @param invalidateCache marks the token the request sent stale
 *   after a 401, if it is still the cached one, so other code paths
 *   stop handing out the bad token. Allowed to throw — a real
 *   storage failure or a sealed client is more important than a
 *   stale 401.
 * @param refreshSession returns a valid access token, refreshing
 *   when needed. May throw on any refresh-side failure; the
 *   interceptor swallows it and returns the original 401 to the
 *   caller.
 */
internal class AutoRefreshInterceptor(
    private val getAccessToken: suspend () -> String,
    private val invalidateCache: suspend (sentToken: String) -> Unit,
    private val refreshSession: suspend () -> String,
) : PreludeInterceptor {
    override suspend fun intercept(
        request: Request,
        next: SendFunction,
    ): Response {
        val sentToken = getAccessToken()
        val response = next(request.withBearer(sentToken))

        if (response.code != 401) return response

        // A sibling caller may have refreshed while our 401 was in flight:
        // then its token is kept and `refreshSession` returns it without a
        // new refresh.
        try {
            invalidateCache(sentToken)
        } catch (e: Throwable) {
            // Close the 401 before rethrowing so its connection returns to
            // OkHttp's pool instead of waiting on the body's finalizer.
            // `Throwable` so cancellation closes the response too.
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
                // Refresh failed — return the ORIGINAL 401 so upstream retry
                // loops treat auth as non-transient. The retry below is
                // deliberately outside this catch so its own errors propagate.
                // `Exception`, not `Throwable`, so JVM `Error`s propagate; keep
                // it below the `CancellationException` catch, which it would
                // otherwise swallow.
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
