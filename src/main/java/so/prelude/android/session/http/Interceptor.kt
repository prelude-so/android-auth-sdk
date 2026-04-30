package so.prelude.android.session.http

import okhttp3.Request
import okhttp3.Response

/**
 * Call-the-next-layer function. Shape matches [HttpSession.perform]
 * so a base session is itself a valid [SendFunction].
 */
internal typealias SendFunction = suspend (Request) -> Response

/**
 * Observes or modifies a request/response as it travels through the
 * HTTP stack. Interceptors compose first-is-outermost.
 *
 * Named [PreludeInterceptor] to avoid colliding with `okhttp3.Interceptor`,
 * whose synchronous `intercept(chain)` signature is unsuitable for
 * coroutine-based code paths (token refresh, DPoP nonce retry, etc.).
 *
 * Declared as a `fun interface` so callers can pass a bare lambda:
 *
 * ```
 * val logger = PreludeInterceptor { request, next ->
 *     println("--> ${request.method} ${request.url}")
 *     next(request)
 * }
 * ```
 */
internal fun interface PreludeInterceptor {
    suspend fun intercept(request: Request, next: SendFunction): Response
}

/**
 * Wrap [baseSession] with a chain of [interceptors] (first is outermost).
 *
 * `DPoPInterceptor` and `ChallengeDPoPInterceptor` must not appear in
 * the same chain — both write the `DPoP` header, and `Request.Builder.header()`
 * replaces rather than appending, so whichever runs innermost silently
 * wins. Step-up flows substitute the challenge variant for the base
 * interceptor on the single request that needs it.
 */
internal fun composeInterceptors(
    interceptors: List<PreludeInterceptor>,
    baseSession: HttpSession,
): SendFunction {
    var next: SendFunction = { request -> baseSession.perform(request) }
    for (interceptor in interceptors.reversed()) {
        val current = next
        next = { request -> interceptor.intercept(request, current) }
    }
    return next
}
