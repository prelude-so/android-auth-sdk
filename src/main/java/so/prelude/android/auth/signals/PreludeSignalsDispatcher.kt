package so.prelude.android.auth.signals

/**
 * Pluggable anti-fraud signals dispatcher.
 *
 * [so.prelude.android.auth.PreludeAuthClient] calls [dispatch]
 * at the start of an unauthenticated login (currently `startOTPLogin`)
 * and attaches the returned `dispatch_id` to the request body. Returning
 * `null` is a supported no-op for callers that don't configure one.
 */
fun interface PreludeSignalsDispatcher {
    /**
     * Dispatch a fresh signals payload and return its server-assigned
     * `dispatch_id`, or `null` to skip. Implementations may throw on
     * failure (network, timeout, server error) — the SDK swallows
     * those errors, logs them, and proceeds with the login flow
     * without a `dispatch_id`. Anti-fraud coverage degrades gracefully
     * rather than blocking authentication.
     */
    suspend fun dispatch(): String?
}
