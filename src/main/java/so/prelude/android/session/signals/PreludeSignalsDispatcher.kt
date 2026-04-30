package so.prelude.android.session.signals

/**
 * Pluggable anti-fraud signals dispatcher.
 *
 * [so.prelude.android.session.PreludeSessionClient] calls [dispatch]
 * at the start of an unauthenticated login (currently `startOTPLogin`)
 * and attaches the returned `dispatch_id` to the request body. Returning
 * `null` is a supported no-op for callers that don't configure one.
 */
fun interface PreludeSignalsDispatcher {
    /**
     * Dispatch a fresh signals payload and return its server-assigned
     * `dispatch_id`, or `null` to skip. Throw on genuine failures so
     * callers don't silently lose anti-fraud coverage.
     */
    suspend fun dispatch(): String?
}
