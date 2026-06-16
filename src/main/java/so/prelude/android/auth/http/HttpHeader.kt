package so.prelude.android.auth.http

/**
 * HTTP header names used by the Prelude Auth SDK. Centralised
 * here so hyphenation and casing stay uniform across the codebase.
 */
internal object HttpHeader {
    // Standard (RFC 9110 / 7230)
    const val ACCEPT = "Accept"
    const val AUTHORIZATION = "Authorization"
    const val CONTENT_TYPE = "Content-Type"
    const val DATE = "Date"

    /**
     * Written on every outgoing request when the client is
     * configured with a `hostOverride`. The DPoP interceptor
     * copies this value into the `htu` claim.
     */
    const val HOST = "Host"

    // DPoP (RFC 9449)
    const val DPOP = "DPoP"
    const val DPOP_NONCE = "DPoP-Nonce"

    // Prelude session-specific

    /**
     * Stable per-domain device id attached to every session
     * request. Persisted in [so.prelude.android.auth.store.DeviceIDStore].
     */
    const val DEVICE_ID = "X-Device-Id"

    /**
     * Request header on `/refresh`; response header on
     * `/login/finalize` and any `/refresh` that rotates the token.
     */
    const val REFRESH_TOKEN = "X-Refresh-Token"

    /** ISO 8601 expiry paired with [REFRESH_TOKEN]. */
    const val REFRESH_TOKEN_EXPIRES_AT = "X-Refresh-Token-Expires-At"
}
