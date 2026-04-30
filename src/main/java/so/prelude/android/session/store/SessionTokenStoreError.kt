package so.prelude.android.session.store

/**
 * Failure modes surfaced by the session token stores
 * ([AccessTokenCache] and the refresh-token store).
 *
 * Hydrate paths intentionally swallow these — a failed read on cold
 * start is treated as "no value present" so the SDK falls back to a
 * refresh round-trip rather than crashing the app.
 */
internal sealed class SessionTokenStoreError(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /** The persistent backend (SharedPreferences) refused a read or write. */
    internal class StorageFailure(cause: Throwable) :
        SessionTokenStoreError("Token store failure: ${cause.message}", cause)

    /** A persisted value couldn't be encoded or decoded. */
    internal class CodecFailure(message: String, cause: Throwable? = null) :
        SessionTokenStoreError("Token codec failure: $message", cause)
}
