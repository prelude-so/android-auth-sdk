package so.prelude.android.auth.store

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

private val storeJson = Json { ignoreUnknownKeys = true }

/**
 * Persistent store for refresh tokens, scoped by Prelude domain.
 *
 * Stateless on purpose: refresh tokens are read at most twice per
 * session (one `/refresh`, one `/revoke`), so an in-memory cache
 * would be all complexity and no upside. Every call routes through
 * [RefreshTokenStorage].
 *
 * Contract: only `finalizeLogin` (post-login) and `refresh()` (post-
 * rotation) write to this store; only `logout()` deletes from it.
 * Other call sites that happen to see an `X-Refresh-Token` response
 * header leave it alone — keeps the refresh-token lifecycle
 * (issued → rotated → revoked) reviewable in a single place.
 *
 * @param storage persistent backend. Production wires in
 *   [SharedPreferencesRefreshTokenStorage]; tests wire an in-memory
 *   double (or a failure-injecting wrapper).
 */
internal class RefreshTokenStore(
    private val storage: RefreshTokenStorage,
) {
    /**
     * Stored record for [domain], or `null` when none is persisted
     * or the blob can't be decoded.
     *
     * A corrupt blob is treated as "no record" rather than
     * surfacing an error: the only recovery path is a fresh login,
     * so a decode failure here behaves identically to a missing
     * row from the caller's perspective.
     */
    fun get(domain: String): RefreshTokenRecord? {
        val blob = storage.read(domain) ?: return null
        return try {
            storeJson.decodeFromString(RefreshTokenRecord.serializer(), blob)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Persist [record] for [domain]. Throws
     * [TokenStoreError.CodecFailure] if the record can't be
     * encoded (impossible for the current schema — guard against a
     * future field with a non-default serializer) and
     * [TokenStoreError.StorageFailure] when the backend
     * refuses the write.
     */
    fun set(
        domain: String,
        record: RefreshTokenRecord,
    ) {
        val blob =
            try {
                storeJson.encodeToString(RefreshTokenRecord.serializer(), record)
            } catch (e: SerializationException) {
                throw TokenStoreError.CodecFailure("encode failed", e)
            }
        storage.write(domain, blob)
    }

    /**
     * Remove the entry for [domain]. A missing entry is a no-op.
     * Throws [TokenStoreError.StorageFailure] on any other
     * backend failure.
     */
    fun delete(domain: String) {
        storage.delete(domain)
    }
}
