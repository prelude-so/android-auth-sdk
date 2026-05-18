package so.prelude.android.auth.store

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_FILE = "so.prelude.auth.refresh"

/**
 * Per-domain persistent backing for [RefreshTokenStore].
 *
 * Parallel to [AccessTokenStorage] — opaque key/value storage with
 * no JSON or domain-model awareness. Kept as a separate interface
 * so the refresh and access stores can evolve independently and so
 * tests can inject a per-store double without entangling fixtures.
 *
 * Production wires in [SharedPreferencesRefreshTokenStorage] (a
 * separate `SharedPreferences` file from the access-token cache);
 * tests use [InMemoryRefreshTokenStorage].
 */
internal interface RefreshTokenStorage {
    /** Read the persisted blob for [domain], or `null` if none. */
    fun read(domain: String): String?

    /**
     * Persist [blob] for [domain]. Implementations throw
     * [TokenStoreError.StorageFailure] when the underlying
     * backend rejects the write so [RefreshTokenStore] can preserve
     * its caller-visible "either fully wrote or did nothing"
     * contract.
     */
    fun write(
        domain: String,
        blob: String,
    )

    /**
     * Remove the entry for [domain]. A missing entry is a no-op (no
     * throw). Implementations throw
     * [TokenStoreError.StorageFailure] for any other failure.
     */
    fun delete(domain: String)
}

/**
 * Production [RefreshTokenStorage] backed by app-private
 * [SharedPreferences].
 *
 * Stored in a dedicated prefs file (`so.prelude.auth.refresh`)
 * so refresh-token writes can't accidentally collide with the
 * access-token cache's keys, and so a future migration of either
 * store can move independently.
 *
 * The threat model matches the access-token cache: the refresh
 * token alone has no value to an attacker without the DPoP
 * keypair, which lives in the AndroidKeystore (StrongBox / TEE
 * when available) and isn't extractable. The Android per-app
 * sandbox prevents cross-app reads. The same argument that
 * justifies plaintext SharedPreferences for the access-token
 * blob applies here.
 *
 * Writes use [SharedPreferences.Editor.commit] (synchronous,
 * returns a success boolean) rather than `apply()` so a backend
 * rejection propagates as [TokenStoreError.StorageFailure]
 * — without that signal a refresh round-trip could rotate the
 * server-side token while leaving the device with a stale local
 * record (next refresh: 401, hard logout).
 */
internal class SharedPreferencesRefreshTokenStorage(
    context: Context,
) : RefreshTokenStorage {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)

    override fun read(domain: String): String? = prefs.getString(domain, null)

    override fun write(
        domain: String,
        blob: String,
    ) {
        val ok =
            try {
                prefs.edit().putString(domain, blob).commit()
            } catch (e: Exception) {
                throw TokenStoreError.StorageFailure(e)
            }
        if (!ok) {
            throw TokenStoreError.StorageFailure(
                IllegalStateException("SharedPreferences.commit() returned false"),
            )
        }
    }

    override fun delete(domain: String) {
        // `remove` on a missing key is a no-op for SharedPreferences and
        // `commit()` still returns true — matches the protocol contract.
        val ok =
            try {
                prefs.edit().remove(domain).commit()
            } catch (e: Exception) {
                throw TokenStoreError.StorageFailure(e)
            }
        if (!ok) {
            throw TokenStoreError.StorageFailure(
                IllegalStateException("SharedPreferences.commit() returned false"),
            )
        }
    }
}
