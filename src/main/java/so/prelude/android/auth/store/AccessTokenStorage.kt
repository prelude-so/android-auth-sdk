package so.prelude.android.auth.store

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_FILE = "so.prelude.auth.access"

/**
 * Per-domain persistent backing for [AccessTokenCache].
 *
 * The cache owns JSON encoding and the storage-before-memory
 * ordering invariant; this abstraction is just opaque key/value
 * storage.
 *
 * Tests use [InMemoryAccessTokenStorage]; production wires in
 * [SharedPreferencesAccessTokenStorage].
 */
internal interface AccessTokenStorage {
    /** Read the persisted blob for [domain], or `null` if none. */
    fun read(domain: String): String?

    /**
     * Persist [blob] for [domain]. Implementations throw
     * [TokenStoreError.StorageFailure] when the underlying
     * backend rejects the write so [AccessTokenCache] can preserve its
     * pre-call in-memory state.
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
 * Production [AccessTokenStorage] backed by app-private
 * [SharedPreferences].
 *
 * The access token alone has no value to an attacker without the DPoP
 * keypair, which lives in the AndroidKeystore (StrongBox / TEE when
 * available) and isn't extractable. The Android per-app sandbox
 * already prevents cross-app reads. This is the same threat-model
 * argument that justifies plaintext SharedPreferences for the DPoP
 * nonce in [so.prelude.android.auth.dpop.DPoPNonceStore]; it
 * applies equally to a token that is unusable on its own.
 *
 * Writes use [SharedPreferences.Editor.commit] (synchronous, returns
 * a success boolean) rather than `apply()` so a backend rejection
 * propagates as [TokenStoreError.StorageFailure] — the cache
 * relies on that signal to preserve the storage-before-memory
 * ordering invariant. The `commit()` cost is negligible at
 * human-scale token write rates (login + refresh, not per-request).
 */
internal class SharedPreferencesAccessTokenStorage(
    context: Context,
) : AccessTokenStorage {
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
