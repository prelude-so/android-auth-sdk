package so.prelude.android.auth.store

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_FILE = "so.prelude.auth.device_id"

/**
 * Per-domain persistent backing for [DeviceIDStore]. Opaque
 * key/value, no domain-model awareness — parallel to
 * [AccessTokenStorage] and [RefreshTokenStorage] so each store
 * can evolve independently.
 */
internal interface DeviceIDStorage {
    fun read(domain: String): String?

    fun write(
        domain: String,
        value: String,
    )
}

/**
 * Production [DeviceIDStorage] backed by app-private
 * [SharedPreferences].
 *
 * The id is non-secret but its stability matters: the backend
 * uses it to correlate requests from this install without a
 * cookie. Plaintext SharedPreferences is appropriate — the
 * per-app sandbox prevents cross-app reads and an attacker with
 * device access has stronger primitives than reading a device id.
 *
 * Writes use [SharedPreferences.Editor.commit] so a
 * SharedPreferences rejection surfaces as
 * [TokenStoreError.StorageFailure]; silently dropping a write
 * here would let two callers diverge on the id.
 */
internal class SharedPreferencesDeviceIDStorage(
    context: Context,
) : DeviceIDStorage {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)

    override fun read(domain: String): String? = prefs.getString(domain, null)

    override fun write(
        domain: String,
        value: String,
    ) {
        val ok =
            try {
                prefs.edit().putString(domain, value).commit()
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
