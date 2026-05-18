package so.prelude.android.auth.dpop

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_FILE = "so.prelude.auth.dpop-nonce"

/**
 * Per-domain DPoP nonce storage.
 *
 * Persisted, plaintext, in app-private [SharedPreferences]. The
 * nonce is a server-issued freshness token; without the DPoP
 * keypair (which lives in the AndroidKeystore) it has no value to
 * an attacker, and the Android per-app sandbox already prevents
 * cross-app reads.
 *
 * Persistence is a cold-start optimisation: replaying the last
 * known nonce on the first request after process restart usually
 * lets the server skip its `use_dpop_nonce` 401 challenge. Lost
 * writes are harmless — the protocol recovers via the same
 * challenge/retry path.
 *
 * No locking: [SharedPreferences] writes are per-key atomic, and
 * last-write-wins is the documented semantic. Read-modify-write is
 * never composed at this layer.
 */
internal class DPoPNonceStore(
    context: Context,
) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)

    fun get(domain: String): String? = prefs.getString(domain, null)

    /**
     * `apply()` rather than `commit()`: the in-memory map is
     * updated synchronously, so subsequent [get] calls in the same
     * process see the new value immediately. Disk durability is
     * eventual, which is fine — a lost write just costs one extra
     * 401 round-trip.
     *
     * Empty-string [nonce] is normalised to a [delete] so the
     * "no nonce yet" state has a single representation (absent
     * entry).
     */
    fun set(
        domain: String,
        nonce: String,
    ) {
        if (nonce.isEmpty()) {
            delete(domain)
            return
        }
        prefs.edit().putString(domain, nonce).apply()
    }

    fun delete(domain: String) {
        prefs.edit().remove(domain).apply()
    }
}
