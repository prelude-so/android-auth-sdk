package so.prelude.android.auth.dpop

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_FILE = "so.prelude.auth.dpop-clock-skew"

/**
 * Per-domain DPoP clock-skew storage.
 *
 * Skew is `serverTime - localTime` in milliseconds. Persisted to
 * app-private [SharedPreferences] so the corrected `iat` survives
 * a process restart — the device clock is unlikely to have
 * re-synced in the meantime, and a stale entry self-heals through
 * the next `invalid_dpop_proof` round trip.
 *
 * Same SharedPreferences semantics as [DPoPNonceStore]: per-key
 * atomic writes, no locking, last-write-wins.
 */
internal class DPoPClockSkewStore(
    context: Context,
) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)

    fun get(domain: String): Long? = if (prefs.contains(domain)) prefs.getLong(domain, 0L) else null

    fun set(
        domain: String,
        skewMs: Long,
    ) {
        prefs.edit().putLong(domain, skewMs).apply()
    }

    fun delete(domain: String) {
        prefs.edit().remove(domain).apply()
    }
}
