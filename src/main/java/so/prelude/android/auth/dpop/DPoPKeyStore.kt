package so.prelude.android.auth.dpop

import android.content.Context

/**
 * Persistent DPoP keypair, nonce, and clock-skew storage, scoped
 * by Prelude domain. One key per domain, lazily created on first
 * use.
 *
 * Implementations must be thread- and instance-safe: concurrent
 * [getOrCreate] callers within the same process must observe a
 * single shared key, even when each holds its own [DPoPKeyStore].
 */
internal interface DPoPKeyStore {
    /**
     * Return the persisted key for [domain], or `null` if none.
     * Never creates. Used by the challenge interceptor, which must
     * not provoke key creation just to attach a proof.
     */
    fun get(domain: String): DPoPKey?

    fun getOrCreate(domain: String): DPoPKey

    fun delete(domain: String)

    fun getNonce(domain: String): String?

    fun setNonce(
        domain: String,
        nonce: String,
    )

    fun deleteNonce(domain: String)

    /**
     * `serverTime - localTime` in ms persisted from the last
     * `invalid_dpop_proof` retry, or `null` when none has been
     * recorded for [domain]. Read on every signing path so step-up
     * one-shot proofs are also pre-corrected.
     */
    fun getClockSkewMs(domain: String): Long?

    fun setClockSkewMs(
        domain: String,
        skewMs: Long,
    )

    fun deleteClockSkewMs(domain: String)
}

/**
 * Build a [DPoPKeyStore] for the current device.
 *
 * Cheap — no key generation, no probe. The strongest hardware tier
 * the device offers (StrongBox → TEE → software AndroidKeystore) is
 * detected lazily on the first key operation. The verdict is cached
 * for the lifetime of the process.
 */
internal fun newDPoPKeyStore(context: Context): DPoPKeyStore =
    AndroidKeystoreStore(
        nonceStore = DPoPNonceStore(context),
        clockSkewStore = DPoPClockSkewStore(context),
    )
