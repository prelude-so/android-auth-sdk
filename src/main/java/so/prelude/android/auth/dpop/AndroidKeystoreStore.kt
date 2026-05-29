package so.prelude.android.auth.dpop

import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * AndroidKeystore-backed [DPoPKeyStore].
 *
 * One concrete impl, parameterised by [tier]: the spec it feeds to
 * `KeyPairGenerator` decides whether the key lands in StrongBox,
 * TEE, or software-only AndroidKeystore.
 *
 * Concurrency: [getOrCreate] and [delete] share a process-global,
 * domain-keyed lock — see [domainLock]. `find` and `create` are
 * individually atomic at the AndroidKeystore boundary, but
 * `find → null → create` is not, and a per-instance lock would miss
 * cross-instance races (two `PreludeAuthClient`s in the same
 * process, each with their own store). Nonce ops go through
 * [DPoPNonceStore], which composes its own locking.
 */
internal class AndroidKeystoreStore(
    private val nonceStore: DPoPNonceStore,
    private val clockSkewStore: DPoPClockSkewStore,
    tierProvider: () -> KeystoreTier = KeystoreTier.Companion::detect,
) : DPoPKeyStore {
    /**
     * Tier is lazy because [KeystoreTier.detect] is hundreds of
     * milliseconds of blocking I/O — we don't want a bare
     * `newDPoPKeyStore(context)` call to pay that cost on the
     * caller's thread. The first [getOrCreate] / [get] / [delete]
     * triggers the probe; those already run on a background
     * dispatcher in our HTTP stack.
     */
    private val tier: KeystoreTier by lazy(tierProvider)

    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun get(domain: String): DPoPKey? = findKey(domain)

    override fun getOrCreate(domain: String): DPoPKey =
        domainLock(domain).withLock {
            findKey(domain) ?: createKey(domain)
        }

    /**
     * Drop both the keypair and any persisted nonce for [domain].
     *
     * The keypair and nonce live in two stores, but the caller's
     * mental model is one record per domain — clearing both here
     * keeps that intact.
     */
    override fun delete(domain: String) =
        domainLock(domain).withLock {
            try {
                if (keyStore.containsAlias(aliasFor(domain))) {
                    keyStore.deleteEntry(aliasFor(domain))
                }
            } catch (e: Exception) {
                throw DPoPKeyStoreError.KeystoreFailure(e)
            }
            nonceStore.delete(domain)
            clockSkewStore.delete(domain)
        }

    override fun getNonce(domain: String): String? = nonceStore.get(domain)

    override fun setNonce(
        domain: String,
        nonce: String,
    ) = nonceStore.set(domain, nonce)

    override fun deleteNonce(domain: String) = nonceStore.delete(domain)

    override fun getClockSkewMs(domain: String): Long? = clockSkewStore.get(domain)

    override fun setClockSkewMs(
        domain: String,
        skewMs: Long,
    ) = clockSkewStore.set(domain, skewMs)

    override fun deleteClockSkewMs(domain: String) = clockSkewStore.delete(domain)

    private fun findKey(domain: String): DPoPKey? {
        val alias = aliasFor(domain)
        val raw =
            try {
                keyStore.getEntry(alias, null)
            } catch (e: Exception) {
                // `UnrecoverableKeyException` shows up when the user changed
                // their lockscreen credential and invalidated the key —
                // surface as a real failure rather than silently treating
                // it as "not found", which would create a duplicate.
                throw DPoPKeyStoreError.KeystoreFailure(e)
            } ?: return null
        // If the alias is occupied but not by a PrivateKeyEntry, refuse
        // to proceed. AndroidKeyStore's `KeyPairGenerator.generateKeyPair()`
        // silently overwrites alias collisions, so falling through to
        // the create path here would silently destroy whatever owns
        // the alias.
        val entry =
            raw as? KeyStore.PrivateKeyEntry
                ?: throw DPoPKeyStoreError.KeystoreFailure(
                    IllegalStateException(
                        "Alias '$alias' is occupied by ${raw::class.java.simpleName}, expected PrivateKeyEntry",
                    ),
                )
        return AndroidKeystoreKey(entry.privateKey, entry.certificate.publicKey)
    }

    private fun createKey(domain: String): DPoPKey {
        val spec = tier.buildSpec(aliasFor(domain))
        val keyPair =
            try {
                KeyPairGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                    .apply { initialize(spec) }
                    .generateKeyPair()
            } catch (e: Exception) {
                throw DPoPKeyStoreError.KeyGenerationFailed(e)
            }
        return AndroidKeystoreKey(keyPair.private, keyPair.public)
    }

    companion object {
        // The registry grows monotonically — one entry per domain
        // ever observed in the process. Real apps hit single digits;
        // a multi-tenant test runner could in theory accumulate
        // entries indefinitely. Acceptable in exchange for a
        // lock-free fast path on every request.
        private val locks = ConcurrentHashMap<String, ReentrantLock>()

        /**
         * Acquire (or lazily create) the lock for [domain]. Process-
         * global by design: every store instance contends for the
         * same mutex per domain, so cross-instance `getOrCreate`
         * races collapse to a single create.
         */
        private fun domainLock(domain: String): ReentrantLock = locks.computeIfAbsent(domain) { ReentrantLock() }
    }
}
