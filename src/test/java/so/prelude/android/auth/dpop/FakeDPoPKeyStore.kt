package so.prelude.android.auth.dpop

import java.util.concurrent.ConcurrentHashMap

/**
 * Pure-JVM [DPoPKey] for tests. Its sign output is canned so test
 * assertions can compare exact bytes without setting up real ECDSA.
 */
internal class FakeDPoPKey(
    private val jwk: Map<String, String> =
        mapOf(
            "kty" to "EC",
            "crv" to "P-256",
            "x" to "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "y" to "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
        ),
    private val signature: ByteArray = ByteArray(64) { 0x42 },
) : DPoPKey {
    override fun exportPublicJwk(): Map<String, String> = jwk

    override fun signES256(data: ByteArray): ByteArray = signature
}

/**
 * In-memory [DPoPKeyStore] for pure JVM unit tests; never touches
 * AndroidKeystore. One key per domain, just like the real store.
 */
internal class FakeDPoPKeyStore : DPoPKeyStore {
    private val keys = ConcurrentHashMap<String, DPoPKey>()
    private val nonces = ConcurrentHashMap<String, String>()
    private val clockSkewsMs = ConcurrentHashMap<String, Long>()
    var keyFactory: () -> DPoPKey = ::FakeDPoPKey

    override fun get(domain: String): DPoPKey? = keys[domain]

    override fun getOrCreate(domain: String): DPoPKey = keys.computeIfAbsent(domain) { keyFactory() }

    override fun delete(domain: String) {
        keys.remove(domain)
        nonces.remove(domain)
        clockSkewsMs.remove(domain)
    }

    override fun getNonce(domain: String): String? = nonces[domain]

    override fun setNonce(
        domain: String,
        nonce: String,
    ) {
        nonces[domain] = nonce
    }

    override fun deleteNonce(domain: String) {
        nonces.remove(domain)
    }

    override fun getClockSkewMs(domain: String): Long? = clockSkewsMs[domain]

    override fun setClockSkewMs(
        domain: String,
        skewMs: Long,
    ) {
        clockSkewsMs[domain] = skewMs
    }

    override fun deleteClockSkewMs(domain: String) {
        clockSkewsMs.remove(domain)
    }

    /** Pre-populate without going through `getOrCreate` (e.g. for the
     *  challenge interceptor's "no key for domain" pass-through path). */
    fun setKey(
        domain: String,
        key: DPoPKey,
    ) {
        keys[domain] = key
    }
}
