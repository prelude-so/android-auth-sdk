package so.prelude.android.auth.store

import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory [AccessTokenStorage] for unit tests.
 *
 * Vanilla Android library unit tests have no [android.content.Context]
 * unless Robolectric is on the classpath, so the production
 * [SharedPreferencesAccessTokenStorage] can't be exercised in plain
 * JUnit. This double covers the same surface in a few lines.
 *
 * Intentionally not concurrency-safe at the read-modify-write level —
 * the cache holds a lock across the persistent + in-memory mutation,
 * so this only needs per-call atomicity.
 */
internal class InMemoryAccessTokenStorage : AccessTokenStorage {
    private val rows = ConcurrentHashMap<String, String>()

    override fun read(domain: String): String? = rows[domain]

    override fun write(
        domain: String,
        blob: String,
    ) {
        rows[domain] = blob
    }

    override fun delete(domain: String) {
        rows.remove(domain)
    }
}

/**
 * An [AccessTokenStorage] that delegates to an inner backend and
 * counts read calls. Used to assert that the cache's hot path stays
 * in memory once an entry is hydrated.
 */
internal class CountingAccessTokenStorage(
    private val inner: AccessTokenStorage,
) : AccessTokenStorage {
    var readCount: Int = 0
        private set

    override fun read(domain: String): String? {
        readCount += 1
        return inner.read(domain)
    }

    override fun write(
        domain: String,
        blob: String,
    ) = inner.write(domain, blob)

    override fun delete(domain: String) = inner.delete(domain)
}

/**
 * An [AccessTokenStorage] that delegates to an inner backend but can
 * be told to throw on `write` or `delete`. Used by ordering-invariant
 * tests — when the backend rejects a write, the cache must not have
 * already mutated its in-memory state.
 *
 * Failure overrides are sticky so tests can flip them on between
 * setup and the operation under test.
 */
internal class FailingAccessTokenStorage(
    private val inner: AccessTokenStorage,
) : AccessTokenStorage {
    var writeFailure: Throwable? = null
    var deleteFailure: Throwable? = null
    var readFailure: Throwable? = null

    override fun read(domain: String): String? {
        readFailure?.let { throw it }
        return inner.read(domain)
    }

    override fun write(
        domain: String,
        blob: String,
    ) {
        writeFailure?.let { throw it }
        inner.write(domain, blob)
    }

    override fun delete(domain: String) {
        deleteFailure?.let { throw it }
        inner.delete(domain)
    }
}
