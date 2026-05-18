package so.prelude.android.auth.store

import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory [RefreshTokenStorage] for unit tests.
 *
 * Vanilla Android library unit tests have no [android.content.Context]
 * unless Robolectric is on the classpath, so the production
 * [SharedPreferencesRefreshTokenStorage] can't be exercised in plain
 * JUnit. This double covers the same surface in a few lines, paired
 * with [InMemoryAccessTokenStorage].
 */
internal class InMemoryRefreshTokenStorage : RefreshTokenStorage {
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
 * A [RefreshTokenStorage] that delegates to an inner backend but can
 * be told to throw on `read`, `write`, or `delete`. Used by failure-
 * mode tests that exercise corrupt blobs and disk faults.
 */
internal class FailingRefreshTokenStorage(
    private val inner: RefreshTokenStorage,
) : RefreshTokenStorage {
    var readFailure: Throwable? = null
    var writeFailure: Throwable? = null
    var deleteFailure: Throwable? = null

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
