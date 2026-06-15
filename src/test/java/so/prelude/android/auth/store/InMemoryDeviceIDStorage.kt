package so.prelude.android.auth.store

import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory [DeviceIDStorage] for unit tests — parallels
 * [InMemoryRefreshTokenStorage]. Vanilla Android library unit
 * tests have no Context, so the SharedPreferences-backed
 * production storage can't run in plain JUnit.
 */
internal class InMemoryDeviceIDStorage : DeviceIDStorage {
    private val rows = ConcurrentHashMap<String, String>()

    override fun read(domain: String): String? = rows[domain]

    override fun write(
        domain: String,
        value: String,
    ) {
        rows[domain] = value
    }
}

/**
 * A [DeviceIDStorage] that delegates to an inner backend but can be
 * told to throw on `read` or `write` — parallels
 * [FailingRefreshTokenStorage]. Used by failure-mode tests asserting
 * a device-id fault never fails the request chain.
 */
internal class FailingDeviceIDStorage(
    private val inner: DeviceIDStorage = InMemoryDeviceIDStorage(),
) : DeviceIDStorage {
    var readFailure: Throwable? = null
    var writeFailure: Throwable? = null

    override fun read(domain: String): String? {
        readFailure?.let { throw it }
        return inner.read(domain)
    }

    override fun write(
        domain: String,
        value: String,
    ) {
        writeFailure?.let { throw it }
        inner.write(domain, value)
    }
}
