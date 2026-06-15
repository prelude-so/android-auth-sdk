package so.prelude.android.auth.store

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Per-domain stable device identifier persisted via
 * [DeviceIDStorage]. Lazily generated on first use; the value is
 * non-secret but must stay stable so the backend can correlate
 * requests from this install without a cookie.
 *
 * [getOrCreate] is guarded by an in-process lock so concurrent
 * first-time callers can't race on the read-then-create window
 * and persist different UUIDs. A small in-memory cache fronts
 * [storage] so steady-state requests skip the SharedPreferences
 * read on every call.
 */
internal class DeviceIDStore(
    private val storage: DeviceIDStorage,
) {
    private val creationLock = ReentrantLock()
    private val cache = ConcurrentHashMap<String, String>()

    /** In-memory peek for the interceptor's warm path — no I/O. */
    fun cached(domain: String): String? = cache[domain]

    fun getOrCreate(domain: String): String {
        cache[domain]?.let { return it }
        return creationLock.withLock {
            cache[domain]?.let { return@withLock it }
            storage.read(domain)?.also { cache[domain] = it }?.let { return@withLock it }
            val value = UUID.randomUUID().toString().lowercase()
            storage.write(domain, value)
            cache[domain] = value
            value
        }
    }
}
