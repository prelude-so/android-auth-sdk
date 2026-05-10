package so.prelude.android.session.http

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Process-lifetime [CookieJar] used by the default [OkHttpSession].
 *
 * Required for the OTP login flow: `POST /v1/session/otp` sets a
 * `Set-Cookie: verification=…` header that the matching `POST
 * /v1/session/otp/check` reads to identify the in-flight challenge.
 * `OkHttpClient.Builder` defaults to [CookieJar.NO_COOKIES], which
 * silently drops the cookie and turns the second hop into a 401.
 *
 * The implementation is intentionally minimal:
 *
 *   - cookies are partitioned by host (the server only issues
 *     domain-scoped cookies for its own host),
 *   - duplicates by name are replaced on save,
 *   - expired cookies are pruned lazily on save,
 *   - `loadForRequest` filters via [Cookie.matches] so `Path`,
 *     `Domain`, and `Secure` constraints are honoured.
 *
 * Cookies live in memory only — fine for the verification cookie, which
 * is short-lived and tied to a single login attempt. A long-lived
 * persistent jar would need to use disk storage and consider
 * cross-process invalidation; out of scope here.
 */
internal class InMemoryCookieJar : CookieJar {
    private val byHost = ConcurrentHashMap<String, MutableList<Cookie>>()

    // One lock per host bucket to serialise the read-modify-write
    // (de-dup + prune) inside `saveFromResponse`. Allocated via
    // `computeIfAbsent` so two concurrent first-saves for the same
    // host can't end up holding detached locks (the Kotlin `getOrPut`
    // extension is `get` + conditional `put`, not atomic, so the
    // losing thread would otherwise mutate a list that's no longer in
    // the map).
    private val locks = ConcurrentHashMap<String, ReentrantLock>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        if (cookies.isEmpty()) return

        val host = url.host
        // `computeIfAbsent` is atomic on `ConcurrentHashMap`; the
        // Kotlin `getOrPut` extension is not (it's `get` + conditional
        // `put`), so under concurrent first-saves the losing caller
        // would otherwise hold a detached bucket + lock pair and its
        // writes would silently disappear.
        val bucket = byHost.computeIfAbsent(host) { mutableListOf() }
        val lock = locks.computeIfAbsent(host) { ReentrantLock() }
        lock.withLock {
            val now = System.currentTimeMillis()
            cookies.forEach { incoming ->
                bucket.removeAll { it.name == incoming.name }
                if (incoming.expiresAt > now) {
                    bucket.add(incoming)
                }
            }
            bucket.removeAll { it.expiresAt <= now }
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val bucket = byHost[url.host] ?: return emptyList()
        val lock = locks[url.host] ?: return emptyList()
        return lock.withLock {
            bucket.filter { it.matches(url) }.toList()
        }
    }

    /**
     * Wipe every cookie scoped to [host]. Called from
     * `clearAllStores` so a logout / revoke leaves no
     * server-set markers (e.g. `verification`, `did`) behind for
     * the next login flow on the same client. Idempotent — a host
     * with no bucket is a no-op.
     */
    internal fun clear(host: String) {
        val lock = locks[host] ?: return
        lock.withLock { byHost[host]?.clear() }
    }
}
