package so.prelude.android.auth.store

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.time.Instant
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val cacheJson = Json { ignoreUnknownKeys = true }

/**
 * In-memory cache of access tokens per Prelude domain, backed by
 * persistent storage so a cold start can render the profile and skip a
 * refresh round-trip when the token is still valid.
 *
 * Storage-before-memory ordering invariants:
 *
 *   - [set], [invalidate], and [clear] all advance persistent storage
 *     **before** mutating the in-memory map. A failing storage write
 *     leaves both sides at their pre-call state, so [hydrate] on a
 *     subsequent cold start cannot resurrect a row that disagrees
 *     with what the running cache claims to hold.
 *
 *   - The internal lock is held across the paired persistent +
 *     in-memory mutation, so concurrent callers can't observe a
 *     half-applied transition.
 *
 * @param clock seconds-since-epoch source. Tests inject a pinned value;
 *   production passes `Instant::now` (the default).
 * @param storage persistent backend. Production wires in
 *   [SharedPreferencesAccessTokenStorage]; tests wire an in-memory
 *   double (or a failure-injecting wrapper).
 */
internal class AccessTokenCache(
    private val clock: () -> Instant = Instant::now,
    private val storage: AccessTokenStorage,
) {
    private val memory = HashMap<String, AccessTokenEntry>()
    private val lock = ReentrantLock()

    /**
     * Populate memory from persistent storage for [domain].
     * Best-effort: any decode/storage failure leaves the cache empty.
     * Call once at client init.
     */
    fun hydrate(domain: String) =
        lock.withLock {
            val entry = readPersisted(domain)
            if (entry != null) {
                memory[domain] = entry
            }
        }

    /**
     * Cached entry, or `null` if none is cached or the entry has
     * expired. Expiry strictly less than `now` is expired; equality is
     * still valid, giving an edge-case full second of grace at the
     * boundary.
     */
    fun get(domain: String): AccessTokenEntry? =
        lock.withLock {
            val entry = memory[domain] ?: return null
            if (entry.expiresAt < clock().epochSecond) null else entry
        }

    /**
     * Cached entry regardless of expiration. Used by profile readers
     * so the app can render the logged-in user while a refresh is in
     * flight.
     */
    fun getWithoutExpirationCheck(domain: String): AccessTokenEntry? =
        lock.withLock {
            memory[domain]
        }

    /**
     * Persist a new entry. Storage write comes **before** the
     * in-memory update — a failing storage write leaves both sides at
     * their pre-call state.
     */
    fun set(
        domain: String,
        entry: AccessTokenEntry,
    ) = lock.withLock {
        writePersisted(domain, entry)
        memory[domain] = entry
    }

    /**
     * Mark the entry expired without removing it — still retrievable
     * via [getWithoutExpirationCheck] so the client can render profile
     * data while refresh runs. Implemented by setting
     * `expiresAt = now - 1`.
     *
     * Storage before memory: if the storage write fails, the in-memory
     * snapshot keeps its original [AccessTokenEntry.expiresAt] instead
     * of silently downgrading while persistent storage still holds a
     * valid row. Without this ordering, a storage failure would let
     * the "invalidated" token be resurrected by [hydrate] on the next
     * cold start.
     */
    fun invalidate(domain: String) =
        lock.withLock {
            val current = memory[domain] ?: return@withLock
            val invalidated = current.copy(expiresAt = clock().epochSecond - 1)
            writePersisted(domain, invalidated)
            memory[domain] = invalidated
        }

    /**
     * Remove the entry from both memory and persistent storage.
     *
     * Storage before memory: if the delete fails the entry stays
     * observable so the caller can retry. If we cleared memory first
     * and storage failed, the next cold start would resurrect the
     * still-persisted token.
     */
    fun clear(domain: String) =
        lock.withLock {
            storage.delete(domain)
            memory.remove(domain)
        }

    // MARK: - Codec helpers

    private fun readPersisted(domain: String): AccessTokenEntry? {
        val blob =
            try {
                storage.read(domain)
            } catch (_: Exception) {
                // Hydrate is best-effort — a backend hiccup at startup
                // shouldn't block the app from continuing into refresh.
                return null
            } ?: return null
        return try {
            cacheJson.decodeFromString(AccessTokenEntry.serializer(), blob)
        } catch (_: Exception) {
            // Treat a corrupt blob the same as "no entry": the next
            // refresh will overwrite it. Catch is intentionally broad —
            // the documented type is `SerializationException`, but the
            // parser has historically thrown `IllegalArgumentException`
            // on a few malformed inputs, and hydrate must not crash the
            // app on launch regardless of which one surfaces.
            null
        }
    }

    private fun writePersisted(
        domain: String,
        entry: AccessTokenEntry,
    ) {
        val blob =
            try {
                cacheJson.encodeToString(AccessTokenEntry.serializer(), entry)
            } catch (e: SerializationException) {
                throw TokenStoreError.CodecFailure("encode failed", e)
            }
        storage.write(domain, blob)
    }
}
