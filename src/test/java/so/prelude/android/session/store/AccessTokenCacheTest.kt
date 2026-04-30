package so.prelude.android.session.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

/**
 * Unit tests for [AccessTokenCache].
 *
 * Two themes:
 *
 *   1. Happy-path round-tripping — `set`/`get`, `hydrate` reads what
 *      `set` wrote, `clear` wipes both stores.
 *
 *   2. The storage-first ordering invariants — when the persistent
 *      backend fails, the cache's in-memory state must not have
 *      advanced. Without that property a partial failure could let
 *      the next cold start (which calls `hydrate`) silently overturn
 *      whatever mutation the caller thought succeeded.
 */
class AccessTokenCacheTest {
    // Round Unix timestamp keeps the expiry maths in the tests readable.
    private val fixedEpochSec = 1_700_000_000L
    private val clock: () -> Instant = { Instant.ofEpochSecond(fixedEpochSec) }
    private val domain = "app.example.com"

    private fun makeEntry(
        accessToken: String = "jwt-token",
        expiresIn: Long = 300,
    ): AccessTokenEntry = AccessTokenEntry(
        accessToken = accessToken,
        expiresAt = fixedEpochSec + expiresIn,
    )

    // MARK: - Happy-path

    @Test
    fun setThenGet_roundTripsThroughBackend() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)
        val entry = makeEntry()

        cache.set(domain, entry)

        assertEquals(entry, cache.get(domain))
        assertEquals(entry, cache.getWithoutExpirationCheck(domain))
    }

    @Test
    fun hydrate_readsWhatSetWrote() {
        val storage = InMemoryAccessTokenStorage()
        val writer = AccessTokenCache(clock = clock, storage = storage)
        val entry = makeEntry()
        writer.set(domain, entry)

        // Fresh cache, same storage — simulates a cold start.
        val reader = AccessTokenCache(clock = clock, storage = storage)
        reader.hydrate(domain)

        assertEquals(entry, reader.get(domain))
    }

    @Test
    fun get_returnsNullWhenEntryHasExpired() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)
        // expiresAt = now - 1 → strictly less than now → expired
        cache.set(domain, makeEntry(expiresIn = -1))

        assertNull(cache.get(domain))
        // But still observable to the profile readers — that's the
        // whole point of `getWithoutExpirationCheck`.
        assertNotNull(cache.getWithoutExpirationCheck(domain))
    }

    @Test
    fun get_returnsEntryAtExactExpiryBoundary() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)
        // expiresAt == now → not yet expired (we use `<` not `<=`).
        cache.set(domain, makeEntry(expiresIn = 0))

        assertNotNull(cache.get(domain))
    }

    @Test
    fun clear_removesFromBothStores() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)
        cache.set(domain, makeEntry())

        cache.clear(domain)

        assertNull(cache.getWithoutExpirationCheck(domain))
        // Confirm via a fresh cache that the persistent row is gone too.
        val reader = AccessTokenCache(clock = clock, storage = storage)
        reader.hydrate(domain)
        assertNull(reader.getWithoutExpirationCheck(domain))
    }

    @Test
    fun invalidate_marksEntryExpiredButKeepsItObservable() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)
        cache.set(domain, makeEntry(expiresIn = 300))

        cache.invalidate(domain)

        assertNull("expired", cache.get(domain))
        val observable = cache.getWithoutExpirationCheck(domain)
        assertNotNull("kept around for profile readers", observable)
        // Implementation: expiresAt = now - 1.
        assertEquals(fixedEpochSec - 1, observable!!.expiresAt)
    }

    @Test
    fun invalidate_isNoOpForUncachedDomain() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)
        // No `set` first — invalidate should not throw and should not
        // create a phantom entry.
        cache.invalidate(domain)

        assertNull(cache.getWithoutExpirationCheck(domain))
    }

    @Test
    fun hydrate_swallowsCorruptBlob() {
        val storage = InMemoryAccessTokenStorage()
        // Pre-seed garbage that won't decode to AccessTokenEntry.
        storage.write(domain, "not-json")

        val cache = AccessTokenCache(clock = clock, storage = storage)
        cache.hydrate(domain)

        // Treated as "no entry" — the next refresh will overwrite it.
        // Throwing here would crash the app on startup if a future
        // schema change left an old blob behind.
        assertNull(cache.getWithoutExpirationCheck(domain))
    }

    @Test
    fun hydrate_swallowsStorageReadFailure() {
        val backend = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        backend.readFailure = IOException("disk gone")

        val cache = AccessTokenCache(clock = clock, storage = backend)
        cache.hydrate(domain) // must not throw

        assertNull(cache.getWithoutExpirationCheck(domain))
    }

    // MARK: - Ordering invariants (storage before memory)

    @Test
    fun failedSet_leavesMemoryUntouched() {
        val backend = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        val cache = AccessTokenCache(clock = clock, storage = backend)
        backend.writeFailure = SessionTokenStoreError.StorageFailure(IOException("disk full"))

        try {
            cache.set(domain, makeEntry())
            fail("expected StorageFailure")
        } catch (_: SessionTokenStoreError.StorageFailure) {
            // expected
        }

        assertNull(
            "memory must not hold the new entry when the storage write failed",
            cache.getWithoutExpirationCheck(domain),
        )
    }

    @Test
    fun failedInvalidate_keepsOriginalEntryInMemory() {
        val backend = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        val cache = AccessTokenCache(clock = clock, storage = backend)

        val original = makeEntry(expiresIn = 300)
        cache.set(domain, original)

        backend.writeFailure = SessionTokenStoreError.StorageFailure(IOException("disk full"))

        try {
            cache.invalidate(domain)
            fail("expected StorageFailure")
        } catch (_: SessionTokenStoreError.StorageFailure) {
            // expected
        }

        // Memory still shows the original `expiresAt` — NOT the
        // `now - 1` expiry that a naive memory-first implementation
        // would have written before the storage write failed.
        assertEquals(original, cache.get(domain))
        assertEquals(original.expiresAt, cache.getWithoutExpirationCheck(domain)?.expiresAt)
    }

    @Test
    fun failedInvalidate_doesNotDivergeFromStorageAcrossColdStart() {
        val backend = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        val cache = AccessTokenCache(clock = clock, storage = backend)

        val original = makeEntry(expiresIn = 300)
        cache.set(domain, original)

        backend.writeFailure = SessionTokenStoreError.StorageFailure(IOException("disk full"))
        try {
            cache.invalidate(domain)
            fail("expected StorageFailure")
        } catch (_: SessionTokenStoreError.StorageFailure) {
            // expected
        }

        // Cold-start a fresh cache against the same backend. The
        // backend's read path is not in the failure set, so the row
        // is readable again.
        val fresh = AccessTokenCache(clock = clock, storage = backend)
        fresh.hydrate(domain)

        // Both views agree: the original entry is intact. Before the
        // storage-first ordering, memory would have said "expired"
        // while the persistent row still held the original — the
        // expiry would silently disappear on restart.
        assertEquals(original, cache.get(domain))
        assertEquals(original, fresh.get(domain))
    }

    @Test
    fun failedClear_leavesEntryObservable() {
        val backend = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        val cache = AccessTokenCache(clock = clock, storage = backend)
        val entry = makeEntry()
        cache.set(domain, entry)

        backend.deleteFailure = SessionTokenStoreError.StorageFailure(IOException("disk full"))

        try {
            cache.clear(domain)
            fail("expected StorageFailure")
        } catch (_: SessionTokenStoreError.StorageFailure) {
            // expected
        }

        // Memory still shows the entry, so the caller can see the clear
        // didn't stick and retry / surface the error. A memory-first
        // implementation would have hidden the entry while leaving the
        // still-present persistent row to resurrect it on next launch.
        assertEquals(entry, cache.get(domain))
    }

    @Test
    fun failedSet_doesNotResurrectPriorEntryOnHydrate() {
        // Belt-and-braces companion to `failedSet_leavesMemoryUntouched`:
        // an aborted overwrite must leave the **persistent** side intact
        // too. SharedPreferences is atomic per `commit()`, but a bug in
        // our wrapper could partially-write. This pins the contract.
        val backend = FailingAccessTokenStorage(InMemoryAccessTokenStorage())
        val cache = AccessTokenCache(clock = clock, storage = backend)
        val first = makeEntry(accessToken = "first", expiresIn = 300)
        cache.set(domain, first)

        backend.writeFailure = SessionTokenStoreError.StorageFailure(IOException("disk full"))
        assertThrows(SessionTokenStoreError.StorageFailure::class.java) {
            cache.set(domain, makeEntry(accessToken = "second", expiresIn = 600))
        }

        // The first entry is still what cold-start hydrate sees.
        val fresh = AccessTokenCache(clock = clock, storage = backend)
        fresh.hydrate(domain)
        assertEquals(first, fresh.get(domain))
    }

    // MARK: - Concurrency

    @Test
    fun get_doesNotObservePartialWrite() {
        // Drives N writers + N readers against the cache and asserts
        // every read either sees `null` or a fully-formed entry — no
        // half-applied state where the in-memory map and storage
        // disagree about the expiry.
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)

        val iterations = 500
        // An AssertionError raised in a child Thread terminates that
        // thread silently — Thread.join() returns clean and a JUnit
        // assertion in the lambda below would never fail the test.
        // Capture the first failure from either thread and re-throw
        // on the JUnit thread once both have joined.
        val childFailure = AtomicReference<Throwable?>(null)
        val captureFirst = Thread.UncaughtExceptionHandler { _, e ->
            childFailure.compareAndSet(null, e)
        }

        val writer = Thread {
            repeat(iterations) { i ->
                cache.set(domain, makeEntry(accessToken = "token-$i", expiresIn = 300))
            }
        }.apply { uncaughtExceptionHandler = captureFirst }

        val reader = Thread {
            repeat(iterations) {
                val seen = cache.getWithoutExpirationCheck(domain)
                if (seen != null) {
                    // Token-N → expiresAt always > now. If the cache
                    // ever returned an entry with a half-applied
                    // expiry, this would catch it.
                    assertTrue(
                        "saw entry with stale or zero expiresAt: $seen",
                        seen.expiresAt > fixedEpochSec,
                    )
                }
            }
        }.apply { uncaughtExceptionHandler = captureFirst }

        writer.start(); reader.start()
        writer.join(); reader.join()

        // Surface a child-thread assertion failure as a test failure
        // on the JUnit thread. Without this, Thread.join() would
        // return cleanly and the test would pass even though the
        // reader's invariant check raised.
        childFailure.get()?.let { throw AssertionError("child thread failed: ${it.message}", it) }

        // Final state is the last write — basic liveness check that
        // both threads ran to completion.
        assertEquals("token-${iterations - 1}", cache.getWithoutExpirationCheck(domain)?.accessToken)
    }

    // MARK: - Backend identity

    @Test
    fun multipleDomains_areIsolated() {
        val storage = InMemoryAccessTokenStorage()
        val cache = AccessTokenCache(clock = clock, storage = storage)

        cache.set("a.example.com", makeEntry(accessToken = "a-token"))
        cache.set("b.example.com", makeEntry(accessToken = "b-token"))

        assertEquals("a-token", cache.get("a.example.com")?.accessToken)
        assertEquals("b-token", cache.get("b.example.com")?.accessToken)

        cache.clear("a.example.com")
        assertNull(cache.getWithoutExpirationCheck("a.example.com"))
        assertNotNull(cache.getWithoutExpirationCheck("b.example.com"))
    }

    @Test
    fun get_doesNotRedecodePersistedBlobEachCall() {
        // Once hydrated, in-memory access is the fast path. We verify
        // it by counting reads against the storage backend rather than
        // pinning the in-memory map's identity invariants — the latter
        // is implementation detail, the former is the contract.
        val storage = CountingAccessTokenStorage(InMemoryAccessTokenStorage())
        val cache = AccessTokenCache(clock = clock, storage = storage)
        val entry = makeEntry()
        cache.set(domain, entry)

        val readsBefore = storage.readCount
        repeat(10) { assertEquals(entry, cache.get(domain)) }
        assertEquals(
            "get should not touch storage once the entry is in memory",
            readsBefore,
            storage.readCount,
        )
    }
}
