package so.prelude.android.auth.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * Unit tests for [RefreshTokenStore].
 *
 * The store has moving parts worth covering directly (JSON
 * encode/decode, separate storage abstraction).
 *
 * Structure parallels [AccessTokenCacheTest]: round-trip / hydrate-
 * equivalent / corrupt-blob / failure-injection.
 */
class RefreshTokenStoreTest {
    private val domain = "app.example.com"

    private fun makeRecord(
        token: String = "refresh-v1",
        expiresAt: String? = "2026-12-31T23:59:59Z",
    ): RefreshTokenRecord =
        RefreshTokenRecord(
            refreshToken = token,
            refreshTokenExpiresAt = expiresAt,
        )

    // MARK: - Happy-path

    @Test
    fun setThenGet_roundTripsThroughBackend() {
        val store = RefreshTokenStore(InMemoryRefreshTokenStorage())
        val record = makeRecord()

        store.set(domain, record)

        assertEquals(record, store.get(domain))
    }

    @Test
    fun get_returnsNullWhenNothingPersisted() {
        val store = RefreshTokenStore(InMemoryRefreshTokenStorage())
        assertNull(store.get(domain))
    }

    @Test
    fun get_acrossInstances_seesPersistedRecord() {
        // A fresh store sharing the same backend simulates a cold
        // start. The store has no in-memory cache, so this is also
        // implicitly a "no caching layer" assertion.
        val storage = InMemoryRefreshTokenStorage()
        val writer = RefreshTokenStore(storage)
        val record = makeRecord()
        writer.set(domain, record)

        val reader = RefreshTokenStore(storage)
        assertEquals(record, reader.get(domain))
    }

    @Test
    fun set_withNullExpiresAt_roundTrips() {
        // The server sometimes omits `X-Refresh-Token-Expires-At`;
        // the store must persist that absence faithfully so the
        // refresh path doesn't mistake an unknown expiry for an
        // arbitrary epoch string.
        val store = RefreshTokenStore(InMemoryRefreshTokenStorage())
        store.set(domain, makeRecord(expiresAt = null))

        assertEquals(null, store.get(domain)?.refreshTokenExpiresAt)
    }

    @Test
    fun delete_removesRecord() {
        val storage = InMemoryRefreshTokenStorage()
        val store = RefreshTokenStore(storage)
        store.set(domain, makeRecord())

        store.delete(domain)

        assertNull(store.get(domain))
        // Cold-start equivalent: a fresh store sees nothing too.
        assertNull(RefreshTokenStore(storage).get(domain))
    }

    @Test
    fun delete_isNoOpForMissingDomain() {
        val store = RefreshTokenStore(InMemoryRefreshTokenStorage())
        // No `set` first — delete must not throw and must not write
        // a phantom row.
        store.delete(domain)
        assertNull(store.get(domain))
    }

    @Test
    fun set_overwritesPreviousRecord() {
        val store = RefreshTokenStore(InMemoryRefreshTokenStorage())
        store.set(domain, makeRecord(token = "v1"))
        store.set(domain, makeRecord(token = "v2"))

        assertEquals("v2", store.get(domain)?.refreshToken)
    }

    @Test
    fun get_treatsCorruptBlobAsMissing() {
        val storage = InMemoryRefreshTokenStorage()
        // Pre-seed garbage that won't decode to RefreshTokenRecord.
        // A future schema change might leave older blobs behind; the
        // recovery path is a fresh login, so a decode failure
        // surfaces as "no record" rather than crashing the app.
        storage.write(domain, "not-json")

        val store = RefreshTokenStore(storage)

        assertNull(store.get(domain))
    }

    @Test
    fun multipleDomains_areIsolated() {
        val store = RefreshTokenStore(InMemoryRefreshTokenStorage())
        store.set("a.example.com", makeRecord(token = "a-token"))
        store.set("b.example.com", makeRecord(token = "b-token"))

        assertEquals("a-token", store.get("a.example.com")?.refreshToken)
        assertEquals("b-token", store.get("b.example.com")?.refreshToken)

        store.delete("a.example.com")
        assertNull(store.get("a.example.com"))
        assertNotNull(store.get("b.example.com"))
    }

    // MARK: - Failure modes

    @Test
    fun set_propagatesStorageWriteFailure() {
        val backend = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage())
        backend.writeFailure = TokenStoreError.StorageFailure(IOException("disk full"))
        val store = RefreshTokenStore(backend)

        try {
            store.set(domain, makeRecord())
            fail("expected StorageFailure")
        } catch (_: TokenStoreError.StorageFailure) {
            // expected — the rotated-token write must not silently
            // drop or the next refresh will 401 with no recovery.
        }
    }

    @Test
    fun delete_propagatesStorageDeleteFailure() {
        val backend = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage())
        backend.deleteFailure = TokenStoreError.StorageFailure(IOException("disk full"))
        val store = RefreshTokenStore(backend)

        assertThrows(TokenStoreError.StorageFailure::class.java) {
            store.delete(domain)
        }
    }

    @Test
    fun get_propagatesStorageReadFailure() {
        // Distinct from the corrupt-blob path above: a corrupt blob
        // is "the row exists but can't be parsed", which we swallow.
        // A read fault (storage unavailable, IO error) is "we can't
        // even tell if a row exists", which must surface so the
        // caller can decide whether to retry or hard-logout.
        val backend = FailingRefreshTokenStorage(InMemoryRefreshTokenStorage())
        backend.readFailure = IOException("disk gone")
        val store = RefreshTokenStore(backend)

        assertThrows(IOException::class.java) {
            store.get(domain)
        }
    }
}
