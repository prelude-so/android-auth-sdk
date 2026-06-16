package so.prelude.android.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader
import so.prelude.android.auth.store.DeviceIDStore
import so.prelude.android.auth.store.FailingDeviceIDStorage
import so.prelude.android.auth.store.InMemoryDeviceIDStorage
import so.prelude.android.auth.store.TokenStoreError
import java.util.UUID

/**
 * `X-Device-Id` is attached to every session request and the
 * underlying id is stable across calls — generated once per
 * domain and persisted, so the backend can correlate requests
 * from this install without a cookie.
 */
class DeviceIDTest {
    @Test
    fun deviceIdHeader_isAttachedAndStable_acrossRequests() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install(
                "/v1/session/otp",
                StubHttpSession.Canned.json("{}", statusCode = 204),
            )

            repeat(2) {
                fixture.client.startOTPLogin(
                    StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
                )
            }

            val headers =
                fixture.http
                    .requestsFor("/v1/session/otp")
                    .mapNotNull { it.header(HttpHeader.DEVICE_ID) }
            assertEquals("every request must carry X-Device-Id", 2, headers.size)
            assertEquals("device id must be stable", headers[0], headers[1])
            assertNotNull("device id must be a UUID", UUID.fromString(headers[0]))
        }

    /**
     * Device id is best-effort — if the store faults (e.g. disk
     * failure) the request must still go out, just without
     * [HttpHeader.DEVICE_ID]; it must never fail the chain.
     */
    @Test
    fun deviceIdHeader_isOmittedNotFatal_whenStoreFails() =
        runBlocking {
            val storage =
                FailingDeviceIDStorage().apply {
                    readFailure = TokenStoreError.StorageFailure(IllegalStateException("disk fault"))
                }
            val fixture = Fixture.make(deviceIDStorage = storage)
            fixture.http.install(
                "/v1/session/otp",
                StubHttpSession.Canned.json("{}", statusCode = 204),
            )

            fixture.client.startOTPLogin(
                StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
            )

            val requests = fixture.http.requestsFor("/v1/session/otp")
            assertEquals("request must still be sent", 1, requests.size)
            assertNull("header must be omitted, not fatal", requests[0].header(HttpHeader.DEVICE_ID))
        }

    @Test
    fun deviceIDStore_getOrCreate_isIdempotent() {
        val store = DeviceIDStore(storage = InMemoryDeviceIDStorage())
        val first = store.getOrCreate("example.com")
        val second = store.getOrCreate("example.com")
        assertEquals(first, second)
        assertFalse(first.isEmpty())
    }

    /**
     * Parallel first-time callers must converge on one id — the
     * in-process lock keeps the read-then-write window race-free.
     */
    @Test
    fun deviceIDStore_concurrentGetOrCreate_convergesOnOneID() =
        runBlocking {
            val store = DeviceIDStore(storage = InMemoryDeviceIDStorage())
            val domain = "example.com"

            val ids =
                (1..16)
                    .map { async { store.getOrCreate(domain) } }
                    .awaitAll()

            assertEquals(
                "all callers must observe one id; got ${ids.toSet()}",
                1,
                ids.toSet().size,
            )
        }
}
