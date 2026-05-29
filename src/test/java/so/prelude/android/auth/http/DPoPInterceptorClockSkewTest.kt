package so.prelude.android.auth.http

import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale
import kotlin.math.abs

/**
 * `invalid_dpop_proof` + clock-skew retry path:
 *  - retry once when `|skew| >= 1_000ms`,
 *  - persist the skew so subsequent requests are pre-corrected,
 *  - leave sub-threshold / unparseable-`Date` responses alone so
 *    an unrelated `invalid_dpop_proof` surfaces as itself.
 */
class DPoPInterceptorClockSkewTest {
    private val domain = "api.example.com"

    private fun mkRequest(): Request = Request.Builder().url("https://api.example.com/v1/me").build()

    private fun mkResponse(
        request: Request,
        code: Int,
        body: String = "{}",
        date: String? = null,
    ): Response {
        val builder =
            Response
                .Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message(if (code in 200..299) "OK" else "Error")
                .body(body.toResponseBody("application/json".toMediaType()))
        if (date != null) builder.header(HttpHeader.DATE, date)
        return builder.build()
    }

    private fun httpDate(instant: Instant): String =
        DateTimeFormatter
            .ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)
            .withZone(ZoneOffset.UTC)
            .format(instant)

    private fun iat(proof: String): Long {
        val payload = String(Base64.getUrlDecoder().decode(proof.split('.')[1]))
        return Regex("\"iat\":(\\d+)").find(payload)!!.groupValues[1].toLong()
    }

    // (a) Skew above threshold → retry once and persist.
    @Test
    fun invalidDPoPProof_aboveThreshold_persistsSkewAndRetries() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            val serverAheadMs = 30_000L
            val proofs = mutableListOf<String>()
            var calls = 0
            val send: SendFunction = { req ->
                proofs += req.header(HttpHeader.DPOP) ?: ""
                calls += 1
                if (calls == 1) {
                    mkResponse(
                        req,
                        400,
                        body = """{"code":"invalid_dpop_proof"}""",
                        date = httpDate(Instant.now().plusMillis(serverAheadMs)),
                    )
                } else {
                    mkResponse(req, 200)
                }
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(2, calls)
            assertEquals(200, response.code)
            val persisted = store.getClockSkewMs(domain)
            assertNotNull(persisted)
            assertTrue(
                "expected skew ~${serverAheadMs}ms, got $persisted",
                abs(persisted!! - serverAheadMs) <= 2_000,
            )
            // Retry proof's `iat` must lie in the server's frame.
            val retryIat = iat(proofs[1])
            val expectedSec = (System.currentTimeMillis() + serverAheadMs) / 1000
            assertTrue(
                "retry iat $retryIat must be near $expectedSec",
                abs(retryIat - expectedSec) <= 3,
            )
            response.close()
        }

    // (b) Sub-threshold skew → no retry. Server `Date:` resolution
    // is whole seconds, so a header at current wall-clock yields a
    // computed skew in [-999, +999]ms — strictly below threshold.
    @Test
    fun invalidDPoPProof_subThresholdSkew_doesNotRetry() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var calls = 0
            val send: SendFunction = { req ->
                calls += 1
                mkResponse(
                    req,
                    400,
                    body = """{"code":"invalid_dpop_proof"}""",
                    date = httpDate(Instant.now()),
                )
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(1, calls)
            assertEquals(400, response.code)
            assertNull("skew below threshold must not be persisted", store.getClockSkewMs(domain))
            response.close()
        }

    // (c) Missing Date header → no retry.
    @Test
    fun invalidDPoPProof_noDateHeader_doesNotRetry() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var calls = 0
            val send: SendFunction = { req ->
                calls += 1
                mkResponse(req, 400, body = """{"code":"invalid_dpop_proof"}""", date = null)
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(1, calls)
            assertEquals(400, response.code)
            assertNull(store.getClockSkewMs(domain))
            response.close()
        }

    // (d) Persisted skew is reused on the next, unrelated request.
    @Test
    fun persistedSkew_isAppliedOnSubsequentRequest() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            val persistedSkewMs = 45_000L
            store.setClockSkewMs(domain, persistedSkewMs)

            var seen: Request? = null
            val send: SendFunction = { req ->
                seen = req
                mkResponse(req, 200)
            }

            interceptor.intercept(mkRequest(), send).close()

            val proofIat = iat(seen!!.header(HttpHeader.DPOP)!!)
            val expectedSec = (System.currentTimeMillis() + persistedSkewMs) / 1000
            assertTrue(
                "first proof after a cached skew must already be corrected (iat=$proofIat, expected≈$expectedSec)",
                abs(proofIat - expectedSec) <= 3,
            )
        }

    // (f) Stale persisted skew + sub-threshold server skew →
    // clear the stale value so the next request self-heals. Without
    // this, a post-NTP-sync device keeps replaying e.g. +30s forever
    // because every retry computes ~0 ms drift (below threshold) and
    // returns early without touching the store.
    @Test
    fun invalidDPoPProof_subThresholdSkew_clearsStalePersistedSkew() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setClockSkewMs(domain, 30_000L) // stale, pre-resync
            val interceptor = DPoPInterceptor(store, domain)
            var calls = 0
            val send: SendFunction = { req ->
                calls += 1
                mkResponse(
                    req,
                    400,
                    body = """{"code":"invalid_dpop_proof"}""",
                    date = httpDate(Instant.now()),
                )
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(1, calls)
            assertEquals(400, response.code)
            assertNull("stale skew must be cleared", store.getClockSkewMs(domain))
            response.close()
        }

    // (e) Server rotates `DPoP-Nonce` on the error response → the
    // retry must use (and persist) the rotated value, not the
    // stale stored one. Otherwise the retry would itself fail
    // `use_dpop_nonce` with no second retry available.
    @Test
    fun invalidDPoPProof_rotatedNonce_isHarvestedAndUsedOnRetry() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setNonce(domain, "stale-nonce")
            val interceptor = DPoPInterceptor(store, domain)
            val rotatedNonce = "rotated-nonce"
            val proofs = mutableListOf<String>()
            var calls = 0
            val send: SendFunction = { req ->
                proofs += req.header(HttpHeader.DPOP) ?: ""
                calls += 1
                if (calls == 1) {
                    Response
                        .Builder()
                        .request(req)
                        .protocol(Protocol.HTTP_1_1)
                        .code(400)
                        .message("Error")
                        .body("""{"code":"invalid_dpop_proof"}""".toResponseBody("application/json".toMediaType()))
                        .header(HttpHeader.DATE, httpDate(Instant.now().plusMillis(30_000L)))
                        .header(HttpHeader.DPOP_NONCE, rotatedNonce)
                        .build()
                } else {
                    mkResponse(req, 200)
                }
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(2, calls)
            assertEquals(200, response.code)
            assertEquals(rotatedNonce, store.getNonce(domain))
            // Retry proof must carry the rotated nonce, not the stale one.
            val retryPayload = String(Base64.getUrlDecoder().decode(proofs[1].split('.')[1]))
            val retryNonce = Regex("\"nonce\":\"([^\"]+)\"").find(retryPayload)?.groupValues?.get(1)
            assertEquals(rotatedNonce, retryNonce)
            response.close()
        }
}
