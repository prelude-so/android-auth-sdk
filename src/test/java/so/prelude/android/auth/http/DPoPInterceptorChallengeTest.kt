package so.prelude.android.auth.http

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import java.io.IOException
import java.util.Base64

/**
 * `use_dpop_nonce` 4xx → re-sign + retry path. The nonce-lifecycle
 * happy path lives in [DPoPInterceptorTest].
 */
class DPoPInterceptorChallengeTest {
    private val domain = "api.example.com"

    private fun mkRequest(): Request = Request.Builder().url("https://api.example.com/v1/me").build()

    private fun mkResponse(
        request: Request,
        code: Int,
        body: String = "{}",
        nonce: String? = null,
    ): Response {
        val builder =
            Response
                .Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message(if (code in 200..299) "OK" else "Error")
                .body(body.toResponseBody("application/json".toMediaType()))
        if (nonce != null) builder.header(HttpHeader.DPOP_NONCE, nonce)
        return builder.build()
    }

    private fun decodePayload(proof: String): String = String(Base64.getUrlDecoder().decode(proof.split('.')[1]))

    private fun jtiFrom(payload: String): String? = Regex("\"jti\":\"([^\"]+)\"").find(payload)?.groupValues?.get(1)

    @Test
    fun useDPoPNonce_4xx_retriesWithFreshNonce() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            val proofs = mutableListOf<String>()
            var calls = 0
            val send: SendFunction = { req ->
                proofs += req.header(HttpHeader.DPOP) ?: ""
                calls += 1
                if (calls == 1) {
                    mkResponse(req, 400, body = """{"code":"use_dpop_nonce"}""", nonce = "n1")
                } else {
                    mkResponse(req, 200, nonce = "n2")
                }
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(2, calls)
            assertEquals(200, response.code)
            assertTrue("first proof omits nonce", "\"nonce\"" !in decodePayload(proofs[0]))
            assertTrue(
                "retry proof includes the fresh nonce",
                "\"nonce\":\"n1\"" in decodePayload(proofs[1]),
            )
            // Final harvested nonce comes from the retry response.
            assertEquals("n2", store.getNonce(domain))
            response.close()
        }

    /**
     * Regression: persist-before-retry. If the retry throws, the
     * fresh nonce must already be stored so the next request
     * doesn't re-trigger the challenge.
     */
    @Test
    fun useDPoPNonce_retryThrows_freshNonceStillPersisted() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var calls = 0
            val send: SendFunction = { req ->
                calls += 1
                if (calls == 1) {
                    mkResponse(req, 400, body = """{"code":"use_dpop_nonce"}""", nonce = "n1")
                } else {
                    throw PreludeAuthError.Network(IOException("connection reset"))
                }
            }

            val thrown = runCatching { interceptor.intercept(mkRequest(), send) }.exceptionOrNull()

            assertTrue("expected Network error, got $thrown", thrown is PreludeAuthError.Network)
            assertEquals(2, calls)
            assertEquals("n1", store.getNonce(domain))
        }

    @Test
    fun useDPoPNonce_withoutFreshNonceHeader_throwsExplicitly() {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        val send: SendFunction = { req ->
            mkResponse(req, 400, body = """{"code":"use_dpop_nonce"}""", nonce = null)
        }

        val thrown =
            assertThrows(PreludeAuthError.Generic::class.java) {
                runBlocking { interceptor.intercept(mkRequest(), send) }
            }
        assertEquals("missing_dpop_nonce_header", thrown.code)
    }

    @Test
    fun nonNonceFailure_passesThrough_withoutRetry() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var calls = 0
            val send: SendFunction = { req ->
                calls += 1
                mkResponse(req, 401, body = """{"code":"unauthorized"}""", nonce = "nx")
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(1, calls)
            assertEquals(401, response.code)
            // Still harvest nonce from the non-retry response.
            assertEquals("nx", store.getNonce(domain))
            response.close()
        }

    /**
     * RFC 9449 §4.2: every proof MUST carry a unique `jti`. The
     * `use_dpop_nonce` retry mints a brand-new proof — the original's
     * jti must not leak in, otherwise a server enforcing strict
     * replay protection rejects the retry as a replay.
     */
    @Test
    fun useDPoPNonce_retry_usesFreshJti() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            val proofs = mutableListOf<String>()
            var calls = 0
            val send: SendFunction = { req ->
                proofs += req.header(HttpHeader.DPOP) ?: ""
                calls += 1
                if (calls == 1) {
                    mkResponse(req, 400, body = """{"code":"use_dpop_nonce"}""", nonce = "n1")
                } else {
                    mkResponse(req, 200)
                }
            }

            interceptor.intercept(mkRequest(), send).close()

            val firstJti = jtiFrom(decodePayload(proofs[0]))
            val retryJti = jtiFrom(decodePayload(proofs[1]))
            assertNotNull(firstJti)
            assertNotNull(retryJti)
            assertNotEquals("retry must mint a fresh jti", firstJti, retryJti)
        }
}
