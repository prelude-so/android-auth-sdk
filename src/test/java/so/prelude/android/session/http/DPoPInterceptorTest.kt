package so.prelude.android.session.http

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.PreludeSessionError
import so.prelude.android.session.dpop.FakeDPoPKeyStore
import java.io.IOException
import java.util.Base64

class DPoPInterceptorTest {
    private val domain = "api.example.com"

    private fun mkRequest(url: String = "https://api.example.com/v1/me"): Request =
        Request.Builder().url(url).build()

    private fun mkResponse(
        request: Request,
        code: Int,
        body: String = "{}",
        nonce: String? = null,
    ): Response {
        val builder = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message(if (code in 200..299) "OK" else "Error")
            .body(body.toResponseBody("application/json".toMediaType()))
        if (nonce != null) builder.header(HttpHeader.DPOP_NONCE, nonce)
        return builder.build()
    }

    /** Decode a DPoP JWT's payload segment. */
    private fun decodePayload(proof: String): String =
        String(Base64.getUrlDecoder().decode(proof.split('.')[1]))

    @Test
    fun happyPath_writesDPoPHeaderAndHarvestsNonce() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req, 200, nonce = "fresh-1")
        }

        val response = interceptor.intercept(mkRequest(), send)

        assertEquals(200, response.code)
        assertNotNull(seenRequest!!.header(HttpHeader.DPOP))
        assertEquals("fresh-1", store.getNonce(domain))
        response.close()
    }

    @Test
    fun useDPoPNonce_4xx_retriesWithFreshNonce() = runTest {
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
        // First proof has no nonce, retry has nonce "n1".
        assertTrue("first proof should not include nonce", "\"nonce\"" !in decodePayload(proofs[0]))
        assertTrue("retry proof must include the fresh nonce", "\"nonce\":\"n1\"" in decodePayload(proofs[1]))
        // Final harvested nonce comes from the retry response.
        assertEquals("n2", store.getNonce(domain))
        response.close()
    }

    /**
     * Regression for the "persist nonce before retry" change.
     * If the retry throws, the fresh nonce must still be persisted so
     * the next request doesn't re-trigger the use_dpop_nonce challenge.
     */
    @Test
    fun useDPoPNonce_retryThrows_freshNonceStillPersisted() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)

        var calls = 0
        val send: SendFunction = { req ->
            calls += 1
            if (calls == 1) {
                mkResponse(req, 400, body = """{"code":"use_dpop_nonce"}""", nonce = "n1")
            } else {
                throw PreludeSessionError.Network(IOException("connection reset"))
            }
        }

        val thrown = runCatching { interceptor.intercept(mkRequest(), send) }
            .exceptionOrNull()

        assertTrue("expected Network error, got $thrown", thrown is PreludeSessionError.Network)
        assertEquals(2, calls)
        // Even though the retry blew up, we kept the fresh nonce.
        assertEquals("n1", store.getNonce(domain))
    }

    @Test
    fun useDPoPNonce_withoutFreshNonceHeader_throwsExplicitly() {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        val send: SendFunction = { req ->
            mkResponse(req, 400, body = """{"code":"use_dpop_nonce"}""", nonce = null)
        }

        val thrown = assertThrows(PreludeSessionError.Generic::class.java) {
            runBlocking { interceptor.intercept(mkRequest(), send) }
        }
        assertEquals("missing_dpop_nonce_header", thrown.code)
    }

    @Test
    fun nonNonceFailure_passesThrough_withoutRetry() = runTest {
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
     * Regression: `hostOverride` previously forwarded host+port through
     * OkHttp's `host()`, which rejects port-bearing strings. The override
     * must accept `host:port` verbatim.
     */
    @Test
    fun hostOverride_withPort_doesNotThrow_andShapesHtu() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(
            keyStore = store,
            domain = domain,
            hostOverride = "sessdev.example.com:443",
        )
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req, 200)
        }

        interceptor.intercept(mkRequest("https://127.0.0.1:3000/v1/me"), send).close()

        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue(
            "htu should reflect the host:port override, was: $payload",
            "\"htu\":\"https://sessdev.example.com:443/v1/me\"" in payload,
        )
    }

    @Test
    fun htu_stripsQueryAndFragment() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req, 200)
        }

        interceptor.intercept(
            mkRequest("https://api.example.com/v1/login?token=xyz#frag"),
            send,
        ).close()

        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue(
            "htu must omit query and fragment per RFC 9449 §4.2; was: $payload",
            "\"htu\":\"https://api.example.com/v1/login\"" in payload,
        )
    }

    @Test
    fun proof_omitsNonceOnFirstRequestForFreshDomain() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req, 200)
        }

        interceptor.intercept(mkRequest(), send).close()

        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue("first proof must not contain a nonce", "\"nonce\"" !in payload)
    }

    @Test
    fun emptyStoredNonce_isTreatedAsAbsent() = runTest {
        val store = FakeDPoPKeyStore()
        store.setNonce(domain, "") // wedged in directly; production path normalises this away
        val interceptor = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req, 200)
        }

        interceptor.intercept(mkRequest(), send).close()

        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue("empty-string nonce must not be sent", "\"nonce\"" !in payload)
    }
}
