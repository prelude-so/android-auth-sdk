package so.prelude.android.session.http

import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.dpop.FakeDPoPKeyStore
import java.util.Base64

/**
 * [DPoPInterceptor] nonce-cache mechanics across requests: harvest
 * → reuse → overwrite → cold-start replay → empty-as-absent. Per-call
 * proof shape lives in [DPoPInterceptorTest]; the
 * `use_dpop_nonce` 4xx retry path lives in
 * [DPoPInterceptorChallengeTest].
 */
class DPoPInterceptorNonceLifecycleTest {
    private val domain = "api.example.com"

    private fun mkRequest(): Request =
        Request.Builder().url("https://api.example.com/v1/me").build()

    private fun mkResponse(
        request: Request,
        code: Int = 200,
        nonce: String? = null,
    ): Response {
        val builder = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message("OK")
            .body("{}".toResponseBody("application/json".toMediaType()))
        if (nonce != null) builder.header(HttpHeader.DPOP_NONCE, nonce)
        return builder.build()
    }

    private fun decodePayload(proof: String): String =
        String(Base64.getUrlDecoder().decode(proof.split('.')[1]))

    /**
     * Full lifecycle: nonce minted on call 1's response must be
     * carried into call 2's outgoing proof, otherwise the server
     * re-issues a `use_dpop_nonce` challenge on every request
     * (RFC 9449 §8).
     */
    @Test
    fun harvestedNonce_isReusedOnSubsequentCall() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        val proofs = mutableListOf<String>()
        val send: SendFunction = { req ->
            proofs += req.header(HttpHeader.DPOP) ?: ""
            mkResponse(req, nonce = "n-from-call-1")
        }

        interceptor.intercept(mkRequest(), send).close()
        interceptor.intercept(mkRequest(), send).close()

        assertTrue("call 1 has no nonce", "\"nonce\"" !in decodePayload(proofs[0]))
        assertTrue(
            "call 2 must reuse harvested nonce",
            "\"nonce\":\"n-from-call-1\"" in decodePayload(proofs[1]),
        )
    }

    @Test
    fun proof_omitsNonceOnFirstRequestForFreshDomain() = runTest {
        val store = FakeDPoPKeyStore()
        val interceptor = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req)
        }

        interceptor.intercept(mkRequest(), send).close()

        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue("first proof must not contain a nonce", "\"nonce\"" !in payload)
    }

    /**
     * Each 2xx with a `DPoP-Nonce` advances the cache: subsequent
     * proofs must carry the latest, not the initial. Without this
     * the SDK would replay a stale nonce and pay for a fresh
     * `use_dpop_nonce` challenge on every request after the first.
     */
    @Test
    fun successful2xx_freshNonceHeader_overridesCachedNonce() = runTest {
        val store = FakeDPoPKeyStore().apply { setNonce(domain, "stale") }
        val interceptor = DPoPInterceptor(store, domain)
        val proofs = mutableListOf<String>()
        var calls = 0
        val send: SendFunction = { req ->
            proofs += req.header(HttpHeader.DPOP) ?: ""
            calls += 1
            mkResponse(req, nonce = if (calls == 1) "fresh" else null)
        }

        interceptor.intercept(mkRequest(), send).close()
        interceptor.intercept(mkRequest(), send).close()

        // Cache advanced to the response's nonce on call 1.
        assertEquals("fresh", store.getNonce(domain))
        // Call 1 sent the seeded `stale`; call 2 reuses the freshly
        // overwritten `fresh` — pinning the override semantic, not
        // just "we wrote something".
        assertTrue(
            "call 1 must carry the seeded stale nonce; was: ${decodePayload(proofs[0])}",
            "\"nonce\":\"stale\"" in decodePayload(proofs[0]),
        )
        assertTrue(
            "call 2 must carry the overwritten fresh nonce; was: ${decodePayload(proofs[1])}",
            "\"nonce\":\"fresh\"" in decodePayload(proofs[1]),
        )
    }

    /**
     * Cold-start optimisation: nonce persists across DPoPInterceptor
     * instances (real backing is private SharedPreferences — see
     * [so.prelude.android.session.dpop.DPoPNonceStore]). On the
     * first request after process restart the interceptor must
     * replay the persisted nonce, so the server skips its
     * `use_dpop_nonce` challenge and the cold-start path is one
     * round-trip rather than two.
     */
    @Test
    fun coldStart_reusesPersistedNonce_withoutChallengeRoundTrip() = runTest {
        // Same backing store survives the "process restart" — the
        // new interceptor instance simulates a cold start over a
        // pre-populated nonce store.
        val store = FakeDPoPKeyStore().apply { setNonce(domain, "persisted-from-prior-run") }
        val cold = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        var calls = 0
        val send: SendFunction = { req ->
            seenRequest = req
            calls += 1
            mkResponse(req)
        }

        cold.intercept(mkRequest(), send).close()

        assertEquals("cold start must hit the wire exactly once", 1, calls)
        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue(
            "cold start must replay the persisted nonce; was: $payload",
            "\"nonce\":\"persisted-from-prior-run\"" in payload,
        )
    }

    @Test
    fun emptyStoredNonce_isTreatedAsAbsent() = runTest {
        // Wedged in directly — production path normalises empty to delete.
        val store = FakeDPoPKeyStore().apply { setNonce(domain, "") }
        val interceptor = DPoPInterceptor(store, domain)
        var seenRequest: Request? = null
        val send: SendFunction = { req ->
            seenRequest = req
            mkResponse(req)
        }

        interceptor.intercept(mkRequest(), send).close()

        val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
        assertTrue("empty-string nonce must not be sent", "\"nonce\"" !in payload)
    }
}
