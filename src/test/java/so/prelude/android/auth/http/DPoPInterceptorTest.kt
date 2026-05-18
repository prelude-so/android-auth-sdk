package so.prelude.android.auth.http

import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import java.util.Base64

/**
 * [DPoPInterceptor] per-request proof shape: harvest, fresh JTI,
 * htm/htu/iat claims, host override. Nonce-cache mechanics across
 * requests live in [DPoPInterceptorNonceLifecycleTest]; the
 * `use_dpop_nonce` 4xx retry path lives in
 * [DPoPInterceptorChallengeTest].
 */
class DPoPInterceptorTest {
    private val domain = "api.example.com"

    private fun mkRequest(url: String = "https://api.example.com/v1/me"): Request = Request.Builder().url(url).build()

    private fun mkResponse(
        request: Request,
        code: Int = 200,
        nonce: String? = null,
    ): Response {
        val builder =
            Response
                .Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message("OK")
                .body("{}".toResponseBody("application/json".toMediaType()))
        if (nonce != null) builder.header(HttpHeader.DPOP_NONCE, nonce)
        return builder.build()
    }

    /** Decode a DPoP JWT's payload segment. */
    private fun decodePayload(proof: String): String = String(Base64.getUrlDecoder().decode(proof.split('.')[1]))

    /** Extract the `jti` claim from a DPoP proof payload string. */
    private fun jtiFrom(payload: String): String? = Regex("\"jti\":\"([^\"]+)\"").find(payload)?.groupValues?.get(1)

    @Test
    fun happyPath_writesDPoPHeaderAndHarvestsNonce() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req, nonce = "fresh-1")
            }

            val response = interceptor.intercept(mkRequest(), send)

            assertEquals(200, response.code)
            assertNotNull(seenRequest!!.header(HttpHeader.DPOP))
            assertEquals("fresh-1", store.getNonce(domain))
            response.close()
        }

    /**
     * RFC 9449 §4.2: each proof MUST carry a unique `jti`. Two
     * sequential intercept calls must mint distinct identifiers.
     */
    @Test
    fun proof_freshJtiPerIntercept() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            val proofs = mutableListOf<String>()
            val send: SendFunction = { req ->
                proofs += req.header(HttpHeader.DPOP) ?: ""
                mkResponse(req)
            }

            interceptor.intercept(mkRequest(), send).close()
            interceptor.intercept(mkRequest(), send).close()

            val jti1 = jtiFrom(decodePayload(proofs[0]))
            val jti2 = jtiFrom(decodePayload(proofs[1]))
            assertNotNull(jti1)
            assertNotNull(jti2)
            assertNotEquals("each proof must mint a fresh jti", jti1, jti2)
        }

    /** Regression: `host()` rejected `host:port`; the SDK accepts it verbatim. */
    @Test
    fun hostOverride_withPort_doesNotThrow_andShapesHtu() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain, hostOverride = "sessdev.example.com:443")
            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor.intercept(mkRequest("https://127.0.0.1:3000/v1/me"), send).close()

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            assertTrue(
                "htu should reflect host:port override, was: $payload",
                "\"htu\":\"https://sessdev.example.com:443/v1/me\"" in payload,
            )
        }

    @Test
    fun htu_stripsQueryAndFragment() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor
                .intercept(
                    mkRequest("https://api.example.com/v1/login?token=xyz#frag"),
                    send,
                ).close()

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            assertTrue(
                "htu must omit query and fragment per RFC 9449 §4.2; was: $payload",
                "\"htu\":\"https://api.example.com/v1/login\"" in payload,
            )
        }

    /**
     * Pins three RFC 9449 §4.2 claims that the existing tests only
     * touch indirectly: `htm` mirrors the request method, `htu` keeps
     * the scheme/host lowercase, and `iat` lands within a small
     * window of `now`. A regression in any of these would survive the
     * shape-only htu test that's already on file.
     */
    @Test
    fun proof_carriesCorrectHtmHtuLowercase_andRecentIat() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = DPoPInterceptor(store, domain)
            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            val before = System.currentTimeMillis() / 1000
            // Mixed-case scheme/host on input — OkHttp normalises both
            // segments to lowercase on parse, so the proof must carry the
            // canonical form regardless of how the caller spelled it.
            val request =
                Request
                    .Builder()
                    .url("https://API.EXAMPLE.COM/v1/me")
                    .method("PATCH", "{}".toRequestBody("application/json".toMediaType()))
                    .build()
            interceptor.intercept(request, send).close()
            val after = System.currentTimeMillis() / 1000

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            // htm mirrors the request method verbatim.
            assertTrue("htm must echo the request method; was: $payload", "\"htm\":\"PATCH\"" in payload)
            // htu is lowercased scheme/host (OkHttp normalisation).
            assertTrue(
                "htu must use lowercase scheme/host; was: $payload",
                "\"htu\":\"https://api.example.com/v1/me\"" in payload,
            )
            // iat is within a small window of `now` (allow +/- 1s for
            // the integer-second crossing between `before` and `after`).
            val iat =
                Regex("\"iat\":(\\d+)")
                    .find(payload)
                    ?.groupValues
                    ?.get(1)
                    ?.toLong()
            assertNotNull("iat claim must be present; was: $payload", iat)
            assertTrue(
                "iat must be within [before-1, after+1]; iat=$iat, before=$before, after=$after",
                iat!! in (before - 1)..(after + 1),
            )
        }
}
