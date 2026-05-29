package so.prelude.android.auth.http

import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.dpop.FakeDPoPKey
import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import java.util.Base64

class ChallengeDPoPInterceptorTest {
    private val domain = "api.example.com"

    private fun mkRequest(): Request = Request.Builder().url("https://api.example.com/v1/step-up/finalize").build()

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

    /** Build a compact JWT containing only the given JTI. Header and
     *  signature are placeholders; `decodeJwtJti` doesn't verify. */
    private fun challengeToken(jti: String?): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("{\"alg\":\"none\"}".toByteArray())
        val payloadJson = if (jti == null) "{}" else """{"jti":"$jti"}"""
        val payload = enc.encodeToString(payloadJson.toByteArray())
        return "$header.$payload.placeholder"
    }

    private fun decodePayload(proof: String): String = String(Base64.getUrlDecoder().decode(proof.split('.')[1]))

    @Test
    fun noKeyForDomain_passesThroughUnchanged() =
        runTest {
            val store = FakeDPoPKeyStore()
            val interceptor = ChallengeDPoPInterceptor(store, domain, challengeToken("c-123"))

            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor.intercept(mkRequest(), send).close()
            // No DPoP header — challenge step-up only makes sense once a
            // session key already exists, and creating one here would change
            // the server-side binding.
            assertNull(seenRequest!!.header(HttpHeader.DPOP))
        }

    @Test
    fun missingJtiInToken_passesThroughUnchanged() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setKey(domain, FakeDPoPKey())
            val interceptor = ChallengeDPoPInterceptor(store, domain, challengeToken(jti = null))

            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor.intercept(mkRequest(), send).close()
            assertNull(seenRequest!!.header(HttpHeader.DPOP))
        }

    @Test
    fun keyAndJtiPresent_signsProofWithChallengeJti() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setKey(domain, FakeDPoPKey())
            val interceptor = ChallengeDPoPInterceptor(store, domain, challengeToken("challenge-jti"))

            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor.intercept(mkRequest(), send).close()

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            assertTrue(
                "challenge proof must pin its jti to the challenge token's jti; was: $payload",
                "\"jti\":\"challenge-jti\"" in payload,
            )
        }

    @Test
    fun proof_omitsNonce() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setKey(domain, FakeDPoPKey())
            // Pre-populate a nonce — the challenge interceptor must NOT pull it in.
            store.setNonce(domain, "should-not-appear")
            val interceptor = ChallengeDPoPInterceptor(store, domain, challengeToken("j"))

            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor.intercept(mkRequest(), send).close()

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            assertTrue("challenge proof must not include a nonce", "\"nonce\"" !in payload)
        }

    @Test
    fun nonceFromResponse_isNotHarvested() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setKey(domain, FakeDPoPKey())
            val interceptor = ChallengeDPoPInterceptor(store, domain, challengeToken("j"))
            val send: SendFunction = { req -> mkResponse(req, nonce = "do-not-cache") }

            interceptor.intercept(mkRequest(), send).close()

            // The challenge interceptor is one-shot ownership — it deliberately
            // doesn't update the nonce cache from response headers.
            assertEquals(null, store.getNonce(domain))
        }

    /**
     * Persisted clock skew on the keystore must flow through to
     * the challenge proof's `iat`. The challenge interceptor
     * reads the same field the regular DPoP retry path persisted
     * earlier.
     */
    @Test
    fun keyAndJtiPresent_appliesPersistedClockSkew() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setKey(domain, FakeDPoPKey())
            val skewMs = 45_000L
            store.setClockSkewMs(domain, skewMs)
            val interceptor = ChallengeDPoPInterceptor(store, domain, challengeToken("j"))

            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            interceptor.intercept(mkRequest(), send).close()

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            val iat = Regex("\"iat\":(\\d+)").find(payload)!!.groupValues[1].toLong()
            val expectedSec = (System.currentTimeMillis() + skewMs) / 1000
            assertTrue(
                "challenge proof iat $iat must carry the persisted skew (expected≈$expectedSec)",
                kotlin.math.abs(iat - expectedSec) <= 3,
            )
        }

    /**
     * Regression: same host:port override path that broke
     * [DPoPInterceptor]. The challenge interceptor uses the same
     * helper, so the fix is shared but worth pinning here too.
     */
    @Test
    fun hostOverride_withPort_doesNotThrow() =
        runTest {
            val store = FakeDPoPKeyStore()
            store.setKey(domain, FakeDPoPKey())
            val interceptor =
                ChallengeDPoPInterceptor(
                    keyStore = store,
                    domain = domain,
                    challengeToken = challengeToken("j"),
                    hostOverride = "sessdev.example.com:443",
                )
            var seenRequest: Request? = null
            val send: SendFunction = { req ->
                seenRequest = req
                mkResponse(req)
            }

            val request = Request.Builder().url("https://127.0.0.1:3000/v1/step-up").build()
            interceptor.intercept(request, send).close()

            val payload = decodePayload(seenRequest!!.header(HttpHeader.DPOP)!!)
            assertTrue(
                "htu should reflect host:port override, was: $payload",
                "\"htu\":\"https://sessdev.example.com:443/v1/step-up\"" in payload,
            )
        }
}
