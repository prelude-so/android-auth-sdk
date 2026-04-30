package so.prelude.android.session.http

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Unit tests for [AutoRefreshInterceptor].
 *
 * Coverage: happy path, 401 → refresh → retry, refresh failure
 * returning the original 401, retry failure propagating, and
 * cancellation. Owner-side dedup of concurrent refreshes lives on the
 * client and is covered by [PreludeSessionClient]'s own suite (this
 * interceptor takes the closures as opaque suspend lambdas).
 */
class AutoRefreshInterceptorTest {

    private fun mkRequest(url: String = "https://api.example.com/v1/me"): Request =
        Request.Builder().url(url).build()

    private fun mkResponse(
        request: Request,
        code: Int,
        body: String = "{}",
    ): Response = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message(if (code in 200..299) "OK" else "Error")
        .body(body.toResponseBody("application/json".toMediaType()))
        .build()

    /**
     * A [ResponseBody] whose underlying source increments [counter]
     * when closed. We tap the source — not the body — because
     * `ResponseBody.close()` is `final` in OkHttp; it routes to
     * `source().closeQuietly()`, which is exactly what we observe
     * here. Used to verify the interceptor releases the underlying
     * connection back to OkHttp's pool rather than waiting for the
     * body's finalizer.
     */
    private class CloseCountingBody(
        private val counter: AtomicInteger,
        payload: String = "{}",
    ) : ResponseBody() {
        private val backing: Buffer = Buffer().writeUtf8(payload)
        // BufferedSource is a sealed interface in modern okio so we
        // forward at the (non-sealed) Source level and buffer it back.
        // `super.close()` routes through ForwardingSource to backing.
        private val countingSource: BufferedSource =
            object : ForwardingSource(backing) {
                override fun close() {
                    counter.incrementAndGet()
                    super.close()
                }
            }.buffer()
        override fun contentType() = "application/json".toMediaType()
        override fun contentLength(): Long = backing.size
        override fun source(): BufferedSource = countingSource
    }

    private fun mkCloseCountingResponse(
        request: Request,
        code: Int,
        counter: AtomicInteger,
        body: String = "{}",
    ): Response = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message(if (code in 200..299) "OK" else "Error")
        .body(CloseCountingBody(counter, body))
        .build()

    @Test
    fun happyPath_attachesBearer_andReturnsResponseUntouched() = runTest {
        var observed: String? = null
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "token-1" },
            invalidateCache = { fail("invalidate must not run on 2xx") },
            refreshSession = { fail("refresh must not run on 2xx") },
        )

        val response = interceptor.intercept(mkRequest()) { req ->
            observed = req.header(HttpHeader.AUTHORIZATION)
            mkResponse(req, 200)
        }

        assertEquals("Bearer token-1", observed)
        assertEquals(200, response.code)
        response.close()
    }

    @Test
    fun emptyToken_stillSendsRequest_withBearerHeader() = runTest {
        // Documents the contract: an empty token is fine; the server's
        // 401 will trigger the refresh path.
        //
        // We assert that an Authorization header is present and starts
        // with `Bearer` rather than pinning the exact literal: OkHttp's
        // header storage trims trailing whitespace, so `Bearer ` and
        // `Bearer` are indistinguishable on the wire — and the wire
        // behaviour is what the server actually sees.
        var observed: String? = null
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "" },
            invalidateCache = { fail("invalidate must not run on 2xx") },
            refreshSession = { fail("refresh must not run on 2xx") },
        )

        val response = interceptor.intercept(mkRequest()) { req ->
            observed = req.header(HttpHeader.AUTHORIZATION)
            mkResponse(req, 200)
        }

        assertEquals(
            "header is present and carries no token after the scheme",
            "Bearer",
            observed?.trim(),
        )
        response.close()
    }

    @Test
    fun on401_invalidatesCache_refreshes_retriesWithNewToken() = runTest {
        val invalidateCalls = AtomicInteger()
        val refreshCalls = AtomicInteger()
        val seenAuth = mutableListOf<String?>()
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "stale" },
            invalidateCache = { invalidateCalls.incrementAndGet() },
            refreshSession = {
                refreshCalls.incrementAndGet()
                "fresh"
            },
        )

        var calls = 0
        val response = interceptor.intercept(mkRequest()) { req ->
            seenAuth += req.header(HttpHeader.AUTHORIZATION)
            calls += 1
            mkResponse(req, if (calls == 1) 401 else 200)
        }

        assertEquals(2, calls)
        assertEquals(1, invalidateCalls.get())
        assertEquals(1, refreshCalls.get())
        assertEquals(listOf("Bearer stale", "Bearer fresh"), seenAuth)
        assertEquals(200, response.code)
        response.close()
    }

    @Test
    fun on401_refreshFails_returnsOriginal401_withoutThrowing() = runTest {
        // The whole point of the interceptor's catch: an auth failure
        // is non-transient. Throwing here would cause an upstream
        // retry loop (e.g. an exponential backoff) to spin forever.
        val invalidateCalls = AtomicInteger()
        var sendCalls = 0
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "stale" },
            invalidateCache = { invalidateCalls.incrementAndGet() },
            refreshSession = { throw IOException("boom") },
        )

        val response = interceptor.intercept(mkRequest()) { req ->
            sendCalls += 1
            mkResponse(req, 401, body = """{"code":"unauthorized"}""")
        }

        assertEquals(1, invalidateCalls.get())
        // Only the original send happens — no retry was attempted.
        assertEquals(1, sendCalls)
        assertEquals(401, response.code)
        // Body is intact (not consumed) so callers can still decode
        // the original error payload.
        assertEquals("""{"code":"unauthorized"}""", response.body?.string())
        response.close()
    }

    @Test
    fun on401_retrySend_throws_propagates() = runTest {
        // After a successful refresh, a transport error on the retry
        // is NOT auth-related. It must propagate so the caller can
        // distinguish "auth was the problem" from "the network
        // dropped".
        var calls = 0
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "stale" },
            invalidateCache = {},
            refreshSession = { "fresh" },
        )

        assertThrows(IOException::class.java) {
            kotlinx.coroutines.runBlocking {
                interceptor.intercept(mkRequest()) { req ->
                    calls += 1
                    if (calls == 1) {
                        mkResponse(req, 401)
                    } else {
                        throw IOException("retry kaput")
                    }
                }
            }
        }
        assertEquals(2, calls)
    }

    @Test
    fun on401_invalidateThrows_propagates_andClosesResponse() = runTest {
        // A real storage failure during invalidate is surfaceable.
        // A naive catch here would mask a bad disk and make later
        // debugging impossible.
        //
        // Pin the resource-hygiene contract too: the 401 response
        // must be closed before the throw propagates, so its
        // connection slot returns to OkHttp's pool now rather than
        // waiting for the body's finalizer. Without an explicit
        // close on this path the connection would leak until GC.
        val closes = AtomicInteger()
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "stale" },
            invalidateCache = { throw IOException("storage gone") },
            refreshSession = { fail("refresh must not run when invalidate fails") },
        )

        assertThrows(IOException::class.java) {
            kotlinx.coroutines.runBlocking {
                interceptor.intercept(mkRequest()) { req ->
                    mkCloseCountingResponse(req, 401, closes)
                }
            }
        }
        assertEquals("401 response must be closed before throw propagates", 1, closes.get())
    }

    @Test
    fun on401_refreshCancelled_cancelsCaller() = runTest {
        // Cooperative cancellation must propagate so structured
        // concurrency stays intact. Swallowing CancellationException
        // would leave the parent waiting on a child that's already
        // gone — a classic deadlock shape.
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "stale" },
            invalidateCache = {},
            refreshSession = { throw CancellationException("caller bailed") },
        )

        try {
            coroutineScope {
                val job = async {
                    interceptor.intercept(mkRequest()) { req -> mkResponse(req, 401) }
                }
                job.await()
            }
            fail("expected CancellationException")
        } catch (_: CancellationException) {
            // expected
        }
    }

    @Test
    fun on401_overwritesPreExistingAuthorizationHeader() = runTest {
        // Defensive: a caller-supplied placeholder Authorization
        // header must be replaced, not stacked. OkHttp's
        // `addHeader()` would append; we use `header()` which
        // replaces — pin the contract here so a refactor doesn't
        // silently drift.
        var seenValues: List<String> = emptyList()
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "real-token" },
            invalidateCache = { fail("not on 2xx") },
            refreshSession = { fail("not on 2xx") },
        )

        val request = Request.Builder()
            .url("https://api.example.com/v1/me")
            .header(HttpHeader.AUTHORIZATION, "Bearer placeholder")
            .build()

        val response = interceptor.intercept(request) { req ->
            seenValues = req.headers.values(HttpHeader.AUTHORIZATION)
            mkResponse(req, 200)
        }

        // Exactly one Authorization header on the wire, holding the
        // real token — placeholder must be gone, not stacked beneath.
        assertEquals(listOf("Bearer real-token"), seenValues)
        assertEquals(200, response.code)
        response.close()
    }

    @Test
    fun nonAuthFailure_status_passesThrough() = runTest {
        // 4xx that isn't 401 (e.g. 403, 429) must NOT trigger the
        // refresh path. Refreshing a still-valid token on a
        // forbidden / rate-limited response would burn the
        // single-use refresh token to no benefit.
        var refreshes = 0
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "tok" },
            invalidateCache = { fail("not on non-401") },
            refreshSession = {
                refreshes += 1
                "x"
            },
        )

        val response = interceptor.intercept(mkRequest()) { req -> mkResponse(req, 403) }
        assertEquals(403, response.code)
        assertEquals(0, refreshes)
        response.close()
    }

    @Test
    fun successfulRefresh_returnsRetryResponse_notOriginal() = runTest {
        // Pin which response object reaches the caller — must be
        // the retry, not the closed 401. A regression here would
        // surface as a "401" from a request that actually succeeded.
        val first = AtomicInteger()
        val secondResponseRef = arrayOfNulls<Response>(1)
        val interceptor = AutoRefreshInterceptor(
            getAccessToken = { "stale" },
            invalidateCache = {},
            refreshSession = { "fresh" },
        )

        val received = interceptor.intercept(mkRequest()) { req ->
            first.incrementAndGet()
            if (first.get() == 1) {
                mkResponse(req, 401)
            } else {
                mkResponse(req, 200, body = """{"ok":true}""").also {
                    secondResponseRef[0] = it
                }
            }
        }

        assertSame(secondResponseRef[0], received)
        received.close()
    }

    private fun fail(message: String): Nothing = throw AssertionError(message)
}
