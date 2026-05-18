package so.prelude.android.auth

import kotlinx.coroutines.CompletableDeferred
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import so.prelude.android.auth.http.HttpSession
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Path-keyed [HttpSession] stub for client-level integration tests.
 *
 * Supports per-path *gates* — install a gate via [installGate] to make
 * `perform()` suspend on that path until [releaseGate] is called from
 * the test. Used by the logout / refresh-race suite to interleave
 * concurrent requests deterministically without sleeps.
 *
 * @see [install] to install a canned response per request path.
 * @see [recorded] to read back the requests issued by the client.
 * @see [installGate] to suspend a specific path until released.
 */
internal class StubHttpSession : HttpSession {
    /** A single canned response, returned verbatim from [perform]. */
    data class Canned(
        val statusCode: Int,
        val body: ByteArray = ByteArray(0),
        val headers: Map<String, String> = emptyMap(),
    ) {
        companion object {
            /** JSON body. The `Content-Type` header is set automatically. */
            fun json(
                body: String,
                statusCode: Int = 200,
                headers: Map<String, String> = emptyMap(),
            ): Canned =
                Canned(
                    statusCode = statusCode,
                    body = body.toByteArray(),
                    headers = headers + mapOf("Content-Type" to "application/json"),
                )
        }
    }

    private val lock = ReentrantLock()
    private val byPath = HashMap<String, Canned>()
    private val recorded = ArrayList<Request>()
    private val gates = HashMap<String, CompletableDeferred<Unit>>()

    /** Install a canned response for [path] (e.g. `/v1/session/otp`). */
    fun install(
        path: String,
        canned: Canned,
    ) = lock.withLock {
        byPath[path] = canned
    }

    /** Convenience: install the same response for several paths. */
    fun installAll(vararg pairs: Pair<String, Canned>) =
        lock.withLock {
            for ((path, canned) in pairs) byPath[path] = canned
        }

    /**
     * Install a gate on [path]. Subsequent [perform] calls for that
     * path record the request, then suspend until [releaseGate] is
     * called for the same path. The canned response is delivered after
     * release. Used to interleave concurrent requests deterministically.
     */
    fun installGate(path: String) =
        lock.withLock {
            gates[path] = CompletableDeferred()
        }

    /**
     * Release the gate on [path], unblocking any [perform] currently
     * suspended on it. No-op when no gate is installed for [path] —
     * tests can call this unconditionally on cleanup.
     */
    fun releaseGate(path: String) {
        val gate = lock.withLock { gates.remove(path) }
        gate?.complete(Unit)
    }

    /** Snapshot of all requests issued by the client, in order. */
    fun recorded(): List<Request> = lock.withLock { recorded.toList() }

    /** All recorded requests whose URL path matches [path]. */
    fun requestsFor(path: String): List<Request> =
        lock.withLock {
            recorded.filter { it.url.encodedPath == path }
        }

    /** Number of recorded requests whose URL path matches [path]. */
    fun requestCount(path: String): Int =
        lock.withLock {
            recorded.count { it.url.encodedPath == path }
        }

    override suspend fun perform(request: Request): Response {
        val path = request.url.encodedPath
        val (canned, gate) =
            lock.withLock {
                recorded += request
                val canned =
                    byPath[path]
                        ?: error("StubHttpSession: no canned response installed for path=$path")
                canned to gates[path]
            }

        // Suspend before delivering the response so a test that races
        // multiple in-flight requests can rendezvous on the recorded-
        // request count, then release in a controlled order. The gate
        // is read once at request-arrival time so a release/install
        // happening after this point doesn't affect this in-flight call.
        gate?.await()

        val builder =
            Response
                .Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(canned.statusCode)
                .message(if (canned.statusCode in 200..299) "OK" else "Error")
                .body(
                    String(canned.body)
                        .toResponseBody(
                            canned.headers["Content-Type"]?.toMediaType()
                                ?: "application/octet-stream".toMediaType(),
                        ),
                )
        canned.headers.forEach { (k, v) -> builder.header(k, v) }
        // Tests pin a clock; emit a `Date:` matching that clock so the
        // HttpClient's timeDiffSec stays at zero unless a test overrides
        // the header explicitly. Skipped when callers already set one.
        if (!canned.headers.keys.any { it.equals("Date", ignoreCase = true) }) {
            builder.header("Date", FIXED_DATE)
        }
        return builder.build()
    }

    companion object {
        /** RFC 7231 `Date:` header for the fixed test clock (epoch 1_700_000_000). */
        const val FIXED_DATE = "Tue, 14 Nov 2023 22:13:20 GMT"
    }
}
