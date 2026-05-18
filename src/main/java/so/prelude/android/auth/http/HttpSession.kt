package so.prelude.android.auth.http

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.auth.PreludeAuthError
import java.io.IOException
import java.net.SocketTimeoutException
import kotlin.coroutines.resumeWithException
import kotlin.time.Duration
import kotlin.time.toJavaDuration

/**
 * Underlying HTTP transport. Production uses [OkHttpSession]; tests
 * inject a stub. Named `perform` to avoid colliding with OkHttp's
 * `Call.execute()`.
 */
internal interface HttpSession {
    suspend fun perform(request: Request): Response
}

/**
 * [HttpSession] backed by an [OkHttpClient]. Bridges OkHttp's
 * callback-based `enqueue` API to a coroutine so cancellation of the
 * caller propagates down to the in-flight request via [Call.cancel].
 *
 * [SocketTimeoutException] is mapped to [PreludeAuthError.Timeout]; all
 * other [IOException]s are wrapped in [PreludeAuthError.Network].
 */
internal class OkHttpSession(
    private val client: OkHttpClient,
) : HttpSession {
    internal companion object {
        /**
         * Default OkHttp client wired to share [cookieJar] so the SDK
         * can wipe per-domain cookies on logout / revoke. [timeout]
         * caps each phase (connect / read / write) and the call as a
         * whole — a slow DNS hop and a slow read together can't
         * silently exceed the budget the caller asked for.
         */
        internal fun defaultClient(
            cookieJar: InMemoryCookieJar,
            timeout: Duration,
        ): OkHttpClient {
            val javaTimeout = timeout.toJavaDuration()
            return OkHttpClient
                .Builder()
                .cookieJar(cookieJar)
                .connectTimeout(javaTimeout)
                .readTimeout(javaTimeout)
                .writeTimeout(javaTimeout)
                .callTimeout(javaTimeout)
                .build()
        }
    }

    override suspend fun perform(request: Request): Response =
        suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(
                object : Callback {
                    override fun onResponse(
                        call: Call,
                        response: Response,
                    ) {
                        // If the coroutine has already been cancelled by the time
                        // the response arrives, close the body to release the
                        // connection back to OkHttp's pool.
                        continuation.resume(response) { _ -> response.close() }
                    }

                    override fun onFailure(
                        call: Call,
                        e: IOException,
                    ) {
                        // When the coroutine is cancelled, `invokeOnCancellation`
                        // fires `call.cancel()`, which OkHttp reports back through
                        // this callback with an `IOException("Canceled")` — on its
                        // own dispatcher thread, after the continuation is already
                        // dead. `resumeWithException` has no `onCancellation`
                        // overload (unlike `resume`), so resuming an inactive
                        // continuation would throw `IllegalStateException` on a
                        // thread with no handler and crash the process.
                        // See kotlinx.coroutines issues #712 and #830.
                        if (!continuation.isActive) return
                        continuation.resumeWithException(
                            when (e) {
                                is SocketTimeoutException -> PreludeAuthError.Timeout()
                                else -> PreludeAuthError.Network(e)
                            },
                        )
                    }
                },
            )
        }
}
