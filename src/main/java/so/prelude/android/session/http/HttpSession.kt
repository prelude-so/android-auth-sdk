package so.prelude.android.session.http

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.session.PreludeSessionError
import java.io.IOException
import java.net.SocketTimeoutException
import kotlin.coroutines.resumeWithException

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
 * [SocketTimeoutException] is mapped to [PreludeSessionError.Timeout]; all
 * other [IOException]s are wrapped in [PreludeSessionError.Network].
 */
internal class OkHttpSession(
    // Default jar is required for the OTP flow: `/v1/session/otp` sets
    // a `verification` cookie that `/v1/session/otp/check` reads. The
    // bare `OkHttpClient()` default is `CookieJar.NO_COOKIES`, which
    // silently drops the cookie and turns the second hop into a 401.
    // Tests inject a stub session and skip OkHttp entirely.
    private val client: OkHttpClient = defaultClient(InMemoryCookieJar()),
) : HttpSession {
    internal companion object {
        /**
         * Default OkHttp client wired to share [cookieJar] so the SDK
         * can wipe per-domain cookies on logout / revoke.
         */
        internal fun defaultClient(cookieJar: InMemoryCookieJar): OkHttpClient =
            OkHttpClient.Builder()
                .cookieJar(cookieJar)
                .build()
    }

    override suspend fun perform(request: Request): Response =
        suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(
                object : Callback {
                    override fun onResponse(call: Call, response: Response) {
                        // If the coroutine has already been cancelled by the time
                        // the response arrives, close the body to release the
                        // connection back to OkHttp's pool.
                        continuation.resume(response) { _ -> response.close() }
                    }

                    override fun onFailure(call: Call, e: IOException) {
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
                                is SocketTimeoutException -> PreludeSessionError.Timeout()
                                else -> PreludeSessionError.Network(e)
                            },
                        )
                    }
                },
            )
        }
}
