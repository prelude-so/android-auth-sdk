package so.prelude.android.auth.http

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import okhttp3.Headers
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.from
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.time.Duration

/**
 * Source of the current instant. Injected so tests can pin the clock
 * when exercising the `Date:` header / expiry math.
 */
internal typealias NowProvider = () -> Instant

/**
 * One round trip through the HTTP stack. The underlying OkHttp
 * [Response] is already drained and closed — callers read via [body],
 * inspect status via [statusCode], and headers via [headers].
 *
 * Deliberately not a `data class`: the auto-generated `equals` /
 * `hashCode` would compare [body] by reference (Kotlin's `ByteArray`
 * inherits JVM array identity), and this type is a transport DTO —
 * no caller destructures, copies, or keys maps on it.
 *
 * @property timeDiffSec Local clock minus server clock, in seconds,
 *   derived from the `Date:` response header. Zero when the header is
 *   missing or unparseable. Callers add this to server-provided
 *   timestamps so cache expiry compares against the local device clock.
 */
internal class HttpResponse(
    val statusCode: Int,
    val headers: Headers,
    val body: ByteArray,
    val timeDiffSec: Long,
)

/**
 * Thin wrapper over [HttpSession] with an interceptor chain. Three
 * entry points, low to high abstraction: [perform] (raw),
 * [sendExpectingNoBody] (status-code mapping), [sendJson] (+ body
 * decode).
 */
internal class HttpClient(
    private val session: HttpSession,
    private val clock: NowProvider = { Instant.now() },
    private val json: Json = defaultJson,
    /**
     * Optional handle on the cookie jar shared with [session] so
     * the SDK can wipe per-domain cookies in [clearAllStores].
     * `null` when a test injects its own [HttpSession] (no jar to
     * wipe).
     */
    val cookieJar: InMemoryCookieJar? = null,
    /**
     * Interceptors appended after the per-call ones so they end
     * up innermost in the chain — they add headers closest to the
     * wire. Wired by [so.prelude.android.auth.PreludeAuthClient]
     * so every session request carries `X-Device-Id`.
     */
    private val defaultInterceptors: List<PreludeInterceptor> = emptyList(),
) {
    /**
     * Raw response — does not map status codes. For interceptors that
     * need to branch on 4xx/5xx (e.g. DPoP nonce retry).
     */
    suspend fun perform(
        request: Request,
        interceptors: List<PreludeInterceptor> = emptyList(),
    ): HttpResponse {
        val send = composeInterceptors(interceptors + defaultInterceptors, session)
        return send(request).use { response ->
            val bytes = response.body?.bytes() ?: ByteArray(0)
            HttpResponse(
                statusCode = response.code,
                headers = response.headers,
                body = bytes,
                timeDiffSec = timeDiffSec(response),
            )
        }
    }

    /**
     * Send a request with no meaningful body. Maps non-2xx to
     * [PreludeAuthError]. Returns the client/server time difference.
     */
    suspend fun sendExpectingNoBody(
        request: Request,
        interceptors: List<PreludeInterceptor> = emptyList(),
    ): Long {
        val response = perform(request, interceptors)
        throwIfNonSuccess(response)
        return response.timeDiffSec
    }

    /**
     * Send a request and decode a JSON body on 2xx. Maps non-2xx to
     * [PreludeAuthError]; includes a body snippet in decode failures
     * so shape drift is visible, not opaque.
     */
    suspend fun <T> sendJson(
        request: Request,
        deserializer: DeserializationStrategy<T>,
        interceptors: List<PreludeInterceptor> = emptyList(),
    ): Pair<T, HttpResponse> {
        val response = perform(request, interceptors)
        throwIfNonSuccess(response)
        val bodyText = response.body.toString(Charsets.UTF_8)
        val decoded =
            try {
                json.decodeFromString(deserializer, bodyText)
            } catch (e: Exception) {
                throw PreludeAuthError.Generic(
                    code = "decoding_failed",
                    displayMessage = "${e.message ?: "JSON decode failed"} — body: ${bodyText.take(512)}",
                )
            }
        return decoded to response
    }

    private fun timeDiffSec(response: Response): Long {
        val dateString = response.header(HttpHeader.DATE) ?: return 0
        return try {
            val serverInstant = Instant.from(httpDateFormatter.parse(dateString))
            clock().epochSecond - serverInstant.epochSecond
        } catch (_: Exception) {
            0
        }
    }

    /** Visible for re-use by consumers that already hold an [HttpResponse]. */
    internal fun throwIfNonSuccess(response: HttpResponse) {
        if (response.statusCode in 200..299) return

        val bodyText = response.body.toString(Charsets.UTF_8)
        val apiError: ApiErrorJson? =
            try {
                json.decodeFromString(ApiErrorJson.serializer(), bodyText)
            } catch (_: Exception) {
                null
            }

        if (apiError != null) {
            throw PreludeAuthError.from(apiError)
        }

        throw PreludeAuthError.Generic(
            code = "http_${response.statusCode}",
            displayMessage = "HTTP ${response.statusCode} — body: ${bodyText.take(512)}",
        )
    }

    companion object {
        /** RFC 7231 `IMF-fixdate` parser. Prelude always emits this form. */
        private val httpDateFormatter: DateTimeFormatter =
            DateTimeFormatter
                .ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)
                .withZone(ZoneOffset.UTC)

        internal val defaultJson: Json = Json { ignoreUnknownKeys = true }

        /**
         * Build an [HttpClient] whose [OkHttpSession] shares
         * [cookieJar] and applies [timeout] to every phase of the
         * call. The same jar is exposed on the returned client so
         * the SDK can wipe its per-domain cookies on logout / revoke.
         */
        internal fun withCookieJar(
            timeout: Duration,
            cookieJar: InMemoryCookieJar = InMemoryCookieJar(),
            defaultInterceptors: List<PreludeInterceptor> = emptyList(),
        ): HttpClient =
            HttpClient(
                session = OkHttpSession(OkHttpSession.defaultClient(cookieJar, timeout)),
                cookieJar = cookieJar,
                defaultInterceptors = defaultInterceptors,
            )
    }
}
