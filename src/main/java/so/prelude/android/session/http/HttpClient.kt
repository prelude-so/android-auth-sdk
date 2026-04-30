package so.prelude.android.session.http

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import okhttp3.Headers
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.session.PreludeSessionError
import so.prelude.android.session.from
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

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
    private val session: HttpSession = OkHttpSession(),
    private val clock: NowProvider = { Instant.now() },
    private val json: Json = defaultJson,
) {
    /**
     * Raw response — does not map status codes. For interceptors that
     * need to branch on 4xx/5xx (e.g. DPoP nonce retry).
     */
    suspend fun perform(
        request: Request,
        interceptors: List<PreludeInterceptor> = emptyList(),
    ): HttpResponse {
        val send = composeInterceptors(interceptors, session)
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
     * [PreludeSessionError]. Returns the client/server time difference.
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
     * [PreludeSessionError]; includes a body snippet in decode failures
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
        val decoded = try {
            json.decodeFromString(deserializer, bodyText)
        } catch (e: Exception) {
            throw PreludeSessionError.Generic(
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
            throw PreludeSessionError.from(apiError)
        }

        throw PreludeSessionError.Generic(
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
    }
}
