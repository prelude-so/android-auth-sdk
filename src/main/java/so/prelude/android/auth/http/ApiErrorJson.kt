package so.prelude.android.auth.http

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Response

/**
 * Backend error body. `message` is optional (the session service
 * omits it for some codes).
 */
@Serializable
internal data class ApiErrorJson(
    val code: String,
    val message: String? = null,
    val type: String? = null,
    @SerialName("request_id") val requestId: String? = null,
) {
    /** Displayable message; falls back to [code] when absent or empty. */
    val displayMessage: String
        get() = message?.takeUnless { it.isEmpty() } ?: code
}

// Caps the cost of a giant non-JSON error page.
private const val MAX_ERROR_PEEK_BYTES = 4L * 1024L
private val errorJson = Json { ignoreUnknownKeys = true }

/** Peek the body and return the JSON error code, or `null` on any decode failure. */
internal fun Response.apiErrorCode(): String? =
    try {
        errorJson.decodeFromString(ApiErrorJson.serializer(), peekBody(MAX_ERROR_PEEK_BYTES).string()).code
    } catch (_: Exception) {
        null
    }
