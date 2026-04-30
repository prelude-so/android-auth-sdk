package so.prelude.android.session.http

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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
