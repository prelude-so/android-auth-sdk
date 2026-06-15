package so.prelude.android.auth.social

import so.prelude.android.auth.PreludeAuthError
import java.net.URI
import java.net.URLDecoder

/**
 * Decoded query parameters of the post-login redirect.
 */
internal sealed interface OAuthRedirect {
    data class Challenge(
        val token: String,
    ) : OAuthRedirect

    data class Failure(
        val code: String,
        val message: String,
    ) : OAuthRedirect

    /** Typed error for a [Failure], or `null` for a [Challenge]. */
    val error: PreludeAuthError?
        get() =
            when (this) {
                is Challenge -> {
                    null
                }

                is Failure -> {
                    when (code) {
                        "missing_challenge_token" -> PreludeAuthError.MissingChallengeToken(message)
                        "email_already_in_use" -> PreludeAuthError.Conflict(message)
                        "server_error" -> PreludeAuthError.InternalServerError(message)
                        else -> PreludeAuthError.Unauthorized(message)
                    }
                }
            }

    companion object {
        /** Message surfaced when a callback carries no challenge token. */
        const val MISSING_TOKEN_MESSAGE = "Missing challenge token from login callback"

        /**
         * Parse the redirect delivered to the app's callback scheme.
         * Server-reported failures win over a missing token.
         */
        fun parse(url: String): OAuthRedirect {
            val params = parseQuery(runCatching { URI(url).rawQuery }.getOrNull())

            params["error"]?.takeIf { it.isNotEmpty() }?.let { code ->
                return Failure(
                    code = code,
                    message = params["error_description"] ?: "Authentication failed",
                )
            }

            val token = params["challenge_token"]
            return if (token.isNullOrEmpty()) {
                Failure(
                    code = "missing_challenge_token",
                    message = MISSING_TOKEN_MESSAGE,
                )
            } else {
                Challenge(token)
            }
        }

        /** First value wins on duplicate keys, matching the platform browser. */
        private fun parseQuery(rawQuery: String?): Map<String, String> {
            if (rawQuery.isNullOrEmpty()) return emptyMap()
            val out = LinkedHashMap<String, String>()
            for (pair in rawQuery.split("&")) {
                val eq = pair.indexOf('=')
                if (eq < 0) continue
                val name = URLDecoder.decode(pair.substring(0, eq), "UTF-8")
                val value = URLDecoder.decode(pair.substring(eq + 1), "UTF-8")
                out.putIfAbsent(name, value)
            }
            return out
        }
    }
}
