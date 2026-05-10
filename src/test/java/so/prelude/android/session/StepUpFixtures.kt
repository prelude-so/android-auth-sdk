package so.prelude.android.session

import kotlinx.coroutines.delay
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.store.AccessTokenEntry
import so.prelude.android.session.store.RefreshTokenRecord
import java.util.Base64

/**
 * Shared test data + canned response builders for the step-up
 * test suite ([RequestStepUpTest], [RequestStepUpAuthTest],
 * [SubmitStepUpOTPTest], [SubmitStepUpOTPCompletionTest],
 * [StepUpConcurrencyTest], [StepUpEdgeCasesTest]).
 */
internal object StepUpFixtures {
    // Well-formed unsigned JWT carrying a scoped access token.
    // payload: {"sub":"user-1","sid":"sess-1"}
    const val SCOPED_ACCESS_TOKEN =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTEifQ.sig"

    /** Fixed clock baseline used across the suite. */
    const val BASE_EPOCH: Long = 1_700_000_000L

    val verifyEmailToken: String by lazy {
        makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_email",
                "jti" to "jti-otp",
                "exp" to BASE_EPOCH + 600,
            ),
        )
    }

    val verifySmsToken: String by lazy {
        makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "verify_sms",
                "jti" to "jti-sms",
                "exp" to BASE_EPOCH + 600,
            ),
        )
    }

    val completedToken: String by lazy {
        makeChallengeToken(
            mapOf(
                "challenge_id" to "chal-1",
                "current_step" to "completed",
                "jti" to "jti-completed",
                "exp" to BASE_EPOCH + 600,
            ),
        )
    }

    fun stepUpResponse(status: String, challengeToken: String? = null): StubHttpSession.Canned {
        // Build the JSON body explicitly rather than via TQS interpolation —
        // `"$x"""` lexes ambiguously around closing quotes.
        val tokenField = if (challengeToken != null) {
            ",\"challenge_token\":\"$challengeToken\""
        } else {
            ""
        }
        return StubHttpSession.Canned.json("""{"status":"$status"$tokenField}""")
    }

    fun apiError(code: String, message: String = "", status: Int = 400) =
        StubHttpSession.Canned.json(
            """{"code":"$code","message":"$message"}""",
            statusCode = status,
        )

    fun refreshOk(refreshToken: String = "refresh-v2", expiresInSec: Long = 3_600) =
        StubHttpSession.Canned.json(
            """{"access_token":"$SCOPED_ACCESS_TOKEN","expires_at":${BASE_EPOCH + expiresInSec}}""",
            headers = mapOf(
                HttpHeader.REFRESH_TOKEN to refreshToken,
                HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
            ),
        )

    /**
     * Build a well-formed but unsigned JWT — [JwtDecoder] reads only
     * the header + payload, so a placeholder signature suffices.
     * Hand-rolls the payload JSON in a deterministic order so golden
     * tokens stay stable across JVM versions.
     */
    fun makeChallengeToken(claims: Map<String, Any>): String {
        val header = base64Url("""{"alg":"HS256","typ":"JWT"}""".toByteArray())
        val payloadJson = buildString {
            append('{')
            claims.entries.forEachIndexed { i, (k, v) ->
                if (i > 0) append(',')
                append('"').append(k).append('"').append(':')
                when (v) {
                    is Number, is Boolean -> append(v.toString())
                    else -> append('"').append(v.toString().replace("\"", "\\\"")).append('"')
                }
            }
            append('}')
        }
        val payload = base64Url(payloadJson.toByteArray())
        return "$header.$payload.sig"
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** Mirrors the helper in `LogoutTests` / `RefreshClientTest`. */
    suspend fun waitUntil(timeoutMs: Long = 2_000, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            delay(5)
        }
        throw AssertionError("timed out waiting for condition (after ${timeoutMs}ms)")
    }
}

/**
 * Pre-populate a [Fixture] so the protected `/stepup/request` call
 * has a usable session. Access token kept unexpired so AutoRefresh
 * doesn't pre-empt — opt-in to the refresh path explicitly.
 */
internal fun Fixture.prePopulateStepUp(refreshToken: String = "refresh-v1") {
    keyStore.getOrCreate(domain)
    refreshTokenStore.set(
        domain = domain,
        record = RefreshTokenRecord(
            refreshToken = refreshToken,
            refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
        ),
    )
    accessTokenCache.set(
        domain = domain,
        entry = AccessTokenEntry(
            accessToken = StepUpFixtures.SCOPED_ACCESS_TOKEN,
            expiresAt = clock.epochSecond + 3_600,
        ),
    )
}
