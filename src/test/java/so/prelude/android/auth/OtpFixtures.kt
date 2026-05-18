package so.prelude.android.auth

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.Request
import okio.Buffer
import so.prelude.android.auth.http.HttpHeader

/**
 * Shared test data + canned response builders for the OTP-login
 * test suite ([OtpClientStartTest], [OtpClientCheckTest],
 * [OtpClientFinalizeTest], [OtpClientAuthHeadersTest]).
 */
internal object OtpFixtures {
    // Well-formed unsigned JWT: payload `{"sub":"user-1"}`.
    const val JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    val emailIdentifier =
        PreludeIdentifier(
            type = PreludeIdentifierType.EMAIL_ADDRESS,
            value = "alice@example.com",
        )

    fun checkOkResponse(challenge: String = "challenge-abc") = StubHttpSession.Canned.json("""{"challenge_token":"$challenge"}""")

    fun finalizeOkResponse(
        accessToken: String = JWT,
        expiresInSec: Long = 3600,
        refreshToken: String? = "refresh-v1",
        refreshExpiresAt: String? = null,
    ): StubHttpSession.Canned {
        val expiresAt = 1_700_000_000L + expiresInSec
        val headers = mutableMapOf<String, String>()
        if (refreshToken != null) headers[HttpHeader.REFRESH_TOKEN] = refreshToken
        if (refreshExpiresAt != null) {
            headers[HttpHeader.REFRESH_TOKEN_EXPIRES_AT] = refreshExpiresAt
        }
        return StubHttpSession.Canned.json(
            """{"access_token":"$accessToken","expires_at":$expiresAt}""",
            headers = headers,
        )
    }

    fun apiError(
        code: String,
        message: String = "",
        status: Int = 400,
    ) = StubHttpSession.Canned.json(
        """{"code":"$code","message":"$message"}""",
        statusCode = status,
    )
}

internal fun Request.bodyAsString(): String {
    val buffer = Buffer()
    body?.writeTo(buffer)
    return buffer.readUtf8()
}

internal fun Request.bodyAsJson(): JsonObject = Json.parseToJsonElement(bodyAsString()).jsonObject
