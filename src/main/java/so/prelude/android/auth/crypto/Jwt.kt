package so.prelude.android.auth.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.PreludeJSONValue
import so.prelude.android.auth.PreludeProfile
import java.util.Base64

private val claimsJson = Json { ignoreUnknownKeys = true }

/**
 * A decoded JSON Web Token. The SDK never verifies tokens locally —
 * the backend is the source of truth — this decoder just unpacks
 * claims so the client can render a profile while a refresh runs.
 *
 * @property claims standard-claim view (typed fields).
 * @property payload raw decoded payload as a JSON object, for
 *   extracting application-specific claims via [PreludeProfile.extras].
 * @property encoded base64url segments, kept verbatim so callers can
 *   re-send the original token without re-serialising.
 */
internal data class Jwt(
    val claims: JwtClaims,
    val payload: JsonObject,
    val encoded: EncodedJwt,
) {
    internal data class EncodedJwt(
        val header: String,
        val payload: String,
        val signature: String,
    )
}

/**
 * Standard-claim view. Fields are nullable because token shapes vary
 * (challenge vs. access vs. refresh); missing or mistyped claims
 * decode as `null`.
 */
internal data class JwtClaims(
    val iss: String? = null,
    val sub: String? = null,
    val exp: Long? = null,
    val nbf: Long? = null,
    val iat: Long? = null,
    val jti: String? = null,
    val sid: String? = null,
)

internal object JwtDecoder {
    /**
     * Decode a compact-serialised JWT. Strict on structure (`header.
     * payload.signature`, all non-empty), lenient on claim types
     * (anything that doesn't fit the typed shape silently becomes
     * `null` instead of raising).
     */
    fun decode(token: String): Jwt {
        val parts = token.split('.')
        if (parts.size != 3) {
            throw PreludeAuthError.InvalidChallengeToken("JWT must have three parts")
        }
        val (headerPart, payloadPart, signaturePart) = parts
        if (headerPart.isEmpty() || payloadPart.isEmpty() || signaturePart.isEmpty()) {
            throw PreludeAuthError.InvalidChallengeToken("JWT has empty parts")
        }

        val payloadBytes =
            try {
                Base64.getUrlDecoder().decode(payloadPart)
            } catch (e: IllegalArgumentException) {
                throw PreludeAuthError.InvalidChallengeToken(
                    "JWT payload is not valid Base64URL: ${e.message ?: "decode failed"}",
                )
            }

        val payloadObject =
            try {
                claimsJson.parseToJsonElement(String(payloadBytes, Charsets.UTF_8)) as? JsonObject
                    ?: throw PreludeAuthError.InvalidChallengeToken(
                        "JWT payload is not a JSON object",
                    )
            } catch (e: PreludeAuthError) {
                throw e
            } catch (e: Exception) {
                throw PreludeAuthError.InvalidChallengeToken(
                    "JWT payload is not valid JSON: ${e.message ?: "parse failed"}",
                )
            }

        return Jwt(
            claims =
                JwtClaims(
                    iss = payloadObject.stringClaim("iss"),
                    sub = payloadObject.stringClaim("sub"),
                    exp = payloadObject.longClaim("exp"),
                    nbf = payloadObject.longClaim("nbf"),
                    iat = payloadObject.longClaim("iat"),
                    jti = payloadObject.stringClaim("jti"),
                    sid = payloadObject.stringClaim("sid"),
                ),
            payload = payloadObject,
            encoded = Jwt.EncodedJwt(headerPart, payloadPart, signaturePart),
        )
    }
}

private fun JsonObject.stringClaim(name: String): String? = (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

private fun JsonObject.longClaim(name: String): Long? = (get(name) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull

/**
 * Build a [PreludeProfile] from a decoded JWT. The JWT `sub` and `sid`
 * claims become the typed [PreludeProfile.userId] and
 * [PreludeProfile.sessionId] fields; every other top-level claim lands
 * in [PreludeProfile.extras] with its JSON shape preserved.
 */
internal fun PreludeProfile.Companion.fromJwt(jwt: Jwt): PreludeProfile {
    val extras =
        jwt.payload
            .filterKeys { it != "sub" && it != "sid" }
            .mapValues { (_, v) -> v.toPreludeJSONValue() }
    return PreludeProfile(
        userId = jwt.claims.sub,
        sessionId = jwt.claims.sid,
        extras = extras,
    )
}

/**
 * Recursive `JsonElement` → [PreludeJSONValue] mapping. Bools precede
 * integers so `true` / `false` aren't coerced to `1` / `0`; integers
 * precede doubles so 64-bit ids keep their precision.
 */
private fun JsonElement.toPreludeJSONValue(): PreludeJSONValue =
    when (this) {
        is JsonNull -> {
            PreludeJSONValue.Null
        }

        is JsonObject -> {
            PreludeJSONValue.Object(mapValues { (_, v) -> v.toPreludeJSONValue() })
        }

        is JsonArray -> {
            PreludeJSONValue.Array(map { it.toPreludeJSONValue() })
        }

        is JsonPrimitive -> {
            when {
                isString -> {
                    PreludeJSONValue.Str(content)
                }

                // Bools precede integers so `true` / `false` aren't coerced to `1` / `0`.
                // Integers precede doubles so 64-bit ids (above Double's safe-int
                // threshold of 2^53) keep their precision instead of being silently
                // rounded.
                else -> {
                    booleanOrNull?.let { PreludeJSONValue.Bool(it) }
                        ?: longOrNull?.let { PreludeJSONValue.Int(it) }
                        ?: doubleOrNull?.let { PreludeJSONValue.Double(it) }
                        // Fallback for unparseable primitives — kotlinx.serialization
                        // parses unquoted literals as `JsonPrimitive(isString=false)`,
                        // so a hostile/malformed token surfaces as a string instead of
                        // throwing mid-iteration.
                        ?: PreludeJSONValue.Str(content)
                }
            }
        }
    }
